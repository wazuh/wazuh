// SPDX-License-Identifier: AGPL-3.0-or-later
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <indexerConnector.hpp>
#include <json.hpp>

#include <base/logging.hpp>

#include <wiconnector/windexerconnector.hpp>

#include "indexerConnectorAsyncAdapter.hpp"

namespace wiconnector
{

namespace
{

constexpr std::size_t SINGLE_RESULT_SIZE {1};                     ///< Size for single result queries
constexpr std::string_view REMOTE_CONF_INDEX {".wazuh-settings"}; ///< remote conf index name

size_t getTotalHits(const nlohmann::json& hits)
{
    if (!hits.contains("total") || !hits["total"].is_object())
    {
        throw std::runtime_error("Hits object is invalid or does not contain total hits");
    }

    const auto& total = hits["total"];
    if (total.is_object() && total.contains("value"))
    {
        return total["value"].get<size_t>();
    }
    else if (total.is_number())
    {
        return total.get<size_t>();
    }
    else
    {
        throw std::runtime_error("Total hits format is unrecognized");
    }
}

/// How far past the page deadline the remote configuration call may last: the library lets an attempt with the whole
/// budget overrun the page by its 1 s grace before it reports the node, and the call must not cut that short.
constexpr std::chrono::milliseconds REMOTE_CONF_DEADLINE_MARGIN {5000};
/// While no node is usable yet (before the first probe round), the most a read waits for one, as the content adapter's
/// probeDeadline does (I158b): it must not hold a scheduler thread for a whole request timeout.
constexpr std::chrono::milliseconds REMOTE_CONF_NODE_WAIT {10000};

/// The remote configuration query, the same body the v1 connector sent.
nlohmann::json remoteConfigBody()
{
    nlohmann::json body;
    body["size"] = SINGLE_RESULT_SIZE;
    body["track_total_hits"] = true;
    body["stored_fields"] = nlohmann::json::array();
    body["query"] = {{"match_all", nlohmann::json::object()}};
    body["_source"] = {{"includes", {"engine"}}, {"excludes", nlohmann::json::array()}};
    return body;
}

/// The `engine` object of the one settings document in @p hits (the `hits` object of a search response).
json::Json engineConfigFromHits(const nlohmann::json& hits)
{
    size_t totalHits = getTotalHits(hits);

    if (totalHits == 0)
    {
        throw IndexerConnectorException("Remote settings document not found");
    }

    if (totalHits > 1)
    {
        throw IndexerConnectorException("Multiple remote settings documents found in index "
                                        + std::string(REMOTE_CONF_INDEX) + " (expected 1, got "
                                        + std::to_string(totalHits) + ")");
    }

    const auto& hitArray = hits["hits"];
    if (!hitArray.is_array() || hitArray.empty())
    {
        throw IndexerConnectorException("No hits returned for remote settings");
    }

    const auto& firstHit = hitArray[0];
    if (!firstHit.contains("_source"))
    {
        throw IndexerConnectorException("Remote settings hit does not contain _source");
    }

    const auto& sourceData = firstHit["_source"];
    if (!sourceData.contains("engine") || !sourceData["engine"].is_object())
    {
        throw IndexerConnectorException("Remote settings _source.engine missing or invalid");
    }

    return json::Json {sourceData["engine"].dump().c_str()};
}

/// Why no call should wait for a node: every node was probed (Down with a reason) and none is usable (I190b).
/// Nullopt while a usable node exists or before the first probe round (every node is born Down without a reason).
std::optional<std::string> noUsableNodeAfterProbes(const indexer_client::HealthView& health)
{
    if (health.nodes.empty() || health.anyUsable())
    {
        return std::nullopt;
    }
    std::string reasons;
    for (const auto& node : health.nodes)
    {
        if (node.reason.empty())
        {
            return std::nullopt;
        }
        reasons += (reasons.empty() ? "" : "; ") + node.url + ": " + node.reason;
    }
    return reasons;
}

/// The remote configuration through the engine's Client: one attempt, a page deadline of the request timeout and an
/// immediate failure once every node was probed and none is usable (I190, I190b). Every failure throws.
json::Json remoteConfigFromClient(indexer_client::IClient& reader, std::chrono::milliseconds requestTimeout)
{
    if (const auto why = noUsableNodeAfterProbes(reader.health()))
    {
        throw IndexerConnectorException(std::string {"Search request failed: no usable indexer node ("} + *why + ")");
    }

    const auto query = reader.query();
    if (!query)
    {
        throw IndexerConnectorException(std::string {"Search request failed: "}
                                        + indexer_client::toString(indexer_client::Cause::ClientClosed));
    }

    indexer_client::QueryOptions options;
    options.retry.maxAttempts = 1;
    options.pageDeadline = requestTimeout;
    const auto budget = reader.health().anyUsable()
                            ? requestTimeout + REMOTE_CONF_DEADLINE_MARGIN
                            : std::min(requestTimeout + REMOTE_CONF_DEADLINE_MARGIN, REMOTE_CONF_NODE_WAIT);
    const auto deadline = std::chrono::steady_clock::now() + budget;

    const auto outcome = query->search(REMOTE_CONF_INDEX, remoteConfigBody(), options, deadline);
    if (!outcome.ok())
    {
        throw IndexerConnectorException(std::string {"Search request failed: "}
                                            + indexer_client::toString(outcome.cause)
                                            + (outcome.reason.empty() ? "" : ": " + outcome.reason),
                                        IndexerConnectorException::Category::Other,
                                        outcome.httpStatus);
    }
    if (!outcome.value.is_object() || !outcome.value.contains("hits"))
    {
        throw IndexerConnectorException("Search response does not contain 'hits' field");
    }
    return engineConfigFromHits(outcome.value["hits"]);
}

} // namespace

/****************************************************************************************
 * Config class implementation
 ****************************************************************************************/

/*
 * Example:
 * {
 *   "hosts": [
 *     "http://10.2.20.2:9200",
 *     "https://10.2.20.42:9200"
 *   ],
 *   "ssl": {
 *     "certificate_authorities": [
 *       "/var/wazuh-manager/",
 *       "/var/wazuh-manager_cert/"
 *     ],
 *     "certificate": "cert",
 *     "key": "key_example"
 *   }
 * }
 */
std::string Config::toJson() const
{
    nlohmann::json config {};
    config["hosts"] = hosts;

    if (!ssl.cacert.empty() || !ssl.cert.empty() || !ssl.key.empty())
    {
        nlohmann::json sslJson {};
        if (!ssl.cacert.empty())
        {
            sslJson["certificate_authorities"] = ssl.cacert;
        }
        if (!ssl.cert.empty())
        {
            sslJson["certificate"] = ssl.cert;
        }
        if (!ssl.key.empty())
        {
            sslJson["key"] = ssl.key;
        }
        config["ssl"] = sslJson;
    }

    config["max_queue_bytes"] = maxQueueBytes;
    config["max_retry_delay_seconds"] = maxRetryDelaySeconds;

    return config.dump();
}

std::shared_ptr<IndexerConnectorAsync> makeIndexerConnectorAsync(std::string_view jsonOssecConfig)
{
    if (jsonOssecConfig.empty())
    {
        throw std::runtime_error("Empty JSON configuration for IndexerConnector");
    }

    const auto jsonParsed = nlohmann::json::parse(jsonOssecConfig, nullptr, false);
    if (jsonParsed.is_discarded())
    {
        throw std::runtime_error("Invalid JSON configuration for IndexerConnector");
    }

    const auto logFunction = logging::createStandaloneLogFunction();
    return std::make_shared<IndexerConnectorAsync>(jsonParsed, LoggingContext {logging::default_tag(), logFunction});
}

/****************************************************************************************
 * Wrapper of IndexerConnector class implementation
 ****************************************************************************************/
WIndexerConnector::WIndexerConnector(std::string_view jsonOssecConfig)
    : WIndexerConnector(makeIndexerConnectorAsync(jsonOssecConfig))
{
}

WIndexerConnector::WIndexerConnector(std::shared_ptr<IndexerConnectorAsync> connector)
{
    if (!connector)
    {
        throw std::runtime_error("IndexerConnectorAsync instance cannot be null");
    }
    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsyncAdapter>(std::move(connector));
}

WIndexerConnector::WIndexerConnector(const Config& config, const LogFunctionType& logFunction)
{
    nlohmann::json jsonConfig = nlohmann::json::parse(config.toJson(), nullptr, false);
    if (jsonConfig.is_discarded())
    {
        throw std::runtime_error("Invalid JSON configuration for IndexerConnector");
    }

    auto inner =
        std::make_unique<IndexerConnectorAsync>(jsonConfig, LoggingContext {logging::default_tag(), logFunction});
    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsyncAdapter>(std::move(inner));
}

WIndexerConnector::WIndexerConnector(std::shared_ptr<IndexerConnectorAsync> connector,
                                     std::shared_ptr<indexer_client::IClient> reader,
                                     std::chrono::milliseconds requestTimeout)
    : WIndexerConnector(std::move(connector))
{
    if (!reader)
    {
        throw std::runtime_error("The indexer client for the reads cannot be null");
    }
    m_reader = std::move(reader);
    m_requestTimeout = requestTimeout;
}

WIndexerConnector::WIndexerConnector(std::unique_ptr<IIndexerConnectorAsync> async,
                                     std::shared_ptr<indexer_client::IClient> reader,
                                     std::chrono::milliseconds requestTimeout)
    : WIndexerConnector(std::move(async))
{
    if (!reader)
    {
        throw std::runtime_error("The indexer client for the reads cannot be null");
    }
    m_reader = std::move(reader);
    m_requestTimeout = requestTimeout;
}

WIndexerConnector::WIndexerConnector(std::unique_ptr<IIndexerConnectorAsync> async)
{
    if (!async)
    {
        throw std::runtime_error("IndexerConnectorAsync instance cannot be null");
    }
    m_indexerConnectorAsync = std::move(async);
}

WIndexerConnector::~WIndexerConnector() = default;

void WIndexerConnector::shutdown()
{
    LOG_INFO("[indexer-connector] Shutdown initiated");
    // A remote configuration search in flight holds the shared lock; the Client's requestClose() (the engine's
    // EngineIndexerRuntime::beginStop(), before this call) makes it return ClientClosed, so this wait is short.
    std::unique_lock lock(m_mutex);
    m_indexerConnectorAsync.reset();
    m_reader.reset();
}

uint64_t WIndexerConnector::getQueueSize()
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        return 0;
    }
    return m_indexerConnectorAsync->getQueueSize();
}

uint64_t WIndexerConnector::getDroppedEvents()
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        return 0;
    }
    return m_indexerConnectorAsync->getDroppedEvents();
}

void WIndexerConnector::index(std::string_view index, std::string_view data)
{
    std::shared_lock lock(m_mutex);
    if (m_indexerConnectorAsync)
    {
        try
        {
            m_indexerConnectorAsync->indexDataStream(index, data);
        }
        catch (const IndexerConnectorException& e)
        {
            LOG_WARNING("[indexer-connector] Error indexing data: {}", e.what());
            return;
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[indexer-connector] Error indexing data: {}", e.what());
            return;
        }
    }
    else
    {
        LOG_DEBUG("[indexer-connector] IndexerConnectorAsync shutdown, cannot index data");
    }
}

json::Json WIndexerConnector::getEngineRemoteConfig()
{
    std::shared_lock lock(m_mutex);
    if (m_reader)
    {
        return remoteConfigFromClient(*m_reader, m_requestTimeout);
    }
    if (!m_indexerConnectorAsync)
    {
        throw std::runtime_error("IndexerConnectorAsync is not initialized");
    }

    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    nlohmann::json source = {{"includes", {"engine"}}, {"excludes", nlohmann::json::array()}};

    return engineConfigFromHits(m_indexerConnectorAsync->search(REMOTE_CONF_INDEX, SINGLE_RESULT_SIZE, query, source));
}

}; // namespace wiconnector
