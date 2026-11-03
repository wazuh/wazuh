// SPDX-License-Identifier: AGPL-3.0-or-later
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
    std::unique_lock lock(m_mutex); // Wait for in-flight operations
    m_indexerConnectorAsync.reset();
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
    if (!m_indexerConnectorAsync)
    {
        throw std::runtime_error("IndexerConnectorAsync is not initialized");
    }

    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    nlohmann::json source = {{"includes", {"engine"}}, {"excludes", nlohmann::json::array()}};

    nlohmann::json hits = m_indexerConnectorAsync->search(REMOTE_CONF_INDEX, SINGLE_RESULT_SIZE, query, source);
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

}; // namespace wiconnector
