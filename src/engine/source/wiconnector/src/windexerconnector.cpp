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

constexpr std::string_view POLICY_INDEX {"wazuh-threatintel-policies"}; ///< Policy index name
constexpr std::string_view IOC_INDEX {"wazuh-threatintel-enrichments"}; ///< IOC index name
constexpr std::size_t SINGLE_RESULT_SIZE {1};                           ///< Size for single result queries
constexpr std::string_view REMOTE_CONF_INDEX {".wazuh-settings"}; ///< remote conf index name
constexpr std::string_view CTI_CONSUMERS_INDEX {".wazuh-cti-consumers"}; ///< CTI consumers index name

// Helpers
nlohmann::json getQueryFilter(std::string_view space)
{
    if (space.empty())
    {
        throw std::runtime_error("Space name cannot be empty");
    }
    nlohmann::json query = R"({"bool": {"filter": [{ "term": { "space.name": "" }}]}})"_json;
    query["bool"]["filter"][0]["term"]["space.name"] = space;
    return query;
}

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
    if (!username.empty() && !password.empty())
    {
        config["username"] = username;
        config["password"] = password;
    }

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

/****************************************************************************************
 * Wrapper of IndexerConnector class implementation
 ****************************************************************************************/
WIndexerConnector::WIndexerConnector(std::string_view jsonOssecConfig, const std::size_t maxHitsPerRequest)
{
    if (maxHitsPerRequest == 0)
    {
        LOG_WARNING("[indexer-connector] maxHitsPerRequest must be greater than zero, default to 1");
        m_maxHitsPerRequest = 1;
    }
    else
    {
        m_maxHitsPerRequest = maxHitsPerRequest;
    }

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
    auto inner =
        std::make_unique<IndexerConnectorAsync>(jsonParsed, LoggingContext {logging::default_tag(), logFunction});
    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsyncAdapter>(std::move(inner));
}

WIndexerConnector::WIndexerConnector(const Config& config,
                                     const LogFunctionType& logFunction,
                                     const std::size_t maxHitsPerRequest)
{
    if (maxHitsPerRequest == 0)
    {
        LOG_WARNING("[indexer-connector] maxHitsPerRequest must be greater than zero, default to 1");
        m_maxHitsPerRequest = 1;
    }
    else
    {
        m_maxHitsPerRequest = maxHitsPerRequest;
    }

    nlohmann::json jsonConfig = nlohmann::json::parse(config.toJson(), nullptr, false);
    if (jsonConfig.is_discarded())
    {
        throw std::runtime_error("Invalid JSON configuration for IndexerConnector");
    }

    auto inner =
        std::make_unique<IndexerConnectorAsync>(jsonConfig, LoggingContext {logging::default_tag(), logFunction});
    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsyncAdapter>(std::move(inner));
}

WIndexerConnector::WIndexerConnector(std::unique_ptr<IIndexerConnectorAsync> async, const std::size_t maxHitsPerRequest)
{
    if (!async)
    {
        throw std::runtime_error("IndexerConnectorAsync instance cannot be null");
    }
    m_indexerConnectorAsync = std::move(async);

    if (maxHitsPerRequest == 0)
    {
        LOG_WARNING("[indexer-connector] maxHitsPerRequest must be greater than zero, default to 1");
        m_maxHitsPerRequest = 1;
    }
    else
    {
        m_maxHitsPerRequest = maxHitsPerRequest;
    }
}

WIndexerConnector::~WIndexerConnector() = default;

void WIndexerConnector::shutdown()
{
    LOG_INFO("[indexer-connector] Shutdown initiated");
    m_shutdownRequested.store(true, std::memory_order_relaxed);
    std::unique_lock lock(m_mutex); // Wait for any in-flight operations (syncs)
    m_indexerConnectorAsync.reset();
}

void WIndexerConnector::requestShutdown()
{
    m_shutdownRequested.store(true, std::memory_order_relaxed);
    LOG_INFO("[indexer-connector] Shutdown requested");
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
            LOG_WARNING("[indexer-connector] Error indexing data: %s", e.what());
            return;
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[indexer-connector] Error indexing data: %s", e.what());
            return;
        }
    }
    else
    {
        LOG_DEBUG("[indexer-connector] IndexerConnectorAsync shutdown, cannot index data");
    }
}

bool WIndexerConnector::existsPolicy(std::string_view space)
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        throw std::runtime_error("IndexerConnectorAsync is not initialized");
    }

    // Prepare query filter for the space
    nlohmann::json query = getQueryFilter(space);

    // Prepare source filter to only retrieve space.name field
    nlohmann::json source = {{"includes", {"space.name"}}, {"excludes", nlohmann::json::array()}};

    // Execute search query with size=1 (we only need to know if at least one exists)
    nlohmann::json hits = m_indexerConnectorAsync->search(POLICY_INDEX, SINGLE_RESULT_SIZE, query, source);

    // Check total hits
    size_t totalHits = getTotalHits(hits);

    return totalHits > 0;
}

bool WIndexerConnector::existsIndex(std::string_view indexName)
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        throw std::runtime_error("IndexerConnectorAsync is not initialized");
    }

    try
    {
        // Try a simple count query with size=0
        nlohmann::json query = R"({"match_all": {}})"_json;
        nlohmann::json source = {{"includes", nlohmann::json::array()}, {"excludes", nlohmann::json::array()}};

        // If the index doesn't exist, this will throw an exception
        m_indexerConnectorAsync->search(indexName, 0, query, source);
        return true;
    }
    catch (const IndexerConnectorException&)
    {
        return false;
    }
}

bool WIndexerConnector::existsIocDataIndex()
{
    return existsIndex(IOC_INDEX);
}

bool WIndexerConnector::isConsumerReadyForSync(std::string_view consumerId)
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        LOG_DEBUG("[indexer-connector] IndexerConnectorAsync not initialized, consumer '{}' not ready",
                  std::string(consumerId));
        return false;
    }

    try
    {
        nlohmann::json query = {{"ids", {{"values", {consumerId}}}}};
        nlohmann::json source = {{"includes", {"status", "local_offset"}}, {"excludes", nlohmann::json::array()}};

        nlohmann::json hits = m_indexerConnectorAsync->search(CTI_CONSUMERS_INDEX, SINGLE_RESULT_SIZE, query, source);

        size_t totalHits = getTotalHits(hits);
        if (totalHits == 0)
        {
            LOG_DEBUG("[indexer-connector] Consumer document '{}' not found", std::string(consumerId));
            return false;
        }

        const auto& hitArray = hits["hits"];
        if (!hitArray.is_array() || hitArray.empty() || !hitArray[0].contains("_source"))
        {
            LOG_DEBUG("[indexer-connector] Invalid consumer hit for '{}'", std::string(consumerId));
            return false;
        }

        const auto& src = hitArray[0]["_source"];

        // Check status == "ready"
        if (!src.contains("status") || !src["status"].is_string())
        {
            LOG_DEBUG("[indexer-connector] Consumer '{}' missing 'status' field", std::string(consumerId));
            return false;
        }

        const auto status = src["status"].get<std::string>();
        if (status != "ready")
        {
            LOG_DEBUG("[indexer-connector] Consumer '{}' is not ready (status: {})", std::string(consumerId), status);
            return false;
        }

        // Check local_offset != 0
        if (!src.contains("local_offset") || !src["local_offset"].is_number())
        {
            LOG_DEBUG("[indexer-connector] Consumer '{}' missing or non-numeric 'local_offset' field",
                      std::string(consumerId));
            return false;
        }

        const auto localOffset = src["local_offset"].get<int64_t>();
        if (localOffset == 0)
        {
            LOG_DEBUG("[indexer-connector] Consumer '{}' has local_offset=0, data not yet available",
                      std::string(consumerId));
            return false;
        }

        LOG_DEBUG("[indexer-connector] Consumer '{}' is ready for sync (ready, local_offset={})",
                  std::string(consumerId),
                  localOffset);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_DEBUG("[indexer-connector] Error checking consumer '{}' readiness: {}", std::string(consumerId), e.what());
        return false;
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
