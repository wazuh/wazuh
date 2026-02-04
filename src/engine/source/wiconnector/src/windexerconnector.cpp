#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <indexerConnector.hpp>
#include <json.hpp>

#include <base/logging.hpp>

#include <wiconnector/windexerconnector.hpp>

namespace wiconnector
{

namespace
{

/**
 * @brief List of policy resource aliases in the indexer
 */
const std::vector<std::string> POLICY_ALIASES = {".cti-kvdbs", ".cti-decoders", ".cti-integrations", ".cti-policies"};

constexpr std::string_view PIT_KEEP_ALIVE {"5m"};          ///< Keep alive duration for Point In Time
constexpr std::string_view POLICY_INDEX {".cti-policies"}; ///< Policy index name
constexpr std::size_t SINGLE_RESULT_SIZE {1};              ///< Size for single result queries
constexpr std::size_t HASH_QUERY_SIZE {1};                 ///< Size for hash query (expecting single result)

/// @brief Types of indexer resources
enum class IndexResourceType
{
    KVDB,
    DECODER,
    INTEGRATION_DECODER,
    POLICY
};

IndexResourceType fromIndexName(std::string_view indexName)
{
    // Static regex patterns compiled once
    static const std::array<std::pair<std::regex, IndexResourceType>, 4> patterns = {
        {{std::regex(R"(.*-kvdbs$)"), IndexResourceType::KVDB},
         {std::regex(R"(.*-decoders$)"), IndexResourceType::DECODER},
         {std::regex(R"(.*-integrations$)"), IndexResourceType::INTEGRATION_DECODER},
         {std::regex(R"(.*-policies$)"), IndexResourceType::POLICY}}};

    for (const auto& [pattern, resourceType] : patterns)
    {
        if (std::regex_match(indexName.begin(), indexName.end(), pattern))
        {
            return resourceType;
        }
    }

    throw IndexerConnectorException("Cannot determine resource type from index name: " + std::string(indexName));
}

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

nlohmann::json getSortCriteria()
{
    nlohmann::json sort = R"([{"_shard_doc": "asc"}, {"_id": "asc"}])"_json;
    return sort;
}

nlohmann::json getSearchAfter(const nlohmann::json& hits)
{
    if (!hits.contains("hits") || !hits["hits"].is_array() || hits["hits"].empty())
    {
        throw std::runtime_error("Hits object is invalid or empty");
    }

    return hits["hits"].back().at("sort");
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

json::Json extractDocumentFromHit(const nlohmann::json& hit)
{
    if (!hit.contains("_source") || !hit["_source"].is_object())
    {
        throw std::runtime_error("Hit does not contain _source field");
    }

    const auto& source = hit["_source"];
    if (!source.contains("document"))
    {
        throw std::runtime_error("Source does not contain document field");
    }

    try
    {
        return json::Json {source["document"].dump().c_str()};
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format(
            "Failed to parse document JSON: '{}'. Original error: {}", source["document"].dump(), e.what()));
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

    return config.dump();
}

/****************************************************************************************
 * Wrapper of IndexerConnector class implementation
 ****************************************************************************************/
WIndexerConnector::WIndexerConnector(std::string_view jsonOssecConfig)
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
    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsync>(jsonParsed, logFunction);
}

WIndexerConnector::WIndexerConnector(const Config& config, const LogFunctionType& logFunction)
{
    nlohmann::json jsonConfig = nlohmann::json::parse(config.toJson(), nullptr, false);
    if (jsonConfig.is_discarded())
    {
        throw std::runtime_error("Invalid JSON configuration for IndexerConnector");
    }

    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsync>(jsonConfig, logFunction);
}

WIndexerConnector::~WIndexerConnector() = default;

void WIndexerConnector::shutdown()
{
    std::unique_lock lock(m_mutex);
    m_indexerConnectorAsync.reset();
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

PolicyResources WIndexerConnector::getPolicy(std::string_view space)
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        throw std::runtime_error("IndexerConnectorAsync is not initialized");
    }

    std::vector<std::pair<IndexResourceType, json::Json>> resourceList;

    // Create Point In Time (PIT) - Can throw IndexerConnectorException
    auto pit = m_indexerConnectorAsync->createPointInTime(POLICY_ALIASES, PIT_KEEP_ALIVE, true);

    auto pitGuard = std::unique_ptr<decltype(pit), std::function<void(decltype(pit)*)>>(
        &pit,
        [this](auto* p)
        {
            try
            {
                m_indexerConnectorAsync->deletePointInTime(*p);
            }
            catch (const IndexerConnectorException& e)
            {
                LOG_WARNING_L("pitGuard", "[indexer-connector] Error deleting Point In Time (PIT): {}", e.what());
            }
        });

    // Prepare query and sort criteria
    nlohmann::json query = getQueryFilter(space);
    nlohmann::json sort = getSortCriteria();
    std::optional<nlohmann::json> searchAfter = std::nullopt;

    size_t total_hits = 0;
    size_t retrievedSoFar = 0;
    bool moreHits = true;

    do
    {
        nlohmann::json hits = m_indexerConnectorAsync->search(pit, m_maxHitsPerRequest, query, sort, searchAfter);

        if (!searchAfter.has_value())
        {
            total_hits = getTotalHits(hits);
            resourceList.reserve(total_hits);
            LOG_TRACE("[indexer-connector] Total hits to retrieve: {}", total_hits);
        }

        const auto& hitArray = hits["hits"];

        // Just in case total_hits was greater than zero but no hits were returned
        if (!hitArray.is_array() || hitArray.empty())
        {
            LOG_TRACE("[indexer-connector] No more hits retrieved, ending pagination");
            break;
        }

        retrievedSoFar += hitArray.size();
        for (const auto& hit : hitArray)
        {
            auto indexName = hit["_index"].get<std::string>();
            auto sourceData = extractDocumentFromHit(hit);
            IndexResourceType resourceType = fromIndexName(indexName);
            resourceList.emplace_back(resourceType, std::move(sourceData));
        }

        moreHits = retrievedSoFar < total_hits;
        searchAfter = getSearchAfter(hits);
        LOG_TRACE("[indexer-connector] Retrieved {} / {} hits so far", retrievedSoFar, total_hits);

    } while (moreHits);

    // Organize resources into PolicyResources structure
    PolicyResources policyMap {};

    // Avoid memory reallocations
    {
        std::size_t kvdbCount = 0;
        std::size_t decoderCount = 0;
        std::size_t integrationDecoderCount = 0;
        for (const auto& [type, _] : resourceList)
        {
            switch (type)
            {
                case IndexResourceType::KVDB: ++kvdbCount; break;
                case IndexResourceType::DECODER: ++decoderCount; break;
                case IndexResourceType::INTEGRATION_DECODER: ++integrationDecoderCount; break;
                case IndexResourceType::POLICY: break;
            }
        }
        policyMap.kvdbs.reserve(kvdbCount);
        policyMap.decoders.reserve(decoderCount);
        policyMap.integration.reserve(integrationDecoderCount);
    }

    // Move resources to appropriate vectors
    for (auto& [type, data] : resourceList)
    {
        switch (type)
        {
            case IndexResourceType::KVDB: policyMap.kvdbs.emplace_back(std::move(data)); break;
            case IndexResourceType::DECODER: policyMap.decoders.emplace_back(std::move(data)); break;
            case IndexResourceType::INTEGRATION_DECODER: policyMap.integration.emplace_back(std::move(data)); break;
            case IndexResourceType::POLICY: policyMap.policy = std::move(data); break;
        }
    }

    // Enrich policy with origin_space if not present
    if (policyMap.policy.isObject() && policyMap.policy.size() > 0)
    {
        policyMap.policy.setString(space, "/origin_space");
    }

    return policyMap;
}

std::string WIndexerConnector::getPolicyHash(std::string_view space)
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        throw std::runtime_error("IndexerConnectorAsync is not initialized");
    }

    // Prepare query filter for the space
    nlohmann::json query = getQueryFilter(space);

    // Prepare source filter to only retrieve space.hash.sha256
    nlohmann::json source = {{"includes", {"space.hash.sha256"}}, {"excludes", nlohmann::json::array()}};

    // Execute search query
    nlohmann::json hits = m_indexerConnectorAsync->search(POLICY_INDEX, HASH_QUERY_SIZE, query, source);

    // Check total hits
    size_t totalHits = getTotalHits(hits);

    if (totalHits == 0)
    {
        throw IndexerConnectorException("No policy found for space: " + std::string(space));
    }

    if (totalHits > 1)
    {
        throw IndexerConnectorException("Multiple policies found for space: " + std::string(space)
                                        + " (expected 1, got " + std::to_string(totalHits) + ")");
    }

    // Extract the hash from the first (and only) hit
    const auto& hitArray = hits["hits"];
    if (!hitArray.is_array() || hitArray.empty())
    {
        throw IndexerConnectorException("No hits returned despite total_hits > 0 for space: " + std::string(space));
    }

    const auto& firstHit = hitArray[0];
    if (!firstHit.contains("_source"))
    {
        throw IndexerConnectorException("Hit does not contain _source field for space: " + std::string(space));
    }

    const auto& source_data = firstHit["_source"];
    if (!source_data.contains("space") || !source_data["space"].contains("hash")
        || !source_data["space"]["hash"].contains("sha256"))
    {
        throw IndexerConnectorException("space.hash.sha256 field not found for space: " + std::string(space));
    }

    return source_data["space"]["hash"]["sha256"].get<std::string>();
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

}; // namespace wiconnector
