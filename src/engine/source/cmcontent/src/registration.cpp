#include <algorithm>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <cmcontent/registration.hpp>

namespace cmcontent
{

namespace
{

/// The 12 IOC fields the enrichment pipeline actually reads. Anything else in the document is
/// bandwidth and parse time spent on data that is immediately discarded.
const std::vector<std::string> IOC_SOURCE_INCLUDES {"document.name",
                                                    "document.type",
                                                    "document.id",
                                                    "document.software.type",
                                                    "document.software.name",
                                                    "document.software.alias",
                                                    "document.confidence",
                                                    "document.first_seen",
                                                    "document.last_seen",
                                                    "document.feed.name",
                                                    "document.tags",
                                                    "document.provider"};

/// Every index a policy's resources can live in.
const std::vector<std::string> POLICY_ALIASES {"wazuh-threatintel-kvdbs",
                                               "wazuh-threatintel-decoders",
                                               "wazuh-threatintel-filters",
                                               "wazuh-threatintel-integrations",
                                               "wazuh-threatintel-policies"};

/// `_shard_doc` is synthesised by the PIT itself, so it is mapped in every index the PIT spans —
/// including the consumer status index, which is why no `unmapped_type` is needed here.
nlohmann::json sortKeys()
{
    return nlohmann::json::array({nlohmann::json {{"_shard_doc", "asc"}}, nlohmann::json {{"_id", "asc"}}});
}

std::size_t clampPageSize(std::size_t pageSize)
{
    return std::clamp<std::size_t>(pageSize, 1, MAX_PAGE_SIZE);
}

nlohmann::json baseParameters(const nlohmann::json& connection,
                              const std::string& topic,
                              std::string_view consumerName,
                              const Options& options)
{
    nlohmann::json parameters;
    parameters["topicName"] = topic;
    parameters["ondemand"] = true;
    // No "interval": the Engine owns a scheduler with CPU priorities and a startup ordering the
    // library cannot reproduce, so it drives runOnce from its own task instead of letting the
    // library spawn a thread per topic.

    auto& configData = parameters["configData"];
    configData["consumerName"] = std::string {consumerName};
    configData["changeDetection"] = "hash";
    configData["consumerRetryIntervalSeconds"] = options.consumerRetrySeconds;
    // No "databasePath": Engine state lives in store::IStore, and the token travels with it.

    configData["indexer"] = connection;
    auto& indexer = configData["indexer"];
    indexer["consumerStatusIndex"] = std::string {CTI_CONSUMERS_INDEX};
    indexer["keepAlive"] = options.pitKeepAlive;
    indexer["consumerStatusCacheSeconds"] = options.consumerCacheSeconds;
    indexer["pageSize"] = clampPageSize(options.pageSize);
    indexer["numSlices"] = 1;
    indexer["sortKeys"] = sortKeys();

    return parameters;
}

} // namespace

std::string rulesetTopic(std::string_view space)
{
    return fmt::format("content.ruleset.{}", space);
}

std::string iocTopic(std::string_view iocType)
{
    return fmt::format("content.ioc.{}", iocType);
}

nlohmann::json rulesetParameters(const nlohmann::json& connection, std::string_view space, const Options& options)
{
    auto parameters = baseParameters(connection, rulesetTopic(space), "Wazuh Engine CM Sync", options);

    auto& indexer = parameters["configData"]["indexer"];
    indexer["indices"] = POLICY_ALIASES;
    indexer["expandWildcards"] = true;
    indexer["consumerStatusId"] = std::string {RULESET_CONSUMER_ID};
    indexer["hashIndex"] = std::string {POLICY_INDEX};

    // The probe must select the ONE policy document of this space. It cannot do that by filtering
    // on `_index`: the configured names are aliases, and the `_index` metafield reports the
    // concrete backing index instead. `document.enabled` is a policy-only field — the policy
    // document is the only one required to carry it — so it is the discriminator, and the same
    // probe reads it as metadata.
    indexer["hashQuery"] = nlohmann::json {
        {"bool",
         {{"filter",
           nlohmann::json::array({nlohmann::json {{"term", {{"space.name", std::string {space}}}}},
                                  nlohmann::json {{"exists", {{"field", "document.enabled"}}}}})}}}};
    indexer["hashPointers"] = nlohmann::json::array({"/space/hash/sha256"});
    indexer["metadataPointers"] =
        nlohmann::json {{"enabled", "/document/enabled"}, {"integrations", "/document/integrations"}};
    indexer["dataQuery"] = nlohmann::json {
        {"bool", {{"filter", nlohmann::json::array({nlohmann::json {{"term", {{"space.name", std::string {space}}}}}})}}}};

    return parameters;
}

nlohmann::json iocParameters(const nlohmann::json& connection, std::string_view iocType, const Options& options)
{
    auto parameters = baseParameters(connection, iocTopic(iocType), "Wazuh Engine IOC Sync", options);

    auto& indexer = parameters["configData"]["indexer"];
    indexer["index"] = std::string {IOC_INDEX};
    indexer["consumerStatusId"] = std::string {IOC_CONSUMER_ID};
    indexer["hashDocId"] = std::string {IOC_HASHES_DOC_ID};

    // Two shapes are accepted for the manifest: the current one nests every type under
    // `type_hashes`, an older one puts them at the top level. First pointer that resolves wins, so
    // both keep working without a migration.
    indexer["hashPointers"] = nlohmann::json::array(
        {fmt::format("/type_hashes/{}/hash/sha256", iocType), fmt::format("/{}/hash/sha256", iocType)});

    indexer["dataQuery"] = nlohmann::json {{"term", {{"document.type", std::string {iocType}}}}};
    indexer["sourceFilter"] =
        nlohmann::json {{"includes", IOC_SOURCE_INCLUDES}, {"excludes", nlohmann::json::array()}};

    return parameters;
}

} // namespace cmcontent
