// SPDX-License-Identifier: AGPL-3.0-or-later
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

nlohmann::json rulesetParameters(const nlohmann::json& connection,
                                 std::string_view space,
                                 const Options& options,
                                 const std::optional<std::string>& consumerId)
{
    auto parameters = baseParameters(connection, rulesetTopic(space), "Wazuh Engine CM Sync", options);

    auto& indexer = parameters["configData"]["indexer"];
    indexer["indices"] = POLICY_ALIASES;
    indexer["expandWildcards"] = true;
    if (consumerId.has_value() && !consumerId->empty())
    {
        indexer["consumerStatusId"] = *consumerId;
    }
    else
    {
        // No consumer writes this space, so there is nothing to wait for: an empty status index
        // disables both the pre-flight probe and the in-snapshot validation.
        indexer.erase("consumerStatusIndex");
    }
    indexer["hashIndex"] = std::string {POLICY_INDEX};

    // The probe must select the ONE policy document of this space, but it runs inside the PIT,
    // which spans every resource index. No document field singles the policy out: `enabled` is
    // required on decoders and filters too (wazuh-decoders.json, wazuh-filters.json), so a field
    // filter matches every one of them and the probe rejects the ambiguity on every cycle.
    //
    // `_index` does single it out, as long as it is not matched exactly: the configured names are
    // aliases and `_index` reports the concrete backing index, which carries a suffix. The wildcard
    // is the same "contains `policies`" rule the sink classifies hits by (kindFromIndexName), so the
    // probe and the sink agree on what the policy document is by construction.
    indexer["hashQuery"] = nlohmann::json {
        {"bool",
         {{"filter",
           nlohmann::json::array({nlohmann::json {{"term", {{"space.name", std::string {space}}}}},
                                  nlohmann::json {{"wildcard", {{"_index", {{"value", "*policies*"}}}}}}})}}}};
    indexer["hashPointers"] = nlohmann::json::array({"/space/hash/sha256"});
    indexer["metadataPointers"] =
        nlohmann::json {{"enabled", "/document/enabled"}, {"integrations", "/document/integrations"}};
    indexer["dataQuery"] = nlohmann::json {
        {"bool",
         {{"filter", nlohmann::json::array({nlohmann::json {{"term", {{"space.name", std::string {space}}}}}})}}}};

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
    indexer["sourceFilter"] = nlohmann::json {{"includes", IOC_SOURCE_INCLUDES}, {"excludes", nlohmann::json::array()}};

    return parameters;
}

} // namespace cmcontent
