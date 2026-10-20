// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <contentTopicSpec.hpp>

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

std::size_t clampPageSize(std::size_t pageSize)
{
    return std::clamp<std::size_t>(pageSize, 1, MAX_PAGE_SIZE);
}

/// What every Engine topic shares. No interval: the Engine owns a scheduler with CPU priorities and a
/// startup ordering the library cannot reproduce, so it drives runOnce from its own task instead of
/// letting the library spawn a thread per topic. No database path: Engine state lives in
/// store::IStore, and the token travels with it. No connection: the Engine's own indexer is handed to
/// every registration (D1 of the content manager). The sort is implied by hash detection
/// (`_shard_doc`, `_id`), so it is not spelled out either (D2).
content_manager::TopicSpec baseSpec(const Options& options, const std::optional<std::string>& consumerId)
{
    content_manager::TopicSpec spec;
    spec.schedule.onDemand = true;
    spec.source.pitKeepAlive = options.pitKeepAlive;
    spec.source.pageSize = clampPageSize(options.pageSize);

    // No consumer writes a space like `custom`, so there is nothing to wait for: no readiness block,
    // no gate (D2).
    if (consumerId.has_value() && !consumerId->empty())
    {
        // At least one second, as the library used to enforce silently: the library now refuses a
        // zero retry, and `analysisd.content_consumer_retry_interval` may legitimately be set to 0.
        spec.readiness = content_manager::Readiness {std::string {CTI_CONSUMERS_INDEX},
                                                     *consumerId,
                                                     std::max<std::size_t>(1, options.consumerRetrySeconds),
                                                     options.consumerCacheSeconds};
    }
    return spec;
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

nlohmann::json
rulesetParameters(std::string_view space, const Options& options, const std::optional<std::string>& consumerId)
{
    auto spec = baseSpec(options, consumerId);
    spec.source.indices = POLICY_ALIASES;
    spec.source.expandWildcards = true;
    spec.source.query = nlohmann::json {
        {"bool",
         {{"filter", nlohmann::json::array({nlohmann::json {{"term", {{"space.name", std::string {space}}}}}})}}}};

    content_manager::HashDetection hash;
    // The probe must select the ONE policy document of this space, but it runs inside the PIT,
    // which spans every resource index. No document field singles the policy out: `enabled` is
    // required on decoders and filters too (wazuh-decoders.json, wazuh-filters.json), so a field
    // filter matches every one of them and the probe rejects the ambiguity on every cycle.
    //
    // `_index` does single it out, as long as it is not matched exactly: the configured names are
    // aliases and `_index` reports the concrete backing index, which carries a suffix. The wildcard
    // is the same "contains `policies`" rule the sink classifies hits by (kindFromIndexName), so the
    // probe and the sink agree on what the policy document is by construction.
    hash.probe = content_manager::QueryProbe {nlohmann::json {
        {"bool",
         {{"filter",
           nlohmann::json::array({nlohmann::json {{"term", {{"space.name", std::string {space}}}}},
                                  nlohmann::json {{"wildcard", {{"_index", {{"value", "*policies*"}}}}}}})}}}}};
    hash.tokenPointers = {"/space/hash/sha256"};
    hash.metadata = {{"enabled", "/document/enabled"}, {"integrations", "/document/integrations"}};
    spec.detection = std::move(hash);

    return content_manager::toParameters(spec);
}

nlohmann::json iocParameters(std::string_view iocType, const Options& options)
{
    auto spec = baseSpec(options, std::string {IOC_CONSUMER_ID});
    spec.source.indices = {std::string {IOC_INDEX}};
    spec.source.query = nlohmann::json {{"term", {{"document.type", std::string {iocType}}}}};
    spec.source.sourceFilter =
        nlohmann::json {{"includes", IOC_SOURCE_INCLUDES}, {"excludes", nlohmann::json::array()}};

    content_manager::HashDetection hash;
    hash.probe = content_manager::DocumentProbe {std::string {IOC_HASHES_DOC_ID}};
    // Two shapes are accepted for the manifest: the current one nests every type under
    // `type_hashes`, an older one puts them at the top level. First pointer that resolves wins, so
    // both keep working without a migration.
    hash.tokenPointers = {fmt::format("/type_hashes/{}/hash/sha256", iocType), fmt::format("/{}/hash/sha256", iocType)};
    spec.detection = std::move(hash);

    return content_manager::toParameters(spec);
}

} // namespace cmcontent
