// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef CMCONTENT_REGISTRATION_HPP
#define CMCONTENT_REGISTRATION_HPP

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <contentTopicSpec.hpp>

/**
 * @brief How the Engine's content reaches it from the indexer, through the shared content manager.
 *
 * This namespace owns what is Engine-specific about the download: each topic's name and spec, and
 * the sinks that turn the documents into Engine state (ruleset namespaces and routes, IOC KVDBs).
 * The sync services decide when topics run and what their outcome means for the reported status.
 */
namespace cmcontent
{

/// Consumer document id for the standard ruleset in `.wazuh-cti-consumers`.
constexpr std::string_view RULESET_CONSUMER_ID {"cti:catalog:consumer:ruleset"};

/// Consumer document id for the IOC enrichment data in `.wazuh-cti-consumers`.
constexpr std::string_view IOC_CONSUMER_ID {"cti:catalog:consumer:iocs"};

/// Index holding the CTI consumer status documents.
constexpr std::string_view CTI_CONSUMERS_INDEX {".wazuh-cti-consumers"};

/// Index holding the IOC enrichment documents.
constexpr std::string_view IOC_INDEX {"wazuh-threatintel-enrichments"};

/// Manifest document carrying the per-type IOC hashes.
constexpr std::string_view IOC_HASHES_DOC_ID {"__ioc_type_hashes__"};

/// Hard cap on the page size, whatever the configuration asks for.
constexpr std::size_t MAX_PAGE_SIZE {1000};

/// Tunables shared by every Engine registration.
struct Options
{
    std::size_t pageSize {100};            ///< Documents per request.
    std::string pitKeepAlive {"5m"};       ///< PIT lease duration.
    std::size_t consumerCacheSeconds {5};  ///< Pre-flight readiness cache lifetime.
    std::size_t consumerRetrySeconds {60}; ///< Backoff when the consumer is not ready.
};

/**
 * @brief Topic name for one ruleset space.
 *
 * @param space Origin space in the indexer.
 * @return The topic name.
 */
std::string rulesetTopic(std::string_view space);

/**
 * @brief Topic name for one IOC type.
 *
 * @param iocType IOC type.
 * @return The topic name.
 */
std::string iocTopic(std::string_view iocType);

/**
 * @brief The registration for one ruleset space.
 *
 * One topic per space: the hash, the promotion and the route are all per space.
 *
 * @param space Origin space in the indexer.
 * @param options Tunables.
 * @param consumerId CTI consumer whose readiness gates the space, or nullopt for a space no consumer
 *                   writes (`custom`): such a space is never gated, since a CTI re-index of the
 *                   standard content says nothing about whether its own documents are complete.
 * @return The spec to hand to `ContentRegister`.
 */
content_manager::TopicSpec
rulesetSpec(std::string_view space, const Options& options, const std::optional<std::string>& consumerId);

/**
 * @brief The registration for one IOC type.
 *
 * @param iocType IOC type.
 * @param options Tunables.
 * @return The spec to hand to `ContentRegister`.
 */
content_manager::TopicSpec iocSpec(std::string_view iocType, const Options& options);

} // namespace cmcontent

#endif // CMCONTENT_REGISTRATION_HPP
