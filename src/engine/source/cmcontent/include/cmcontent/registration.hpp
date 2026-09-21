#ifndef CMCONTENT_REGISTRATION_HPP
#define CMCONTENT_REGISTRATION_HPP

#include <cstddef>
#include <string>
#include <string_view>

#include <json.hpp>

/**
 * @brief Engine-side glue for the shared content manager.
 *
 * The Engine used to carry its own copy of the whole indexer-content pipeline in `wiconnector`:
 * PIT handling, `search_after` pagination, consumer validation, per-space and per-type hash
 * comparison. All of that is the same problem the Vulnerability Detection module solved separately
 * in `shared_modules/content_manager`, with different consistency guarantees and different bugs.
 * This namespace is what is left of the Engine's half: topic naming, the configuration that
 * describes each topic's query, and the sinks that decide what to do with the documents.
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

/// Index holding the per-space policy documents.
constexpr std::string_view POLICY_INDEX {"wazuh-threatintel-policies"};

/// Hard cap on the page size, whatever the configuration asks for.
constexpr std::size_t MAX_PAGE_SIZE {1000};

/// Tunables shared by every Engine registration.
struct Options
{
    std::size_t pageSize {100};                ///< Documents per request.
    std::string pitKeepAlive {"5m"};           ///< PIT lease duration.
    std::size_t consumerCacheSeconds {5};      ///< Pre-flight readiness cache lifetime.
    std::size_t consumerRetrySeconds {60};     ///< Backoff when the consumer is not ready.
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
 * @brief Registration parameters for one ruleset space.
 *
 * One topic per space rather than one for the whole ruleset: the hash, the promotion and the route
 * are all already per-space, so a single multi-space topic would have to invent a sub-stream
 * concept inside the generic contract for the benefit of exactly one consumer.
 *
 * @param connection Indexer connection settings (`hosts`, `ssl`, credentials).
 * @param space Origin space in the indexer.
 * @param options Tunables.
 * @return The parameters to hand to `ContentRegister`.
 */
nlohmann::json rulesetParameters(const nlohmann::json& connection, std::string_view space, const Options& options);

/**
 * @brief Registration parameters for one IOC type.
 *
 * @param connection Indexer connection settings (`hosts`, `ssl`, credentials).
 * @param iocType IOC type.
 * @param options Tunables.
 * @return The parameters to hand to `ContentRegister`.
 */
nlohmann::json iocParameters(const nlohmann::json& connection, std::string_view iocType, const Options& options);

} // namespace cmcontent

#endif // CMCONTENT_REGISTRATION_HPP
