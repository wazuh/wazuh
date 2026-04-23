#ifndef ICMSTORE_DATA_POLICY
#define ICMSTORE_DATA_POLICY

#include <regex>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <base/json.hpp>

#include <cmstore/detail.hpp>

/**
 * @brief DataPolicy class to represent a content manager data policy. Its the definition of a policy.
 *
 * This class encapsulates the data and operations related to a content manager data policy,
 * including its integrations, default parent, root decoder, and optional hash.
 *
 * Expexted JSON format:
 * {
 *   "type": "policy",
 *   "metadata":
 *   {
 *     "title": "Development 0.0.1",
 *   },
 *   "enabled": true,
 *   "root_decoder": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
 *   "origin_space": "space1", -> optional, default value "UNDEFINED"
 *   "index_unclassified_events": true, -> optional, default value false
 *   "index_discarded_events": true, -> optional, default value false
 *   "cleanup_decoder_variables": true, -> optional, default value true
 *   "filters": [], -->> eash filter has a type [pre-filter|post-filter],
 *   "enrichments": ["file", "domain-name", "ip", "url", "geo"],
 *   "integrations":
 *   [
 *     "42e28392-4f5e-473d-89e8-c9030e6fedc2",
 *     "a7fe64a2-0a03-414f-8692-8441bdfe6f69",
 *     "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
 *     "f61133f5-90b9-49ed-b1d5-0b88cb04355e",
 *     "369c3128-9715-4a30-9ff9-22fcac87688b",
 *   ],
 *   "outputs": [], -> optional.
 *   "hash": "7ab287...5180", -> "optional hash value for integrity verification"
 *   "id": "eb5c2519-feff-4789-8542-9a0453cc8690" -> "uuid for the policy"
 * }
 *
 */

namespace cm::store::dataType
{

namespace jsonpolicy
{
constexpr std::string_view PATH_KEY_INTEGRATIONS = "/integrations";
constexpr std::string_view PATH_KEY_ROOT_PARENT = "/root_decoder";
constexpr std::string_view PATH_KEY_FILTERS = "/filters";
constexpr std::string_view PATH_KEY_ENRICHMENTS = "/enrichments";
constexpr std::string_view PATH_KEY_INDEX_UNCLASSIFIED_EVENTS = "/index_unclassified_events";
constexpr std::string_view PATH_KEY_OUTPUTS = "/outputs";
constexpr std::string_view PATH_KEY_TITLE = "/metadata/title";
constexpr std::string_view PATH_KEY_ENABLED = "/enabled";
constexpr std::string_view PATH_KEY_ORIGIN_SPACE = "/origin_space";
constexpr std::string_view PATH_KEY_HASH = "/hash";
constexpr std::string_view PATH_KEY_INDEX_DISCARDED_EVENTS = "/index_discarded_events";
constexpr std::string_view PATH_KEY_CLEANUP_DECODER_VARIABLES = "/cleanup_decoder_variables";

constexpr std::string_view DEFAULT_ORIGIN_SPACE = "UNDEFINED"; ///< Default origin space when not specified

} // namespace jsonpolicy

/**
 * @brief Policy class representing a policy in wazuh-engine
 *
 * This defines the pipeline of processing for events, including integrations,
 */
class Policy
{
private:
    std::string m_title;                     ///< Title of the policy
    bool m_enabled;                          ///< Flag indicating whether the policy is enabled
    std::string m_rootDecoder;               ///< Root decoder UUID
    std::string m_originSpace;               ///< Origin space name (Optional)
    std::vector<std::string> m_integrations; ///< Integrations UUIDs included in the policy
    std::vector<std::string> m_filters;      ///< Filters defined in the policy
    std::vector<std::string> m_enrichments;  ///< Enrichments plugins defined in the policy
    std::vector<std::string> m_outputs;      ///< Outputs defined in the policy (optional)

    std::string m_hash;             ///< Hash of the policy for integrity verification
    bool m_indexUnclassifiedEvents; ///< Flag indicating whether to index unclassified events
    bool m_indexDiscardedEvents;    ///< Flag to control discarded event indexing
    bool m_cleanupDecoderVariables; ///< Flag to control cleanup of temporary decoder variables

    void validateOriginSpace(std::string_view value) const
    {
        if (!std::regex_match(value.begin(), value.end(), std::regex("^[a-zA-Z0-9_]+$")))
        {
            throw std::runtime_error(fmt::format(
                "'origin_space' contains invalid characters: '{}'. Only alphanumeric and underscores are allowed.",
                value));
        }
    }

public:
    ~Policy() = default;
    Policy() = delete;

    Policy(std::string_view policyTitle,
           bool enabled,
           std::string_view rootDecoder,
           std::vector<std::string> integrationsUUIDs,
           std::vector<std::string> filters,
           std::vector<std::string> enrichments,
           std::vector<std::string> outputs,
           std::string_view originSpace,
           std::string_view hash,
           bool indexUnclassifiedEvents,
           bool indexDiscardedEvents,
           bool cleanupDecoderVariables)
        : m_title(policyTitle)
        , m_enabled(enabled)
        , m_rootDecoder(rootDecoder)
        , m_integrations(std::move(integrationsUUIDs))
        , m_filters(std::move(filters))
        , m_enrichments(std::move(enrichments))
        , m_outputs(std::move(outputs))
        , m_originSpace(originSpace)
        , m_hash(hash)
        , m_indexUnclassifiedEvents(indexUnclassifiedEvents)
        , m_indexDiscardedEvents(indexDiscardedEvents)
        , m_cleanupDecoderVariables(cleanupDecoderVariables)
    {
        cm::store::detail::findDuplicateOrInvalidUUID(m_integrations, "Integration");
        cm::store::detail::findDuplicateOrInvalidUUID(m_outputs, "Output");
        cm::store::detail::findDuplicateOrInvalidUUID(m_filters, "Filter");
        if (m_originSpace != jsonpolicy::DEFAULT_ORIGIN_SPACE)
        {
            validateOriginSpace(m_originSpace);
        }
    }

    // Dumper and loader
    static Policy fromJson(const json::Json& policyJson)
    {
        if (!policyJson.isObject())
        {
            throw std::runtime_error("Policy JSON must be an object");
        }

        // Get title
        std::string title = [&]() -> std::string
        {
            std::string title;
            if (policyJson.getString(title, jsonpolicy::PATH_KEY_TITLE) != json::RetGet::Success || title.empty())
            {
                return std::string {"Untitled Policy"};
            }
            return title;
        }();

        // Get enabled
        bool enabled = [&]() -> bool
        {
            auto enabledOpt = policyJson.getBool(jsonpolicy::PATH_KEY_ENABLED);
            if (!enabledOpt.has_value())
            {
                throw std::runtime_error("Policy JSON must have a boolean 'enabled' field");
            }
            return enabledOpt.value();
        }();

        // Get root decoder
        auto rootDecoder = [&]()
        {
            std::string rootDecoder;
            if (policyJson.getString(rootDecoder, jsonpolicy::PATH_KEY_ROOT_PARENT) != json::RetGet::Success)
            {
                throw std::runtime_error("Policy JSON must have a 'root_decoder' field");
            }
            return rootDecoder;
        }();

        // Get integrations
        std::vector<std::string> integrations = [&]() -> auto
        {
            std::vector<std::string> integrations;
            if (!policyJson.isArray(jsonpolicy::PATH_KEY_INTEGRATIONS))
            {
                throw std::runtime_error("Policy JSON must have an 'integrations' array");
            }

            std::size_t integrationCount = policyJson.size(jsonpolicy::PATH_KEY_INTEGRATIONS);
            integrations.reserve(integrationCount);

            for (std::size_t i = 0; i < integrationCount; ++i)
            {
                std::string integration;
                if (policyJson.getString(integration, fmt::format("{}/{}", jsonpolicy::PATH_KEY_INTEGRATIONS, i))
                    != json::RetGet::Success)
                {
                    throw std::runtime_error(fmt::format("Integration at index {} is not a valid string", i));
                }

                integrations.push_back(std::move(integration));
            }
            return integrations;
        }();

        // Get filters
        std::vector<std::string> filters = [&]() -> auto
        {
            std::vector<std::string> filters;
            if (policyJson.isArray(jsonpolicy::PATH_KEY_FILTERS))
            {
                std::size_t filtersCount = policyJson.size(jsonpolicy::PATH_KEY_FILTERS);
                filters.reserve(filtersCount);
                for (std::size_t i = 0; i < filtersCount; ++i)
                {
                    std::string filter;
                    if (policyJson.getString(filter, fmt::format("{}/{}", jsonpolicy::PATH_KEY_FILTERS, i))
                        != json::RetGet::Success)
                    {
                        throw std::runtime_error(fmt::format("Filter at index {} is not a valid string", i));
                    }
                    filters.push_back(std::move(filter));
                }
            }
            else
            {
                throw std::runtime_error("Policy JSON must have a 'filters' array");
            }
            return filters;
        }();

        // Get enrichments
        std::vector<std::string> enrichments = [&]() -> auto
        {
            std::vector<std::string> enrichments;
            if (policyJson.isArray(jsonpolicy::PATH_KEY_ENRICHMENTS))
            {
                std::size_t enrichmentsCount = policyJson.size(jsonpolicy::PATH_KEY_ENRICHMENTS);
                enrichments.reserve(enrichmentsCount);
                for (std::size_t i = 0; i < enrichmentsCount; ++i)
                {
                    std::string enrichment;
                    if (policyJson.getString(enrichment, fmt::format("{}/{}", jsonpolicy::PATH_KEY_ENRICHMENTS, i))
                        != json::RetGet::Success)
                    {
                        throw std::runtime_error(fmt::format("Enrichment at index {} is not a valid string", i));
                    }
                    enrichments.push_back(std::move(enrichment));
                }
            }
            else
            {
                throw std::runtime_error("Policy JSON must have an 'enrichments' array");
            }
            return enrichments;
        }();

        // optional outputs
        std::vector<std::string> outputs = [&]() -> auto
        {
            std::vector<std::string> outputs;
            if (policyJson.isArray(jsonpolicy::PATH_KEY_OUTPUTS))
            {
                std::size_t outputsCount = policyJson.size(jsonpolicy::PATH_KEY_OUTPUTS);
                outputs.reserve(outputsCount);
                for (std::size_t i = 0; i < outputsCount; ++i)
                {
                    std::string output;
                    if (policyJson.getString(output, fmt::format("{}/{}", jsonpolicy::PATH_KEY_OUTPUTS, i))
                        != json::RetGet::Success)
                    {
                        throw std::runtime_error(fmt::format("Output at index {} is not a valid string", i));
                    }

                    outputs.push_back(std::move(output));
                }
            }
            return outputs;
        }();

        // optional origin_space
        auto originSpace = [&]() -> std::string
        {
            std::string originSpace;
            if (policyJson.getString(originSpace, jsonpolicy::PATH_KEY_ORIGIN_SPACE) != json::RetGet::Success
                || originSpace.empty())
            {
                return std::string(jsonpolicy::DEFAULT_ORIGIN_SPACE);
            }

            return originSpace;
        }();

        // optional hash
        auto policyHash = [&]() -> std::string
        {
            std::string hash;
            if (policyJson.getString(hash, jsonpolicy::PATH_KEY_HASH) != json::RetGet::Success || hash.empty())
            {
                return "";
            }
            return hash;
        }();

        // Get index_unclassified_events flag
        auto indexUnclassifiedEvents = [&]() -> bool
        {
            auto indexOpt = policyJson.getBool(jsonpolicy::PATH_KEY_INDEX_UNCLASSIFIED_EVENTS);
            if (!indexOpt.has_value())
            {
                throw std::runtime_error("Policy JSON must have a boolean 'index_unclassified_events' field");
            }
            return indexOpt.value();
        }();

        // Get index_discarded_events flag
        bool indexDiscardedEvents = [&]() -> bool
        {
            auto indexDiscardedOpt = policyJson.getBool(jsonpolicy::PATH_KEY_INDEX_DISCARDED_EVENTS);
            if (!indexDiscardedOpt.has_value())
            {
                throw std::runtime_error("Policy JSON must have a boolean 'index_discarded_events' field");
            }
            return indexDiscardedOpt.value();
        }();

        // Get cleanup_decoder_variables flag
        bool cleanupDecoderVariables = [&]() -> bool
        {
            auto cleanupDecoderVariablesOpt = policyJson.getBool(jsonpolicy::PATH_KEY_CLEANUP_DECODER_VARIABLES);
            if (!cleanupDecoderVariablesOpt.has_value())
            {
                return true;
            }
            return cleanupDecoderVariablesOpt.value();
        }();

        return {title,
                enabled,
                rootDecoder,
                std::move(integrations),
                std::move(filters),
                std::move(enrichments),
                std::move(outputs),
                originSpace,
                policyHash,
                indexUnclassifiedEvents,
                indexDiscardedEvents,
                cleanupDecoderVariables};
    }

    json::Json toJson() const
    {
        json::Json policyJson;

        policyJson.setString(m_title, jsonpolicy::PATH_KEY_TITLE);
        policyJson.setBool(m_enabled, jsonpolicy::PATH_KEY_ENABLED);
        policyJson.setString(m_rootDecoder, jsonpolicy::PATH_KEY_ROOT_PARENT);
        policyJson.setString(m_originSpace, jsonpolicy::PATH_KEY_ORIGIN_SPACE);
        policyJson.setString(m_hash, jsonpolicy::PATH_KEY_HASH);

        policyJson.setArray(jsonpolicy::PATH_KEY_INTEGRATIONS);
        for (const auto& uuid : m_integrations)
        {
            policyJson.appendString(uuid, jsonpolicy::PATH_KEY_INTEGRATIONS);
        }

        policyJson.setArray(jsonpolicy::PATH_KEY_FILTERS);
        for (const auto& filter : m_filters)
        {
            policyJson.appendString(filter, jsonpolicy::PATH_KEY_FILTERS);
        }

        policyJson.setArray(jsonpolicy::PATH_KEY_ENRICHMENTS);
        for (const auto& enrichment : m_enrichments)
        {
            policyJson.appendString(enrichment, jsonpolicy::PATH_KEY_ENRICHMENTS);
        }

        policyJson.setArray(jsonpolicy::PATH_KEY_OUTPUTS);
        for (const auto& output : m_outputs)
        {
            policyJson.appendString(output, jsonpolicy::PATH_KEY_OUTPUTS);
        }

        policyJson.setBool(m_indexUnclassifiedEvents, jsonpolicy::PATH_KEY_INDEX_UNCLASSIFIED_EVENTS);

        policyJson.setBool(m_indexDiscardedEvents, jsonpolicy::PATH_KEY_INDEX_DISCARDED_EVENTS);

        policyJson.setBool(m_cleanupDecoderVariables, jsonpolicy::PATH_KEY_CLEANUP_DECODER_VARIABLES);

        return policyJson;
    }

    // Setters
    //  Getters
    const std::string& getTitle() const { return m_title; }
    bool isEnabled() const { return m_enabled; }
    const std::vector<std::string>& getFiltersUUIDs() const { return m_filters; }
    const std::vector<std::string>& getEnrichments() const { return m_enrichments; }
    const std::vector<std::string>& getOutputsUUIDs() const { return m_outputs; }
    const std::vector<std::string>& getIntegrationsUUIDs() const { return m_integrations; }
    const std::string& getRootDecoderUUID() const { return m_rootDecoder; }
    const std::string& getHash() const { return m_hash; }

    // Getters and setters of optional values
    const std::string& getOriginSpace() const { return m_originSpace; }
    void setOriginSpace(std::string_view originSpace)
    {
        validateOriginSpace(originSpace);
        m_originSpace = originSpace;
    }
    bool shouldIndexUnclassifiedEvents() const { return m_indexUnclassifiedEvents; }
    bool shouldIndexDiscardedEvents() const { return m_indexDiscardedEvents; }
    bool shouldCleanupDecoderVariables() const { return m_cleanupDecoderVariables; }
};

} // namespace cm::store::dataType

#endif // ICMSTORE_DATA_POLICY
