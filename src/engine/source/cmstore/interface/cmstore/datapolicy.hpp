#ifndef _ICMSTORE_DATA_POLICY
#define _ICMSTORE_DATA_POLICY

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
 *   "title": "Development 0.0.1",
 *   "root_decoder": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8"
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
 *   "outputs": [] -> opcional.
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
constexpr std::string_view PATH_KEY_OUTPUTS = "/outputs";
constexpr std::string_view PATH_KEY_TITLE = "/title";
constexpr std::string_view PATH_KEY_ORIGIN_SPACE = "/origin_space";
constexpr std::string_view PATH_KEY_HASH = "/hash";

} // namespace jsonpolicy

namespace
{
constexpr std::string_view DEFAULT_ORIGIN_SPACE = "UNDEFINED"; ///< Default origin space when not specified
}

/**
 * @brief Policy class representing a policy in wazuh-engine
 *
 * This defines the pipeline of processing for events, including integrations,
 */
class Policy
{
private:
    std::string m_title;                     ///< Title of the policy
    std::string m_rootDecoder;               ///< Root decoder UUID
    std::string m_originSpace;               ///< Origin space name (Optional)
    std::vector<std::string> m_integrations; ///< Integrations UUIDs included in the policy
    std::vector<std::string> m_filters;      ///< Filters defined in the policy
    std::vector<std::string> m_enrichments;  ///< Enrichments plugins defined in the policy
    std::vector<std::string> m_outputs;      ///< Outputs defined in the policy (optional)

    std::string m_hash;                      ///< Hash of the policy for integrity verification

public:
    ~Policy() = default;
    Policy() = delete;

    Policy(std::string_view policyTitle,
           std::string_view rootDecoder,
           std::vector<std::string> integrationsUUIDs,
           std::vector<std::string> filters,
           std::vector<std::string> enrichments,
           std::vector<std::string> outputs,
           std::string_view originSpace = DEFAULT_ORIGIN_SPACE,
           std::string_view hash = "")
        : m_title(policyTitle)
        , m_rootDecoder(rootDecoder)
        , m_integrations(std::move(integrationsUUIDs))
        , m_filters(std::move(filters))
        , m_enrichments(std::move(enrichments))
        , m_outputs(std::move(outputs))
        , m_originSpace(originSpace)
        , m_hash(hash)
    {
        cm::store::detail::findDuplicateOrInvalidUUID(m_integrations, "Integration");
        cm::store::detail::findDuplicateOrInvalidUUID(m_outputs, "Output");
        cm::store::detail::findDuplicateOrInvalidUUID(m_filters, "Filter");
    }

    // Dumper and loader
    static Policy fromJson(const json::Json& policyJson)
    {
        if (!policyJson.isObject())
        {
            throw std::runtime_error("Policy JSON must be an object");
        }

        // Get title
        std::string title = [&]() -> auto
        {
            auto titleOpt = policyJson.getString(jsonpolicy::PATH_KEY_TITLE);
            if (!titleOpt.has_value() || titleOpt->empty())
            {
                throw std::runtime_error("Policy JSON must have a non-empty 'title' field");
            }
            return titleOpt.value();
        }();

        // Get root decoder
        auto rootDecoder = [&]()
        {
            auto rootDecoderOpt = policyJson.getString(jsonpolicy::PATH_KEY_ROOT_PARENT);
            if (!rootDecoderOpt.has_value() || rootDecoderOpt->empty())
            {
                throw std::runtime_error("Policy JSON must have a 'root_decoder' UUID");
            }
            return rootDecoderOpt.value();
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
            if (integrationCount == 0)
            {
                throw std::runtime_error("Policy JSON must have at least one integration");
            }
            integrations.reserve(integrationCount);

            for (std::size_t i = 0; i < integrationCount; ++i)
            {
                auto integrationOpt = policyJson.getString(fmt::format("{}/{}", jsonpolicy::PATH_KEY_INTEGRATIONS, i));
                if (!integrationOpt.has_value())
                {
                    throw std::runtime_error(fmt::format("Integration at index {} is not a valid string", i));
                }

                integrations.push_back(integrationOpt.value());
            }
            return integrations;
        }();

        // filters
        std::vector<std::string> filters = [&]() -> auto
        {
            std::vector<std::string> filters;
            if (policyJson.isArray(jsonpolicy::PATH_KEY_FILTERS))
            {
                std::size_t filtersCount = policyJson.size(jsonpolicy::PATH_KEY_FILTERS);
                filters.reserve(filtersCount);
                for (std::size_t i = 0; i < filtersCount; ++i)
                {
                    auto filterOpt = policyJson.getString(fmt::format("{}/{}", jsonpolicy::PATH_KEY_FILTERS, i));
                    if (!filterOpt.has_value())
                    {
                        throw std::runtime_error(fmt::format("Filter at index {} is not a valid string", i));
                    }
                    filters.push_back(filterOpt.value());
                }
            }
            // TODO: Uncomment when filters are mandatory
            // else
            // {
            //     throw std::runtime_error("Policy JSON must have a 'filters' array");
            // }
            return filters;
        }();

        // enrichments
        std::vector<std::string> enrichments = [&]() -> auto
        {
            std::vector<std::string> enrichments;
            if (policyJson.isArray(jsonpolicy::PATH_KEY_ENRICHMENTS))
            {
                std::size_t enrichmentsCount = policyJson.size(jsonpolicy::PATH_KEY_ENRICHMENTS);
                enrichments.reserve(enrichmentsCount);
                for (std::size_t i = 0; i < enrichmentsCount; ++i)
                {
                    auto enrichmentOpt =
                        policyJson.getString(fmt::format("{}/{}", jsonpolicy::PATH_KEY_ENRICHMENTS, i));
                    if (!enrichmentOpt.has_value())
                    {
                        throw std::runtime_error(fmt::format("Enrichment at index {} is not a valid string", i));
                    }
                    enrichments.push_back(enrichmentOpt.value());
                }
            }
            // TODO: Uncomment when enrichments are mandatory
            // else
            // {
            //     throw std::runtime_error("Policy JSON must have an 'enrichments' array");
            // }
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
                    auto outputOpt = policyJson.getString(fmt::format("{}/{}", jsonpolicy::PATH_KEY_OUTPUTS, i));
                    if (!outputOpt.has_value())
                    {
                        throw std::runtime_error(fmt::format("Output at index {} is not a valid string", i));
                    }

                    outputs.push_back(outputOpt.value());
                }
            }
            return outputs;
        }();

        // optional origin_space
        auto originSpace = [&]() -> std::string
        {
            auto originSpaceOpt = policyJson.getString(jsonpolicy::PATH_KEY_ORIGIN_SPACE);
            if (!originSpaceOpt.has_value() || originSpaceOpt->empty())
            {
                return std::string(DEFAULT_ORIGIN_SPACE);
            }
            return originSpaceOpt.value();
        }();

        auto policyHash = [&]() -> std::string {
            auto hashOpt = policyJson.getString(jsonpolicy::PATH_KEY_HASH);
            if (!hashOpt.has_value() || hashOpt->empty())
            {
                return "";
            }
            return hashOpt.value();
        }();

        return {title,
                rootDecoder,
                std::move(integrations),
                std::move(filters),
                std::move(enrichments),
                std::move(outputs),
                originSpace,
                policyHash};

    }

    json::Json toJson() const
    {
        json::Json policyJson;

        policyJson.setString(m_title, jsonpolicy::PATH_KEY_TITLE);
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

        return policyJson;
    }

    //Setters
    // Getters
    const std::string& getTitle() const { return m_title; }
    const std::vector<std::string>& getFiltersUUIDs() const { return m_filters; }
    const std::vector<std::string>& getEnrichments() const { return m_enrichments; }
    const std::vector<std::string>& getOutputsUUIDs() const { return m_outputs; }
    const std::vector<std::string>& getIntegrationsUUIDs() const { return m_integrations; }
    const std::string& getRootDecoderUUID() const { return m_rootDecoder; }
    const std::string& getHash() const { return m_hash; }

    // Getters and setters of optional values
    const std::string& getOriginSpace() const { return m_originSpace; }
    void setOriginSpace(std::string_view originSpace) { m_originSpace = originSpace; }
};

} // namespace cm::store::dataType

#endif // _ICMSTORE_DATA_POLICY
