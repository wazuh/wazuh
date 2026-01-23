#ifndef _ICMSTORE_DATA_POLICY
#define _ICMSTORE_DATA_POLICY

#include <string>
#include <tuple>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>
#include <base/utils/generator.hpp>
#include <base/utils/hash.hpp>

#include <cmstore/detail.hpp>

/**
 * @brief DataPolicy class to represent a content manager data policy. Its the definition of a policy.
 *
 * This class encapsulates the data and operations related to a content manager data policy,
 * including its integrations, default parent, root decoder, and hash.
 *
 * Expexted JSON format:
 * {
 *   "type": "policy",
 *   "title": "Development 0.0.1",
 *   "default_parent": "2321h312-015f-27h2-1771-d88h2ns2h6s8", --> Should be mandatory
 *   "root_decoder": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8", --> Should be mandatory
 *   "integrations":
 *   [
 *     "42e28392-4f5e-473d-89e8-c9030e6fedc2", --> Intration UUIDs
 *     "a7fe64a2-0a03-414f-8692-8441bdfe6f69",
 *     "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
 *     "f61133f5-90b9-49ed-b1d5-0b88cb04355e",
 *     "369c3128-9715-4a30-9ff9-22fcac87688b",
 *   ]
 * }
 *
 */

namespace cm::store::dataType
{

namespace jsonpolicy
{
constexpr std::string_view PATH_KEY_INTEGRATIONS = "/integrations";
constexpr std::string_view PATH_KEY_ROOT_PARENT = "/root_decoder";

} // namespace jsonpolicy

class Policy
{
private:
    std::vector<std::string> m_integrationsUUIDs;
    std::string m_rootDecoder;
    std::string m_hash;

    void updateHash()
    {
        // Create a hash based on the integrations UUIDs and defaults decoders
        std::string toHash = m_rootDecoder;
        toHash.reserve(toHash.length() + m_integrationsUUIDs.size() * base::utils::generators::UUID_V4_LENGTH);
        for (const auto& uuid : m_integrationsUUIDs)
        {
            toHash += uuid;
        }
        m_hash = base::utils::hash::sha256(toHash);
    }

public:
    ~Policy() = default;
    Policy() = delete;

    Policy(std::vector<std::string>&& uuids, std::string rootDecoder)
        : m_integrationsUUIDs(std::move(uuids))
        , m_rootDecoder(std::move(rootDecoder))
    {
        cm::store::detail::findDuplicateOrInvalidUUID(m_integrationsUUIDs, "Integration");

        updateHash();
    }

    // Dumper and loader
    static Policy fromJson(const json::Json& policyJson)
    {
        if (!policyJson.isObject())
        {
            throw std::runtime_error("Policy JSON must be an object");
        }

        if (!policyJson.isArray(jsonpolicy::PATH_KEY_INTEGRATIONS))
        {
            throw std::runtime_error("Policy JSON must have an 'integrations' array");
        }

        std::size_t integrationCount = policyJson.size(jsonpolicy::PATH_KEY_INTEGRATIONS);
        if (integrationCount == 0)
        {
            throw std::runtime_error("Policy JSON must have at least one integration");
        }

        std::vector<std::string> integrations;
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

        auto rootDecoderOpt = policyJson.getString(jsonpolicy::PATH_KEY_ROOT_PARENT);
        if (!rootDecoderOpt.has_value() || rootDecoderOpt->empty())
        {
            throw std::runtime_error("Policy JSON must have a 'root_decoder' UUID");
        }

        return {std::move(integrations), std::move(rootDecoderOpt.value())};
    }

    json::Json toJson() const
    {
        json::Json policyJson;

        policyJson.setString(m_rootDecoder, jsonpolicy::PATH_KEY_ROOT_PARENT);
        policyJson.setArray(jsonpolicy::PATH_KEY_INTEGRATIONS);
        for (const auto& uuid : m_integrationsUUIDs)
        {
            policyJson.appendString(uuid, jsonpolicy::PATH_KEY_INTEGRATIONS);
        }

        return policyJson;
    }

    // Getters
    const std::vector<std::string>& getIntegrationsUUIDs() const { return m_integrationsUUIDs; }
    const std::string& getRootDecoder() const { return m_rootDecoder; }
    const std::string& getHash() const { return m_hash; }
};

} // namespace cm::store::dataType

#endif // _ICMSTORE_DATA_POLICY
