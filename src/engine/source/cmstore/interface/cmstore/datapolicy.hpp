#ifndef _ICMSTORE_DATA_POLICY
#define _ICMSTORE_DATA_POLICY

#include <string>
#include <tuple>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

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
 *   "root_decoder": "decoder/wazuh-core-message/0",  --> Optional
 *   "default_parent": "decoder/integration/0", --> Optional
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
constexpr std::string_view PATH_KEY_ROOT_DECODER = "/root_decoder";
constexpr std::string_view PATH_KEY_DEFAULT_PARENT = "/default_parent";
constexpr std::string_view PATH_KEY_HASH = "/hash";

} // namespace jsonpolicy

class Policy
{
private:
    std::vector<std::string> m_integrationsUUIDs;
    std::vector<std::string> m_integrationsNames;

    base::Name m_rootDecoder {"decoder/wazuh-core-message/0"};
    base::Name m_defaultParent;

    std::string m_hash;

public:

    Policy() = default;
    ~Policy() = default;

    static Policy fromJson(const json::Json& policyJson)
    {
        Policy policy;

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

        policy.m_integrationsUUIDs.reserve(integrationCount);
        policy.m_integrationsNames.reserve(integrationCount);

        for (std::size_t i = 0; i < integrationCount; ++i)
        {
            auto integrationOpt = policyJson.getString(fmt::format("{}/{}", jsonpolicy::PATH_KEY_INTEGRATIONS, i));
            if (!integrationOpt.has_value())
            {
                throw std::runtime_error(fmt::format("Integration at index {} is not a valid string", i));
            }
            policy.m_integrationsUUIDs.push_back(integrationOpt.value());
        }

        try
        {
            if (auto rootDecoderOpt = policyJson.getString(jsonpolicy::PATH_KEY_ROOT_DECODER);
                rootDecoderOpt.has_value())
            {
                policy.m_rootDecoder = base::Name(rootDecoderOpt.value());
            }

            if (auto defaultParentOpt = policyJson.getString(jsonpolicy::PATH_KEY_DEFAULT_PARENT);
                defaultParentOpt.has_value())
            {
                policy.m_defaultParent = base::Name(defaultParentOpt.value());
            }
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format("Error getting policy default parent or root decoder: {}", e.what()));
        }

        if (auto hashOpt = policyJson.getString(jsonpolicy::PATH_KEY_HASH); hashOpt.has_value())
        {
            policy.m_hash = hashOpt.value();
        } else {
            policy.m_hash = "";
        }



        return policy;
    }

    const std::vector<std::string>& getIntegrationsUUIDs() const { return m_integrationsUUIDs; }
    const std::vector<std::string>& getIntegrationsNames() const { return m_integrationsNames; }
    const base::Name& getRootDecoder() const { return m_rootDecoder; }
    const base::Name& getDefaultParent() const { return m_defaultParent; }
    const std::string& getHash() const { return m_hash; }
};

} // namespace cm::store::dataType

#endif // _ICMSTORE_DATA_POLICY
