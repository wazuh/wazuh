#include <api/integration/integration.hpp>

#include <fmt/format.h>

#include <json/json.hpp>

namespace api::integration
{
std::optional<base::Error> Integration::addTo(const api::catalog::Resource& policy,
                                              const api::catalog::Resource& integration)
{
    using api::catalog::Resource;

    if (integration.m_type != Resource::Type::integration)
    {
        return base::Error {fmt::format(R"(Expected integration resource type, got '{}' for resource '{}')",
                                        Resource::typeToStr(integration.m_type),
                                        integration.m_name.fullName())};
    }

    if (policy.m_type != Resource::Type::policy)
    {
        return base::Error {fmt::format(R"(Expected policy resource type, got '{}' for resource '{}')",
                                        Resource::typeToStr(policy.m_type),
                                        policy.m_name.fullName())};
    }

    auto respose = m_catalog->getResource(policy);
    if (std::holds_alternative<base::Error>(respose))
    {
        return base::Error {fmt::format(R"(Policy '{}' could not be obtained from store: {})",
                                        policy.m_name.fullName(),
                                        std::get<base::Error>(respose).message)};
    }
    json::Json policyJson {std::get<std::string>(respose).c_str()};

    // Add the integration to the policy
    if (policyJson.exists("/integrations"))
    {
        auto integrations = policyJson.getArray("/integrations");
        if (!integrations)
        {
            return base::Error {
                fmt::format(R"(Policy '{}' has an invalid integrations array)", policy.m_name.fullName())};
        }

        auto integrationIt = std::find_if(integrations.value().begin(),
                                          integrations.value().end(),
                                          [&integration](const json::Json& item)
                                          { return item.getString().value_or("") == integration.m_name.fullName(); });
        if (integrationIt == integrations.value().end())
        {
            policyJson.appendString(integration.m_name.fullName(), "/integrations");
        }
        else
        {
            return base::Error {fmt::format(R"(Integration '{}' already exists in policy '{}')",
                                            integration.m_name.fullName(),
                                            policy.m_name.fullName())};
        }
    }
    else
    {
        json::Json integrations;
        integrations.setArray();
        integrations.appendString(integration.m_name.fullName());
        policyJson.set("/integrations", integrations);
    }

    // Update
    return m_catalog->putResource(policy, policyJson.str());
}

std::optional<base::Error> Integration::removeFrom(const api::catalog::Resource& policy,
                                                   const api::catalog::Resource& integration)
{
    using api::catalog::Resource;

    if (integration.m_type != Resource::Type::integration)
    {
        return base::Error {fmt::format(R"(Expected integration resource type, got '{}' for resource '{}')",
                                        Resource::typeToStr(integration.m_type),
                                        integration.m_name.fullName())};
    }

    if (policy.m_type != Resource::Type::policy)
    {
        return base::Error {fmt::format(R"(Expected policy resource type, got '{}' for resource '{}')",
                                        Resource::typeToStr(policy.m_type),
                                        policy.m_name.fullName())};
    }

    auto respose = m_catalog->getResource(policy);
    if (std::holds_alternative<base::Error>(respose))
    {
        return base::Error {fmt::format(R"(Policy '{}' could not be obtained from store: {})",
                                        policy.m_name.fullName(),
                                        std::get<base::Error>(respose).message)};
    }
    json::Json policyJson {std::get<std::string>(respose).c_str()};

    // Remove the integration from the policy
    if (policyJson.exists("/integrations"))
    {
        auto integrations = policyJson.getArray("/integrations");
        if (!integrations)
        {
            return base::Error {
                fmt::format(R"(Policy '{}' has an invalid integrations array)", policy.m_name.fullName())};
        }

        json::Json newIntegrations;
        newIntegrations.setArray();
        for (auto& integrationJson : integrations.value())
        {
            if (integrationJson.getString().value_or("") != integration.m_name.fullName())
            {
                newIntegrations.appendJson(integrationJson);
            }
        }

        policyJson.set("/integrations", newIntegrations);
        // Validate the policy and update
        return m_catalog->putResource(policy, policyJson.str());
    }

    return std::nullopt;
}
} // namespace api::integration
