#ifndef ROUTER_ENVIRONMENT_BUILD_HPP
#define ROUTER_ENVIRONMENT_BUILD_HPP

#include <memory>
#include <unordered_set>
#include <utility>

#include <bk/icontroller.hpp>
#include <builder/ibuilder.hpp>
#include <cmstore/types.hpp>

#include "environment.hpp"

namespace router
{

/**
 * @brief Class used to build an environment.
 *
 */
class EnvironmentBuilder
{
private:
    std::weak_ptr<builder::IBuilder> m_builder;              ///< The builder used to construct the policy.
    std::shared_ptr<bk::IControllerMaker> m_controllerMaker; ///< The controller maker used to construct the controller.

public:
    /**
     * @brief Create a new EnvironmentBuilder
     *
     */
    EnvironmentBuilder(std::weak_ptr<builder::IBuilder> builder, std::shared_ptr<bk::IControllerMaker> controllerMaker)
        : m_builder(std::move(builder))
        , m_controllerMaker(std::move(controllerMaker))
    {
        if (m_builder.expired() || m_builder.lock() == nullptr)
        {
            throw std::runtime_error {"Cannot create BuildEnvironment with a null builder"};
        }

        if (m_controllerMaker == nullptr)
        {
            throw std::runtime_error {"Cannot create BuildEnvironment with a null controller maker"};
        }
    }

    EnvironmentBuilder() = delete;

    /**
     * @brief Get the Controller object for a given policy.
     *
     * @param namespaceId The namespace of the policy.
     * @param isTestMode Whether to build the policy in test mode.
     * @return std::pair<std::shared_ptr<bk::IController>, std::string> The controller and the policy hash.
     * @throws std::runtime_error if the policy has no assets or if the backend cannot be built.
     */
    auto makeController(const cm::store::NamespaceId& namespaceId, const bool isTestMode = true)
        -> std::pair<std::shared_ptr<bk::IController>, std::string>
    {
        // Build the policy and create the pipeline
        auto builder = m_builder.lock();
        if (builder == nullptr)
        {
            throw std::runtime_error {"The builder is not available"};
        }

        auto policy = builder->buildPolicy(namespaceId, isTestMode);
        if (policy == nullptr)
        {
            throw std::runtime_error {fmt::format("Failed to build policy '{}'", namespaceId.toStr())};
        }

        if (policy->assets().empty())
        {
            throw std::runtime_error {fmt::format("Policy '{}' has no assets", namespaceId.toStr())};
        }

        std::unordered_set<std::string> assetNames;
        std::transform(policy->assets().begin(),
                       policy->assets().end(),
                       std::inserter(assetNames, assetNames.begin()),
                       [](const auto& name) { return name.toStr(); });

        auto controller = m_controllerMaker->create(policy->expression(), assetNames);
        if (controller == nullptr)
        {
            throw std::runtime_error {fmt::format("Failed to create controller for policy '{}'", namespaceId.toStr())};
        }

        return {controller, policy->hash()};
    }

    /**
     * @brief Create an environment based on a policy.
     *
     * @param policyName The name of the policy.
     * @return Environment The created environment.
     * @throws std::runtime_error if failed to create the environment. // TODO CHange to base::Error
     */
    std::unique_ptr<Environment> create(const cm::store::NamespaceId& namespaceId)
    {
        std::shared_ptr<bk::IController> controller = nullptr;
        try
        {
            std::string hash {};
            std::tie(controller, hash) = makeController(namespaceId, /*isTestMode=*/false);
            return std::make_unique<Environment>(std::move(controller), std::move(hash));
        }
        catch (const std::runtime_error& e)
        {
            if (controller != nullptr)
            {
                controller->stop();
            }
            throw std::runtime_error {fmt::format(
                "Failed to create environment with policy '{}': {}", namespaceId.toStr(), e.what())};
        }
    }
};

} // namespace router

#endif //ROUTER_ENVIRONMENT_BUILD_HPP
