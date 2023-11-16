#ifndef _ROUTER2_ENVIRONMENT_BUILD_HPP
#define _ROUTER2_ENVIRONMENT_BUILD_HPP

#include <bk/icontroller.hpp>

#include "environment.hpp"
#include "ibuilder.hpp"

namespace router
{

constexpr auto JSON_PATH_SESSION_FILTER {"/TestSessionID"};
/**
 * @brief BuildEnvironment class for creating environments based on policies and filters.
 *
 */
class EnvironmentBuilder
{
private:
    std::shared_ptr<IBuilder> m_builder;                     ///< The builder used to construct the policy and filter.
    std::shared_ptr<bk::IControllerMaker> m_controllerMaker; ///< The controller maker used to construct the controller.

    /**
     * @brief Get the Controller object for a given policy.
     *
     * @param policyName The name of the policy.
     * @param builder The builder used to construct the policy.
     * @return std::shared_ptr<bk::IController> The constructed controller.
     * @throws std::runtime_error if the policy has no assets or if the backend cannot be built.
     */
    std::shared_ptr<bk::IController> getController(const base::Name& policyName)
    {
        if (policyName.parts().size() == 0 || policyName.parts()[0] != "policy")
        {
            throw std::runtime_error {"The asset name is empty or it is not a policy"};
        }
        // Build the policy and create the pipeline
        auto newPolicy = m_builder->buildPolicy(policyName);
        if (base::isError(newPolicy))
        {
            throw std::runtime_error {base::getError(newPolicy).message};
        }

        auto policy = base::getResponse(newPolicy);
        if (policy->assets().empty())
        {
            throw std::runtime_error {fmt::format("Policy '{}' has no assets", policyName)};
        }

        // TODO Check de assets names policy api (Return a string instead of a base::Names?)
        std::unordered_set<std::string> assetNames;
        std::transform(policy->assets().begin(),
                       policy->assets().end(),
                       std::inserter(assetNames, assetNames.begin()),
                       [](const auto& name) { return name.toStr(); });

        auto controller = m_controllerMaker->create();
        controller->build(policy->expression(), assetNames);
        return controller;
    }

    /**
     * @brief Get the Expression object for a given filter.
     *
     * @param filterName The name of the filter.
     * @return base::Expression The constructed filter expression.
     * @throws std::runtime_error if the filter cannot be built.
     */
    base::Expression getExpression(const base::Name& filterName)
    {
        // TODO: Remove this check when the Builder can identify if it is a filter or not
        if (filterName.parts().size() == 0 || filterName.parts()[0] != "filter")
        {
            throw std::runtime_error {"The asset name is empty or it is not a filter"};
        }
        auto filter = m_builder->buildAsset(filterName);
        if (base::isError(filter))
        {
            throw std::runtime_error {base::getError(filter).message};
        }

        return base::getResponse(filter);
    }

public:
    /**
     * @brief Construct a new BuildEnvironment object
     *
     * @param builder The builder used to construct the policy and filter.
     */
    EnvironmentBuilder(std::shared_ptr<IBuilder> builder, std::shared_ptr<bk::IControllerMaker> controllerMaker)
        : m_builder(builder)
        , m_controllerMaker(controllerMaker)
    {
        if (m_builder == nullptr)
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
     * @brief Create an environment based on a policy and a filter.
     *
     * @param policyName The name of the policy.
     * @param filterName The name of the filter.
     * @return Environment The created environment.
     * @throws std::runtime_error if failed to create the environment.
     */
    std::unique_ptr<Environment> create(const base::Name& policyName, const base::Name& filterName)
    {
        try
        {
            auto controller = getController(policyName);
            auto expression = getExpression(filterName);
            return std::make_unique<Environment>(std::move(expression), std::move(controller));
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error {fmt::format(
                "Failed to create environment with policy '{}' and filter '{}': {}", policyName, filterName, e.what())};
        }
    }

};

} // namespace router

#endif //_ROUTER2_ENVIRONMENT_BUILD_HPP
