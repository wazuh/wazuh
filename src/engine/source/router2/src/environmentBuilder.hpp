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
    EnvironmentBuilder(std::shared_ptr<IBuilder> builder)
        : m_builder(builder)
    {
        if (m_builder == nullptr)
        {
            throw std::runtime_error {"Cannot create BuildEnvironment with a null builder"};
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
    Environment create(const base::Name& policyName, const base::Name& filterName)
    {
        try
        {
            auto controller = getController(policyName);
            auto expression = getExpression(filterName);
            return Environment(std::move(expression), std::move(controller));
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error {fmt::format(
                "Failed to create environment with policy '{}' and filter '{}': {}", policyName, filterName, e.what())};
        }
    }

    /**
     * @brief Create an environment based on a policy and a filter ID.
     *
     * The filter ID is used to create a filter expression that checks if the session ID is equal to the filter ID.
     * @param policyName The name of the policy.
     * @param filterId The filter ID.
     * @param builder The builder used to construct the policy and filter.
     * @return Environment The created environment.
     * @throw std::runtime_error if failed to create the environment.
     */
    Environment create(const base::Name& policyName, const uint32_t filterId)
    {
        if (policyName.parts().size() == 0 || policyName.parts()[0] != "policy")
        {
            throw std::runtime_error {"The asset name is empty or it is not a policy"};
        }

        std::shared_ptr<bk::IController> controller {};
        try
        {
            controller = getController(policyName);
        }
        catch (std::runtime_error e)
        {
            throw std::runtime_error {fmt::format(
                "Failed to create environment with policy '{}' and filter '{}': {}", policyName, filterId, e.what())};
        }

        json::Json value {std::to_string(filterId).c_str()};

        const auto name {fmt::format("Router filter {} -> {}", JSON_PATH_SESSION_FILTER, value.str())};

        auto expression =
            base::Term<base::EngineOp>::create(name,
                                               [value](const base::Event& event) -> base::result::Result<base::Event>
                                               {
                                                   if (event->equals(JSON_PATH_SESSION_FILTER, value))
                                                   {
                                                       return base::result::makeSuccess(event);
                                                   }
                                                   return base::result::makeFailure(event);
                                               });

        return Environment(std::move(expression), std::move(controller));
    }
};

} // namespace router

#endif //_ROUTER2_ENVIRONMENT_BUILD_HPP
