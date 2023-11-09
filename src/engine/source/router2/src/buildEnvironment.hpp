#ifndef _ROUTER2_BUILD_ENVIRONMENT_HPP
#define _ROUTER2_BUILD_ENVIRONMENT_HPP

#include "environment.hpp"
#include "ibuilder.hpp"

namespace router
{

constexpr auto JSON_PATH_SESSION_FILTER {"/TestSessionID"};

/**
 * @brief BuildEnvironment class for creating environments based on policies and filters.
 *
 */
template <typename T, typename = std::enable_if_t<std::is_base_of<bk::IController, T>::value>>
class BuildEnvironment
{
private:
    std::shared_ptr<IBuilder> m_builder;

    /**
     * @brief Get the Controller object for a given policy.
     *
     * @param policyName The name of the policy.
     * @param builder The builder used to construct the policy.
     * @return std::shared_ptr<bk::IController> The constructed controller.
     */
    std::shared_ptr<T> getController(base::Name& policyName)
    {
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

        auto controller =  std::make_shared<T>();
        controller->build(policy->expression(), assetNames);
        return controller;
    }

    /**
     * @brief Get the Expression object for a given filter.
     *
     * @param filterName The name of the filter.
     * @return base::Expression The constructed filter expression.
     */
    base::Expression getExpression(base::Name& filterName)
    {
        // TODO: Remove this check when the Builder can identify if it is a filter or not
        if (filterName.parts().size() == 0 || filterName.parts()[0] != "filter")
        {
            throw std::runtime_error {"The asset name is empty or it is not a filter"};
        }

        auto filter = m_builder->buildAsset(filterName);
        if(base::isError(filter))
        {
            throw std::runtime_error {base::getError(filter).message};
        }

        return base::getResponse(filter);
    }

public:

    BuildEnvironment(std::shared_ptr<IBuilder> builder) : m_builder (builder){}

    /**
     * @brief Create an environment based on a policy and a filter.
     *
     * @param policyName The name of the policy.
     * @param filterName The name of the filter.
     * @return Environment The created environment.
     */
    Environment create(base::Name& policyName, base::Name& filterName)
    {
        auto controller = getController(policyName);
        auto expression = getExpression(filterName);
        return Environment (std::move(expression), std::move(controller));
    }

    /**
     * @brief Create an environment based on a policy and a filter ID.
     *
     * @param policyName The name of the policy.
     * @param filterId The filter ID.
     * @param builder The builder used to construct the policy and filter.
     * @return Environment The created environment.
     */
    Environment create(base::Name& policyName, const uint32_t filterId)
    {
        auto controller = getController(policyName);

        json::Json value {std::to_string(filterId).c_str()};

        const auto name {fmt::format("condition.value[{}=={}]", JSON_PATH_SESSION_FILTER, value.str())};
        const auto successTrace {fmt::format("[{}] -> Success", name)};
        const auto failureTrace {fmt::format("[{}] -> Failure", name)};

        auto expression = base::Term<base::EngineOp>::create(name,
                                    [=](base::Event event)
                                    {
                                        if (event->equals(JSON_PATH_SESSION_FILTER, value))
                                        {
                                            return base::result::makeSuccess(std::move(event), successTrace);
                                        }
                                        else
                                        {
                                            return base::result::makeFailure(std::move(event), failureTrace);
                                        }
                                    });

        return Environment (std::move(expression), std::move(controller));
    }
};

}

#endif //_ROUTER2_BUILD_ENVIRONMENT_HPP
