#ifndef _BUILD_ENVIRONMENT_HPP
#define _BUILD_ENVIRONMENT_HPP

#include "ibuilder.hpp"
#include <bk/rx/controller.hpp>
#include "environment.hpp"

namespace router
{

constexpr auto JSON_PATH_SESSION_FILTER {"/TestSessionID"};

/**
 * @brief BuildEnvironment class for creating environments based on policies and filters.
 *
 */
class BuildEnvironment
{
private:
    /**
     * @brief Get the Controller object for a given policy.
     *
     * @param policyName The name of the policy.
     * @param builder The builder used to construct the policy.
     * @return std::shared_ptr<bk::IController> The constructed controller.
     */
    static std::shared_ptr<bk::IController> getController(base::Name& policyName, std::shared_ptr<IBuilder> builder)
    {
        // Build the policy and create the pipeline
        auto newPolicy = builder->buildPolicy(policyName);
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

        return std::make_shared<bk::rx::Controller>(policy->expression(), assetNames);
    }

    /**
     * @brief Get the Expression object for a given filter.
     *
     * @param filterName The name of the filter.
     * @param builder The builder used to construct the filter.
     * @return base::Expression The constructed filter expression.
     */
    static base::Expression getExpression(base::Name& filterName, std::shared_ptr<IBuilder> builder)
    {
        // TODO: Remove this check when the Builder can identify if it is a filter or not
        if (filterName.parts().size() == 0 || filterName.parts()[0] != "filter")
        {
            throw std::runtime_error {fmt::format("The asset name is empty or it is not a filter")};
        }

        auto filter = builder->buildAsset(filterName);
        if(base::isError(filter))
        {
            throw std::runtime_error {base::getError(filter).message};
        }

        return base::getResponse(filter);
    }

public:

    /**
     * @brief Create an environment based on a policy and a filter.
     *
     * @param policyName The name of the policy.
     * @param filterName The name of the filter.
     * @param builder The builder used to construct the policy and filter.
     * @return std::shared_ptr<Environment> The created environment.
     */
    static std::shared_ptr<Environment> create(base::Name& policyName, base::Name& filterName, std::shared_ptr<IBuilder> builder)
    {
        auto controller = getController(policyName, builder);
        auto expression = getExpression(filterName, builder);
        return std::make_shared<Environment>(std::move(expression), std::move(controller));
    }

    /**
     * @brief Create an environment based on a policy and a filter ID.
     *
     * @param policyName The name of the policy.
     * @param filterId The filter ID.
     * @param builder The builder used to construct the policy and filter.
     * @return std::shared_ptr<Environment> The created environment.
     */
    static std::shared_ptr<Environment> create(base::Name& policyName, const uint32_t filterId, std::shared_ptr<IBuilder> builder)
    {
        auto controller = getController(policyName, builder);

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

        return std::make_shared<Environment>(std::move(expression), std::move(controller));
    }
};

}

#endif //_BUILD_ENVIRONMENT_HPP
