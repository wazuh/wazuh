#include <router/route.hpp>

namespace router
{

Route::Route(const std::string& name, builder::Asset assetRoute, const std::string& target, int priority)
    : m_name {name}
    , m_filter {assetRoute.getExpression()}
    , m_filterName {assetRoute.m_name}
    , m_target {target}
{
    // TODO Add a check for the name of the route (it should be alfanumeric) when the asset also has a check name
    setPriority(priority);
}

void Route::setPriority(int priority)
{
    if (priority < ROUTE_MAXIMUM_PRIORITY || priority > ROUTE_MINIMUM_PRIORITY)
    {
        throw std::runtime_error(fmt::format("Route '{}' has an invalid priority. Priority must be between {} and {}",
                                             m_filterName,
                                             ROUTE_MAXIMUM_PRIORITY,
                                             ROUTE_MINIMUM_PRIORITY));
    }
    m_priority = static_cast<std::size_t>(priority);
}

bool Route::executeExpression(base::Expression expression, base::Event event) const
{
    // TODO: This is a temporary solution. It should be in the expression itself (Filters should be able to be executed
    // without the check stage)
    if (expression == nullptr)
    {
        return true;
    }

    if (expression->isTerm())
    {
        auto term = expression->getPtr<base::Term<base::EngineOp>>();
        auto result = term->getFn()(event);
        return result.success();
    }
    else if (expression->isOperation())
    {

        if (expression->isAnd())
        {
            auto op = expression->getPtr<base::And>();
            for (auto& operand : op->getOperands())
            {
                if (!executeExpression(operand, event))
                {
                    return false;
                }
            }
            return true;
        }
        else if (expression->isOr())
        {
            auto op = expression->getPtr<base::Or>();
            for (auto& operand : op->getOperands())
            {
                if (executeExpression(operand, event))
                {
                    return true;
                }
            }
            return false;
        }
        else if (expression->isImplication())
        {
            auto op = expression->getPtr<base::Implication>();
            if (executeExpression(op->getOperands()[0], event))
            {
                executeExpression(op->getOperands()[1], event);
                return true;
            }
            return false;
        }
        else if (expression->isBroadcast() || expression->isChain())
        {
            auto op = expression->getPtr<base::Broadcast>();
            for (auto& operand : op->getOperands())
            {
                executeExpression(operand, event);
            }
            return true;
        }
        else
        {
            throw std::runtime_error("Unsupported operation type");
        }
    }
    else
    {
        throw std::runtime_error("Unsupported expression type");
    }
}

} // namespace router
