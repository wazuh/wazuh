#include <router/route.hpp>

namespace router
{

namespace
{

constexpr int MAX_PRIORITY = 255L;
constexpr int MIN_PRIORITY = 0L;

} // namespace

Route::Route(builder::Asset assetRoute, const std::string& target, int priority)
    : m_filter {assetRoute.getExpression()}
    , m_name {assetRoute.m_name}
    , m_target {target}
{
    setPriority(priority);
}

void Route::setPriority(int priority)
{
    if (priority < MIN_PRIORITY || priority > MAX_PRIORITY)
    {
        throw std::runtime_error(fmt::format("Route '{}' has an invalid priority. Priority must be between {} and {}.",
                                             m_name,
                                             MIN_PRIORITY,
                                             MAX_PRIORITY));
    }
    m_priority = static_cast<std::size_t>(priority);
}

bool Route::executeExpression(base::Expression expression, base::Event event) const
{
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
