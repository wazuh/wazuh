#include "route.hpp"

namespace builder
{

namespace {
    constexpr auto PATH_TARGET = "target";
    constexpr auto PATH_PRIORITY = "priority";
    constexpr int MAX_PRIORITY = 255L;
    constexpr int MIN_PRIORITY = 0L;
}

Route::Route(json::Json jsonDefinition, std::shared_ptr<builder::internals::Registry> registry)
{
    // Get the target
    auto targetPath = json::Json::formatJsonPath(PATH_TARGET);
    if (auto target = jsonDefinition.getString(targetPath))
    {
        m_target = target.value();
    }
    else
    {
        throw std::runtime_error("Route has no target or target is not a string.");
    }

    if (m_target.empty())
    {
        throw std::runtime_error(fmt::format("Route '{}' has an empty target.", m_name));
    }
    jsonDefinition.erase(targetPath);

    // Get the priority
    auto priorityPath = json::Json::formatJsonPath(PATH_PRIORITY);
    if (auto priority = jsonDefinition.getInt(priorityPath))
    {
        setPriority(priority.value());
    }
    else
    {
        throw std::runtime_error(R"(Route has no "priority" or "priority" is not an integer.)");
    }
    jsonDefinition.erase(priorityPath);

    // Get the expression
    auto assetRoute = std::make_shared<builder::Asset>(jsonDefinition, builder::Asset::Type::ROUTE, registry);
    m_expr = assetRoute->getExpression();

    // Get the name
    m_name = assetRoute->m_name;
}

void Route::setPriority(int priority)
{
    if (priority < MIN_PRIORITY || priority > MAX_PRIORITY)
    {
        throw std::runtime_error(
            fmt::format("Route '{}' has an invalid priority. Priority must be between {} and {}.",
                        m_name,
                        MIN_PRIORITY,
                        MAX_PRIORITY));
    }
    m_priority = priority;
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

} // namespace builder
