#include "environment.hpp"

namespace
{
/**
 * @brief Evaluate an expression on an event
 *
 * @param event Event to execute the expression on
 * @param expression Expression to execute
 * @return true If the expression is successful
 *
 * @throw std::runtime_error If the expression is not supported (Should not happen)
 */
bool evalExpr(const base::Expression& expression, const base::Event& event)
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
                if (!evalExpr(operand, event))
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
                if (evalExpr(operand, event))
                {
                    return true;
                }
            }
            return false;
        }
        else if (expression->isImplication())
        {
            auto op = expression->getPtr<base::Implication>();
            if (evalExpr(op->getOperands()[0], event))
            {
                evalExpr(op->getOperands()[1], event);
                return true;
            }
            return false;
        }
        else if (expression->isBroadcast() || expression->isChain())
        {
            auto op = expression->getPtr<base::Broadcast>();
            for (auto& operand : op->getOperands())
            {
                evalExpr(operand, event);
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
} // namespace

namespace router
{

bool Environment::isAccepted(const base::Event& event) const
{
    return evalExpr(m_filter, event);
}

} // namespace router
