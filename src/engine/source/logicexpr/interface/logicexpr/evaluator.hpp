#ifndef _LOGICEXPR_EVALUATOR_H
#define _LOGICEXPR_EVALUATOR_H

#include <functional>
#include <memory>
#include <stack>
#include <stdexcept>
#include <vector>

#include <fmt/format.h>

/**
 * @brief Functionality for evaluating logic expressions.
 *
 */
namespace logicexpr::evaluator
{

/**
 * @brief Expression type
 *
 */
enum class ExpressionType
{
    TERM,
    OR,
    AND,
    NOT
};

/**
 * @brief Class to represent a logic expression tree, where terms have the
 * evaluation function.
 *
 * @tparam Event
 */
template<typename Event>
class Expression : public std::enable_shared_from_this<Expression<Event>>
{
public:
    using ThisType = Expression<Event>;
    using FunctionType = std::function<bool(Event)>;

    ExpressionType m_type;
    FunctionType m_function;
    std::shared_ptr<ThisType> m_left, m_right;

    /**
     * @brief Get the Ptr object
     *
     * @return std::shared_ptr<ThisType>
     */
    std::shared_ptr<ThisType> getPtr() { return ThisType::shared_from_this(); }

    /**
     * @brief Get the Ptr const object
     *
     * @return std::shared_ptr<const ThisType>
     */
    std::shared_ptr<const ThisType> getPtr() const { return ThisType::shared_from_this(); }

    /**
     * @brief Create empty expression
     *
     * @return std::shared_ptr<ThisType>
     */
    [[nodiscard]] static std::shared_ptr<ThisType> create() { return std::shared_ptr<ThisType>(new ThisType()); }

    /**
     * @brief Create term expression
     *
     * @param function Function that evaluates the term
     * @return std::shared_ptr<ThisType>
     */
    [[nodiscard]] static std::shared_ptr<ThisType> create(FunctionType&& function)
    {
        return std::shared_ptr<ThisType>(new ThisType(std::forward<FunctionType>(function)));
    }

    /**
     * @brief Create operator expression
     *
     * @param type Operator type
     * @return std::shared_ptr<ThisType>
     * @throws std::runtime_error if type is TERM
     */
    [[nodiscard]] static std::shared_ptr<ThisType> create(ExpressionType&& type)
    {
        return std::shared_ptr<ThisType>(new ThisType(std::forward<ExpressionType>(type)));
    }

    /**
     * @brief Visit pre-order
     *
     * @param expression root expression
     * @param visitor
     */
    static void visitPreOrder(const std::shared_ptr<const ThisType>& expression,
                              std::function<void(const ThisType&)> visitor)
    {
        if (expression)
        {
            visitor(*expression);
            visitPreOrder(expression->m_left, visitor);
            visitPreOrder(expression->m_right, visitor);
        }
    }

private:
    Expression() = default;
    Expression(FunctionType function)
        : m_type(ExpressionType::TERM)
        , m_function(function)
    {
    }
    Expression(ExpressionType type)
    {
        if (ExpressionType::TERM == type)
        {
            throw std::runtime_error(
                "Error creating expression with TERM type, use constructor with function type instead.");
        }

        m_type = type;
    }
};

/**
 * @brief Get the Dijstra Evaluator function from a logic expression tree
 *
 * @tparam Event
 * @param expression root expression
 * @return Expression<Event>::FunctionType
 */
template<typename Event>
typename Expression<Event>::FunctionType getDijstraEvaluator(const std::shared_ptr<const Expression<Event>>& expression)
{
    // Struct for operators stack
    struct Operator
    {
        ExpressionType m_type;
        typename Expression<Event>::FunctionType m_function;
    };

    // Operators stack, while semantically it is a stack of operators a vector
    // is used to iterate and avoid moving data
    std::vector<Operator> operators;

    // Visitor to poputale operators stack
    auto visitor = [&operators](const Expression<Event>& expression)
    {
        if (expression.m_type == ExpressionType::TERM)
        {
            operators.push_back({expression.m_type, expression.m_function});
        }
        else
        {
            operators.push_back({expression.m_type, nullptr});
        }
    };

    Expression<Event>::visitPreOrder(expression, visitor);

    // Evaluator function
    return [operators](Event event) -> bool
    {
        std::stack<bool> operands;
        bool result {false};

        for (auto it = operators.crbegin(); it != operators.crend(); ++it)
        {
            switch (it->m_type)
            {
                case ExpressionType::TERM:
                    // Handle only term expression
                    // TODO: dont allow expressions with one term only, use check list
                    // instead
                    if (operators.size() == 1)
                    {
                        result = it->m_function(event);
                    }
                    else
                    {
                        operands.push(it->m_function(event));
                    }
                    break;
                case ExpressionType::NOT:
                    result = !operands.top();
                    operands.pop();
                    operands.push(result);
                    break;
                case ExpressionType::AND:
                    result = operands.top();
                    operands.pop();
                    result = result && operands.top();
                    operands.pop();
                    operands.push(result);
                    break;
                case ExpressionType::OR:
                    result = operands.top();
                    operands.pop();
                    result = result || operands.top();
                    operands.pop();
                    operands.push(result);
                    break;
                default: throw std::runtime_error("Engine logic expression evaluator got unknown operator type.");
            }
        }

        return result;
    };
}

} // namespace logicexpr::evaluator

#endif // _LOGICEXPR_EVALUATOR_H
