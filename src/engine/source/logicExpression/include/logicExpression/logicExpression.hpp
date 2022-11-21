#ifndef _LOGIC_EXPRESSION_H
#define _LOGIC_EXPRESSION_H

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

#include <fmt/format.h>

#include "logicExpressionEvaluator.hpp"
#include "logicExpressionParser.hpp"

namespace logicExpression
{

/**
 * @brief Generate evaluation function from a string logic expression.
 * This function parses the string and generates a token tree, then uses the
 * provided builder to generate the expression tree with all term's functions.
 * Finally generates the function from built expression tree.
 *
 * @tparam Event Type of the event to be evaluated.
 * @param expression String logic expression.
 * @param termBuilder Builder to generate the term's evaluation function from
 * its description.
 * @return std::function<bool(Event)> Evaluation function.
 */
template<typename Event>
std::function<bool(Event)> buildDijstraEvaluator(
    const std::string& expression,
    std::function<std::function<bool(Event)>(const std::string&)> termBuilder)
{
    // visitor to generate an evaluator::Expression tree from a
    // parser::Expression tree and a term builder function.
    auto visit =
        [termBuilder](const std::shared_ptr<const parser::Expression>& tokenExpr,
                      auto& visit_ref) -> std::shared_ptr<evaluator::Expression<Event>>
    {
        auto builtExpr = evaluator::Expression<Event>::create();
        switch (tokenExpr->m_token.m_type)
        {
            case parser::TokenType::TERM:
                builtExpr->m_type = evaluator::ExpressionType::TERM;
                builtExpr->m_function = termBuilder(tokenExpr->m_token.m_text);
                return builtExpr;
            case parser::TokenType::OPERATOR_NOT:
                builtExpr->m_type = evaluator::ExpressionType::NOT;
                builtExpr->m_left = visit_ref(tokenExpr->m_left, visit_ref);
                return builtExpr;
            case parser::TokenType::OPERATOR_OR:
                builtExpr->m_type = evaluator::ExpressionType::OR;
                builtExpr->m_left = visit_ref(tokenExpr->m_left, visit_ref);
                builtExpr->m_right = visit_ref(tokenExpr->m_right, visit_ref);
                return builtExpr;
            case parser::TokenType::OPERATOR_AND:
                builtExpr->m_type = evaluator::ExpressionType::AND;
                builtExpr->m_left = visit_ref(tokenExpr->m_left, visit_ref);
                builtExpr->m_right = visit_ref(tokenExpr->m_right, visit_ref);
                return builtExpr;
            default:
                throw std::runtime_error(
                    fmt::format("Engine logic expression: Unexpected token type of token "
                                "\"{}\" in parsed expression.",
                                tokenExpr->m_token.m_text));
        }
    };

    // Parse, build and return the evaluator function.
    auto tokenExpression = parser::parse(expression);
    auto builtExprPtr = visit(tokenExpression, visit);
    auto evaluatorFunction = evaluator::getDijstraEvaluator<Event>(builtExprPtr);

    return evaluatorFunction;
}

} // namespace logicExpression

#endif // _LOGIC_EXPRESSION_H
