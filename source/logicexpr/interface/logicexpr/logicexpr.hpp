#ifndef _LOGIC_EXPRESSION_H
#define _LOGIC_EXPRESSION_H

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

#include <fmt/format.h>

#include "evaluator.hpp"
#include "parser.hpp"

namespace logicexpr
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
 * @param termParser Parser to parse the term's of the expression.
 * @return std::function<bool(Event)> Evaluation function.
 */
template<typename Event, typename TermType, typename TermBuilder, typename TermParser>
std::function<bool(Event)>
buildDijstraEvaluator(const std::string& expression, TermBuilder&& termBuilder, TermParser&& termParser)
{

    // visitor to generate an evaluator::Expression tree from a
    // parser::Expression tree and a term builder function.
    auto visit = [termBuilder](const std::shared_ptr<const parser::Expression>& tokenExpr,
                               auto& visitRef) -> std::shared_ptr<evaluator::Expression<Event>>
    {
        auto builtExpr = evaluator::Expression<Event>::create();

        if (tokenExpr->m_token->isTerm())
        {
            auto termToken = tokenExpr->m_token->getPtr<parser::TermToken<TermType>>();
            builtExpr->m_type = evaluator::ExpressionType::TERM;
            builtExpr->m_function = termBuilder(termToken->buildToken());
            return builtExpr;
        }

        if (tokenExpr->m_token->isNot())
        {
            builtExpr->m_type = evaluator::ExpressionType::NOT;
            builtExpr->m_left = visitRef(tokenExpr->m_left, visitRef);
            return builtExpr;
        }

        if (tokenExpr->m_token->isOr())
        {
            builtExpr->m_type = evaluator::ExpressionType::OR;
            builtExpr->m_left = visitRef(tokenExpr->m_left, visitRef);
            builtExpr->m_right = visitRef(tokenExpr->m_right, visitRef);
            return builtExpr;
        }

        if (tokenExpr->m_token->isAnd())
        {
            builtExpr->m_type = evaluator::ExpressionType::AND;
            builtExpr->m_left = visitRef(tokenExpr->m_left, visitRef);
            builtExpr->m_right = visitRef(tokenExpr->m_right, visitRef);
            return builtExpr;
        }

        throw std::runtime_error(
            fmt::format("Engine logic expression: Unexpected token type of token '{}'", tokenExpr->m_token->text()));
    };

    // Parse, build and return the evaluator function.
    auto tokenExpression = parser::parse(expression, std::forward<TermParser>(termParser));
    auto builtExprPtr = visit(tokenExpression, visit);
    auto evaluatorFunction = evaluator::getDijstraEvaluator<Event>(builtExprPtr);

    return evaluatorFunction;
}

} // namespace logicexpr

#endif // _LOGIC_EXPRESSION_H
