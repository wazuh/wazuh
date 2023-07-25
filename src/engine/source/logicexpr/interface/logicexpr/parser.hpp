#ifndef _LOGICEXPR_PARSER_H
#define _LOGICEXPR_PARSER_H

#include <functional>
#include <memory>
#include <sstream>
#include <stack>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>
#include <utils/stringUtils.hpp>

#include "tokenizer.hpp"

/**
 * @brief Namespace containing parsing logic expressions functionality
 */
namespace logicexpr::parser
{

namespace
{
// Helper to ensure correct syntax of expression in infix notation
// Inspired by
// https://stackoverflow.com/questions/29634992/shunting-yard-validate-expression
struct syntaxChecker
{
    // Could be optimized by taking advantage of the fact that shunting-yard
    // algorithm is already doing some comparisons, is as it is for modularity

    // Two states:
    // - 0: expect operand, unary operator or parenthesis
    // - 1: expect binary operator
    bool m_state;

    bool expectedOperand() const { return m_state == false; }

    void expectOperand() { m_state = false; }

    bool expectedOperator() const { return m_state == true; }

    void expectOperator() { m_state = true; }

    syntaxChecker()
        : m_state {false}
    {
    }

    // Check if token satisfies the current state, otherwise throw exception
    void operator()(const Token& token)
    {
        // Got term
        if (Token::Type::TERM == token.m_type)
        {
            if (expectedOperator())
            {
                throw std::runtime_error(
                    fmt::format("Unexpected token TERM \"{}\" at position \"{}\"", token.m_text, token.m_pos));
            }

            expectOperator();
            return;
        }

        // Got unary operator
        if (token.isUnaryOperator())
        {
            if (expectedOperator())
            {
                throw std::runtime_error(
                    fmt::format("Unexpected unary operator \"NOT\" at position \"{}\"", token.m_pos));
            }

            // Still wanting operand
            return;
        }

        // Got binary operator
        if (token.isBinaryOperator())
        {
            if (expectedOperand())
            {
                throw std::runtime_error(
                    fmt::format("Unexpected binary operator \"{}\" at position \"{}\"", token.m_text, token.m_pos));
            }

            expectOperand();
            return;
        }

        // Got parenthesis open
        if (Token::Type::PARENTHESIS_OPEN == token.m_type)
        {
            if (expectedOperator())
            {
                throw std::runtime_error(fmt::format("Unexpected parenthesis \"(\" at position \"{}\"", token.m_pos));
            }

            // Still wanting operand
            return;
        }

        // Got parenthesis close
        if (Token::Type::PARENTHESIS_CLOSE == token.m_type)
        {
            if (expectedOperand())
            {
                throw std::runtime_error(fmt::format("Unexpected parenthesis \")\" at position \"{}\"", token.m_pos));
            }

            // Still wanting operator
            return;
        }
    }
};

// Transform a queue of tokens in infix notation into a stack of tokens in
// postfix notation using Shunting-Yard algorithm.
std::stack<Token> infixToPostfix(std::queue<Token>& infix)
{
    std::stack<Token> postfix;
    std::stack<Token> operatorStack;

    syntaxChecker checker;
    while (!infix.empty())
    {
        auto token = std::move(infix.front());
        infix.pop();
        checker(token);

        if (Token::Type::TERM == token.m_type)
        {
            postfix.push(std::move(token));
        }
        else if (Token::Type::PARENTHESIS_OPEN == token.m_type)
        {
            operatorStack.push(std::move(token));
        }
        else if (Token::Type::PARENTHESIS_CLOSE == token.m_type)
        {
            while (!operatorStack.empty() && operatorStack.top().m_type != Token::Type::PARENTHESIS_OPEN)
            {
                postfix.push(std::move(operatorStack.top()));
                operatorStack.pop();
            }
            if (operatorStack.empty())
            {
                throw std::runtime_error("Parenthesis are not balanced");
            }
            operatorStack.pop();
        }
        else
        {
            while (!operatorStack.empty() && operatorStack.top().m_type != Token::Type::PARENTHESIS_OPEN
                   && operatorStack.top() >= token)
            {
                postfix.push(std::move(operatorStack.top()));
                operatorStack.pop();
            }

            operatorStack.push(std::move(token));
        }
    }

    while (!operatorStack.empty())
    {
        if (operatorStack.top().m_type == Token::Type::PARENTHESIS_OPEN)
        {
            throw std::runtime_error("Parenthesis are not balanced");
        }
        postfix.push(std::move(operatorStack.top()));
        operatorStack.pop();
    }

    return postfix;
}

} // namespace

/**
 * @brief Represents an expression node, where the whole expression is a binary
 * tree linked by m_left and m_right.
 *
 */
class Expression : public std::enable_shared_from_this<Expression>
{
public:
    // Token of this node
    Token m_token;
    // Childs if any
    std::shared_ptr<Expression> m_left, m_right;

    /**
     * @brief Get the Ptr object
     *
     * @return std::shared_ptr<Expression>
     */
    std::shared_ptr<Expression> getPtr() { return shared_from_this(); }

    /**
     * @brief Get the const Ptr object
     *
     * @return std::shared_ptr<const Expression>
     */
    std::shared_ptr<const Expression> getPtr() const { return shared_from_this(); }

    /**
     * @brief Create a new Expression object from a postfix token stack
     *
     * @param postfix stack with all tokens if postfix notation
     * @return std::shared_ptr<Expression> root of the expression tree
     * @throw std::logic_error if the stack is empty or contains an unbalanced
     * expression
     */
    [[nodiscard]] static std::shared_ptr<Expression> create(std::stack<Token>& postfix)
    {
        return std::shared_ptr<Expression>(new Expression(postfix));
    }

    /**
     * @brief Creates empty expression
     *
     * @return std::shared_ptr<Expression>
     */
    [[nodiscard]] static std::shared_ptr<Expression> create() { return std::shared_ptr<Expression>(new Expression()); }

    /**
     * @brief Visit Expression tree in pre-order
     *
     * @param expr Expression root of the tree to be visited
     * @param visitor visitor function
     */
    static void visitPreOrder(const std::shared_ptr<const Expression>& expr,
                              std::function<void(const Expression&)> visitor)
    {
        if (expr)
        {
            visitor(*expr);
            if (expr->m_left)
            {
                visitPreOrder(expr->m_left, visitor);
            }
            if (expr->m_right)
            {
                visitPreOrder(expr->m_right, visitor);
            }
        }
    }

    /**
     * @brief Obtains the graphviz representation string of the expression tree
     *
     * @param root root of the expression tree
     * @return std::string
     */
    static std::string toDotString(const std::shared_ptr<const Expression>& root)
    {
        // Not using visitPreOrder because we need to handle repeated names and
        // we need to now if current node is left or right child
        std::stringstream ss;
        ss << "digraph G {" << std::endl;

        auto visit = [&ss](const std::shared_ptr<const Expression>& root, int depth, int width, auto& visit_ref) -> void
        {
            ss << fmt::format("{}_{}{};", root->m_token.m_text, depth, width) << std::endl;
            if (root->m_left)
            {
                ss << fmt::format("{}_{}{} -> {}_{}{};",
                                  root->m_token.m_text,
                                  depth,
                                  width,
                                  root->m_left->m_token.m_text,
                                  depth + 1,
                                  0)
                   << std::endl;

                visit_ref(root->m_left, depth + 1, 0, visit_ref);
            }
            if (root->m_right)
            {
                ss << fmt::format("{}_{}{} -> {}_{}{};",
                                  root->m_token.m_text,
                                  depth,
                                  width,
                                  root->m_right->m_token.m_text,
                                  depth + 1,
                                  1)
                   << std::endl;

                visit_ref(root->m_right, depth + 1, 1, visit_ref);
            }
        };

        visit(root, 0, 0, visit);
        ss << "}" << std::endl;
        return ss.str();
    }

private:
    // Made private so that only create() can be used to create an Expression
    Expression(std::stack<Token>& postfix)

    {
        if (postfix.empty())
        {
            throw std::logic_error("Engine logic expression parser: Got unbalanced expression.");
        }
        if (postfix.top().m_type == Token::Type::ERROR_TYPE)
        {
            throw std::logic_error("Engine logic expression parser: Got invalid token with \"ERROR_TYPE\".");
        }
        if (postfix.top().m_type == Token::Type::PARENTHESIS_OPEN
            || postfix.top().m_type == Token::Type::PARENTHESIS_CLOSE)
        {
            throw std::logic_error("Engine logic expression parser: Got invalid token "
                                   "with \"PARENTHESIS_OPEN\" or \"PARENTHESIS_CLOSE\".");
        }

        m_token = std::move(postfix.top());
        postfix.pop();

        if (m_token.isUnaryOperator())
        {
            m_left = Expression::create(postfix);
        }
        else if (m_token.isBinaryOperator())
        {
            m_left = Expression::create(postfix);
            m_right = Expression::create(postfix);
        }
    }

    // Made private so that only create() can be used to create an Expression
    Expression() = default;
};

/**
 * @brief Creates and returns a new Expression binary tree from a raw string
 *
 * @param rawExpression raw string expression in infix notation
 * @return std::shared_ptr<Expression> root of the expression tree
 *
 * @throw std::logic_exception if the expression is not valid
 */
template<typename TermParser>
std::shared_ptr<Expression> parse(const std::string& rawExpression, TermParser&& termParser)
{
    auto expression = Expression::create();
    Tokenizer tokenizer(std::forward<TermParser>(termParser));
    try
    {
        auto tokens = tokenizer(rawExpression);
        auto postfix = infixToPostfix(tokens);
        expression = Expression::create(postfix);
    }
    catch (...)
    {
        throw std::runtime_error(fmt::format("Failed to parse expression \"{}\"", rawExpression));
    }

    return expression;
}

} // namespace logicexpr::parser

#endif // _LOGICEXPR_PARSER_H
