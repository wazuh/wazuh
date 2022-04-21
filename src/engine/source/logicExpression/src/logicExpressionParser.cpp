#include "logicExpressionParser.hpp"

#include <memory>
#include <queue>
#include <stack>
#include <string>
#include <vector>

#include <utils/stringUtils.hpp>

// Only the parse function and related structs needs to be exposed, rest of the code is made private here
namespace
{
// Simple tokenizer using blank space and parenthesis as delimiter.
// Blank spaces are discarded.
std::queue<logicExpression::Token> tokenize(const std::string &rawExpression)
{
    std::vector<std::string> rawTokens =
        utils::string::split(rawExpression,
                             utils::string::Delimeter(' ', false),
                             utils::string::Delimeter('(', true),
                             utils::string::Delimeter(')', true));

    std::queue<logicExpression::Token> tokens;
    size_t i = 0;
    for (const auto &rawToken : rawTokens)
    {
        tokens.push(logicExpression::Token::parseToken(rawToken, i));
        i += rawToken.size();
    }

    return tokens;
}

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

    bool expectedOperand() const
    {
        return m_state == false;
    }

    void expectOperand()
    {
        m_state = false;
    }

    bool expectedOperator() const
    {
        return m_state == true;
    }

    void expectOperator()
    {
        m_state = true;
    }

    syntaxChecker()
        : m_state {false}
    {
    }

    // Check if token satisfies the current state, otherwise throw exception
    void operator()(const logicExpression::Token &token)
    {
        // Got term
        if (token.m_type == logicExpression::TokenType::TERM)
        {
            if (expectedOperator())
            {
                throw std::runtime_error(
                    fmt::format("Unexpected term [{}] at pos [{}]",
                                token.m_text,
                                token.m_position));
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
                    fmt::format("Unexpected unary operator [NOT] at pos [{}]",
                                token.m_position));
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
                    fmt::format("Unexpected binary operator [{}] at pos [{}]",
                                token.m_text,
                                token.m_position));
            }

            expectOperand();
            return;
        }

        // Got parenthesis open
        if (token.m_type == logicExpression::TokenType::PARENTHESIS_OPEN)
        {
            if (expectedOperator())
            {
                throw std::runtime_error(
                    fmt::format("Unexpected parenthesis [(] at pos [{}]",
                                token.m_position));
            }

            // Still wanting operand
            return;
        }

        // Got parenthesis close
        if (token.m_type == logicExpression::TokenType::PARENTHESIS_CLOSE)
        {
            if (expectedOperand())
            {
                throw std::runtime_error(
                    fmt::format("Unexpected parenthesis [)] at pos [{}]",
                                token.m_position));
            }

            // Still wanting operator
            return;
        }
    }
};

// Transform a queue of tokens in infix notation into a stack of tokens in
// postfix notation using Shunting-Yard algorithm.
std::stack<logicExpression::Token>
infixToPostfix(std::queue<logicExpression::Token> &infix)
{
    std::stack<logicExpression::Token> postfix;
    std::stack<logicExpression::Token> operatorStack;

    syntaxChecker checker;
    while (!infix.empty())
    {
        auto token = std::move(infix.front());
        infix.pop();
        checker(token);

        if (token.m_type == logicExpression::TokenType::TERM)
        {
            postfix.push(std::move(token));
        }
        else if (token.m_type == logicExpression::TokenType::PARENTHESIS_OPEN)
        {
            operatorStack.push(std::move(token));
        }
        else if (token.m_type == logicExpression::TokenType::PARENTHESIS_CLOSE)
        {
            while (!operatorStack.empty() &&
                   operatorStack.top().m_type !=
                       logicExpression::TokenType::PARENTHESIS_OPEN)
            {
                postfix.push(std::move(operatorStack.top()));
                operatorStack.pop();
            }
            if (operatorStack.empty())
            {
                throw std::runtime_error("Mismatched parenthesis");
            }
            operatorStack.pop();
        }
        else
        {
            while (!operatorStack.empty() &&
                   operatorStack.top().m_type !=
                       logicExpression::TokenType::PARENTHESIS_OPEN &&
                   operatorStack.top() >= token)
            {
                postfix.push(std::move(operatorStack.top()));
                operatorStack.pop();
            }

            operatorStack.push(std::move(token));
        }
    }

    while (!operatorStack.empty())
    {
        if (operatorStack.top().m_type ==
            logicExpression::TokenType::PARENTHESIS_OPEN)
        {
            throw std::runtime_error("Mismatched parenthesis");
        }
        postfix.push(std::move(operatorStack.top()));
        operatorStack.pop();
    }

    return postfix;
}

} // namespace

namespace logicExpression
{

std::shared_ptr<Expression> parse(const std::string &rawExpression)
{
    auto expression = Expression::create();
    try
    {
        auto tokens = tokenize(rawExpression);
        auto postfix = infixToPostfix(tokens);
        expression = Expression::create(postfix);
    }
    catch (...)
    {
        std::throw_with_nested(std::runtime_error(
            fmt::format("Failed to parse expression [{}]", rawExpression)));
    }

    return expression;
}
} // namespace logicExpression
