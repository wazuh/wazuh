#include <logicExpressionParser.hpp>

#include "gtest/gtest.h"

using namespace logicExpression::parser;

TEST(LogicExpressionParser, TokenConstructs)
{
    // Empty
    ASSERT_NO_THROW(Token());
    Token tk;
    EXPECT_EQ(tk.m_type, TokenType::ERROR_TYPE);

    // Parenthesis open
    EXPECT_NO_THROW(tk = Token(TokenType::PARENTHESIS_OPEN, "(", 0));
    EXPECT_EQ(tk.m_type, TokenType::PARENTHESIS_OPEN);
    EXPECT_EQ(tk.m_text, "(");
    EXPECT_EQ(tk.m_position, 0);

    // Parenthesis close
    EXPECT_NO_THROW(tk = Token(TokenType::PARENTHESIS_CLOSE, ")", 0));
    EXPECT_EQ(tk.m_type, TokenType::PARENTHESIS_CLOSE);
    EXPECT_EQ(tk.m_text, ")");
    EXPECT_EQ(tk.m_position, 0);

    // Not operator
    EXPECT_NO_THROW(tk = Token(TokenType::OPERATOR_NOT, "NOT", 0));
    EXPECT_EQ(tk.m_type, TokenType::OPERATOR_NOT);
    EXPECT_EQ(tk.m_text, "NOT");
    EXPECT_EQ(tk.m_position, 0);

    // And operator
    EXPECT_NO_THROW(tk = Token(TokenType::OPERATOR_AND, "AND", 0));
    EXPECT_EQ(tk.m_type, TokenType::OPERATOR_AND);
    EXPECT_EQ(tk.m_text, "AND");
    EXPECT_EQ(tk.m_position, 0);

    // Or operator
    EXPECT_NO_THROW(tk = Token(TokenType::OPERATOR_OR, "OR", 0));
    EXPECT_EQ(tk.m_type, TokenType::OPERATOR_OR);
    EXPECT_EQ(tk.m_text, "OR");
    EXPECT_EQ(tk.m_position, 0);

    // Term
    EXPECT_NO_THROW(tk = Token(TokenType::TERM, "term", 0));
    EXPECT_EQ(tk.m_type, TokenType::TERM);
    EXPECT_EQ(tk.m_text, "term");
    EXPECT_EQ(tk.m_position, 0);
}

TEST(LogicExpressionParser, ParseToken)
{
    // Empty token string
    EXPECT_THROW(Token::parseToken("", 0), std::runtime_error);

    Token tk;

    // Parenthesis open
    EXPECT_NO_THROW(tk = Token::parseToken("(", 0));
    EXPECT_EQ(tk.m_type, TokenType::PARENTHESIS_OPEN);
    EXPECT_EQ(tk.m_text, "(");
    EXPECT_EQ(tk.m_position, 0);

    // Parenthesis close
    EXPECT_NO_THROW(tk = Token::parseToken(")", 0));
    EXPECT_EQ(tk.m_type, TokenType::PARENTHESIS_CLOSE);
    EXPECT_EQ(tk.m_text, ")");
    EXPECT_EQ(tk.m_position, 0);

    // Not operator
    EXPECT_NO_THROW(tk = Token::parseToken("NOT", 0));
    EXPECT_EQ(tk.m_type, TokenType::OPERATOR_NOT);
    EXPECT_EQ(tk.m_text, "NOT");
    EXPECT_EQ(tk.m_position, 0);

    // And operator
    EXPECT_NO_THROW(tk = Token::parseToken("AND", 0));
    EXPECT_EQ(tk.m_type, TokenType::OPERATOR_AND);
    EXPECT_EQ(tk.m_text, "AND");
    EXPECT_EQ(tk.m_position, 0);

    // Or operator
    EXPECT_NO_THROW(tk = Token::parseToken("OR", 0));
    EXPECT_EQ(tk.m_type, TokenType::OPERATOR_OR);
    EXPECT_EQ(tk.m_text, "OR");
    EXPECT_EQ(tk.m_position, 0);

    // Term
    EXPECT_NO_THROW(tk = Token::parseToken("term", 0));
    EXPECT_EQ(tk.m_type, TokenType::TERM);
    EXPECT_EQ(tk.m_text, "term");
    EXPECT_EQ(tk.m_position, 0);
}

TEST(LogicExpressionParser, TokenUtils)
{
    Token tk1;
    Token tk2;

    // is Operator
    tk1 = Token(TokenType::PARENTHESIS_OPEN, "(", 0);
    EXPECT_FALSE(tk1.isOperator());
    tk1 = Token(TokenType::PARENTHESIS_CLOSE, ")", 0);
    EXPECT_FALSE(tk1.isOperator());
    tk1 = Token(TokenType::TERM, "term", 0);
    EXPECT_FALSE(tk1.isOperator());
    tk1 = Token(TokenType::ERROR_TYPE, "", 0);
    EXPECT_FALSE(tk1.isOperator());
    tk1 = Token(TokenType::OPERATOR_NOT, "NOT", 0);
    EXPECT_TRUE(tk1.isOperator());
    tk1 = Token(TokenType::OPERATOR_AND, "AND", 0);
    EXPECT_TRUE(tk1.isOperator());
    tk1 = Token(TokenType::OPERATOR_OR, "OR", 0);
    EXPECT_TRUE(tk1.isOperator());

    // is unary operator
    tk1 = Token(TokenType::PARENTHESIS_OPEN, "(", 0);
    EXPECT_FALSE(tk1.isUnaryOperator());
    tk1 = Token(TokenType::PARENTHESIS_CLOSE, ")", 0);
    EXPECT_FALSE(tk1.isUnaryOperator());
    tk1 = Token(TokenType::TERM, "term", 0);
    EXPECT_FALSE(tk1.isUnaryOperator());
    tk1 = Token(TokenType::ERROR_TYPE, "", 0);
    EXPECT_FALSE(tk1.isUnaryOperator());
    tk1 = Token(TokenType::OPERATOR_NOT, "NOT", 0);
    EXPECT_TRUE(tk1.isUnaryOperator());
    tk1 = Token(TokenType::OPERATOR_AND, "AND", 0);
    EXPECT_FALSE(tk1.isUnaryOperator());
    tk1 = Token(TokenType::OPERATOR_OR, "OR", 0);
    EXPECT_FALSE(tk1.isUnaryOperator());

    // is binary operator
    tk1 = Token(TokenType::PARENTHESIS_OPEN, "(", 0);
    EXPECT_FALSE(tk1.isBinaryOperator());
    tk1 = Token(TokenType::PARENTHESIS_CLOSE, ")", 0);
    EXPECT_FALSE(tk1.isBinaryOperator());
    tk1 = Token(TokenType::TERM, "term", 0);
    EXPECT_FALSE(tk1.isBinaryOperator());
    tk1 = Token(TokenType::ERROR_TYPE, "", 0);
    EXPECT_FALSE(tk1.isBinaryOperator());
    tk1 = Token(TokenType::OPERATOR_NOT, "NOT", 0);
    EXPECT_FALSE(tk1.isBinaryOperator());
    tk1 = Token(TokenType::OPERATOR_AND, "AND", 0);
    EXPECT_TRUE(tk1.isBinaryOperator());
    tk1 = Token(TokenType::OPERATOR_OR, "OR", 0);
    EXPECT_TRUE(tk1.isBinaryOperator());

    // precedence comparisons

    // Two not operator tokens
    tk1 = Token(TokenType::PARENTHESIS_OPEN, "(", 0);
    tk2 = Token(TokenType::PARENTHESIS_CLOSE, ")", 0);
    EXPECT_THROW(tk1 >= tk2, std::logic_error);
    EXPECT_THROW(tk2 >= tk1, std::logic_error);

    // One token operator and one not operator
    tk1 = Token(TokenType::PARENTHESIS_OPEN, "(", 0);
    tk2 = Token(TokenType::OPERATOR_NOT, "NOT", 0);
    EXPECT_THROW(tk1 >= tk2, std::logic_error);
    EXPECT_THROW(tk2 >= tk1, std::logic_error);

    // Operators
    EXPECT_TRUE(Token(TokenType::OPERATOR_NOT, "NOT", 0) >=
                Token(TokenType::OPERATOR_AND, "AND", 0));
    EXPECT_TRUE(Token(TokenType::OPERATOR_AND, "AND", 0) >=
                Token(TokenType::OPERATOR_OR, "OR", 0));
}

TEST(LogicExpressionParser, ExpressionConstructs)
{
    // Empty expression
    EXPECT_NO_THROW(Expression::create());

    auto expr = Expression::create();

    // From Token stack
    std::stack<Token> tokens;

    // Error token
    tokens.push(Token(TokenType::ERROR_TYPE, "", 0));
    EXPECT_THROW(Expression::create(tokens), std::logic_error);
    tokens.pop();

    // Parenthesis
    tokens.push(Token(TokenType::PARENTHESIS_OPEN, "(", 0));
    EXPECT_THROW(Expression::create(tokens), std::logic_error);
    tokens.pop();
    tokens.push(Token(TokenType::PARENTHESIS_CLOSE, ")", 0));
    EXPECT_THROW(Expression::create(tokens), std::logic_error);
    tokens.pop();

    // Term
    tokens.push(Token(TokenType::TERM, "term", 0));
    EXPECT_NO_THROW(expr = Expression::create(tokens));

    // Simple expression
    tokens.push(Token(TokenType::TERM, "term", 0));
    tokens.push(Token(TokenType::TERM, "term", 0));
    tokens.push(Token(TokenType::OPERATOR_AND, "AND", 0));
    EXPECT_NO_THROW(expr = Expression::create(tokens));

    // Unbalanced expression
    tokens.push(Token(TokenType::TERM, "term", 0));
    tokens.push(Token(TokenType::OPERATOR_AND, "AND", 0));
    EXPECT_THROW(Expression::create(tokens), std::logic_error);
}

TEST(LogicExpressionParser, ExpressionUtils)
{
    auto expr1 = Expression::create();
    auto expr2 = Expression::create();

    // Different ptrs
    EXPECT_FALSE(expr1 == expr2);

    EXPECT_NO_THROW(expr2 = expr1->getPtr());
    EXPECT_TRUE(expr1 == expr2);

    // Visitor Pre-Order
    int i = 0;
    auto visitor = [&i](const Expression &expr)
    {
        EXPECT_EQ(expr.m_token.m_position, i);
        ++i;
    };

    std::stack<Token> tokens;
    tokens.push(Token(TokenType::TERM, "term", 2));
    tokens.push(Token(TokenType::TERM, "term", 1));
    tokens.push(Token(TokenType::OPERATOR_AND, "AND", 0));
    auto root = Expression::create(tokens);
    EXPECT_NO_THROW(Expression::visitPreOrder(root, visitor));

    // To dot
    std::string dot;
    EXPECT_NO_THROW(dot = Expression::toDotString(root));
    std::string expected = R"(digraph G {
AND_00;
AND_00 -> term_10;
term_10;
AND_00 -> term_11;
term_11;
}
)";
    EXPECT_EQ(dot, expected);
}

TEST(LogicExpressionParser, ParseErrors)
{
    const std::vector<std::string> expressions = {
        R"(event.type=="test" AND (something)unexpectedTerm)",
        R"(event.type=="test" AND OR (something))",
        R"(AND term)",
        R"(term OR)",
        R"(term AND (notClosedParenthesis)",
        R"(term AND notOpenedParenthesis))",
        R"(NOT)",
        R"(AND)",
        R"(term NOT AND term),
        R"(())",
        R"()",
    };

    for (auto &expression : expressions)
    {
        EXPECT_THROW(parse(expression), std::runtime_error);
    }
}

TEST(LogicExpressionParser, Parse)
{
    const std::vector<std::string> expressions = {
        R"(onlyOneTerm)",
        R"(term AND term)",
        R"(term OR term)",
        R"(term AND (term OR term))",
        R"(term OR (term AND term))",
        R"(NOT term)",
        R"(NOT (term AND term))",
        R"(NOT (term OR term))",
        R"(NOT (term AND (term OR term)))",
        R"(term AND term OR term)",
        R"(term OR NOT term AND term)",
    };

    const std::vector<std::string> expectedGraph = {
        R"(digraph G {
onlyOneTerm_00;
}
)",
        R"(digraph G {
AND_00;
AND_00 -> term_10;
term_10;
AND_00 -> term_11;
term_11;
}
)",
        R"(digraph G {
OR_00;
OR_00 -> term_10;
term_10;
OR_00 -> term_11;
term_11;
}
)",
        R"(digraph G {
AND_00;
AND_00 -> OR_10;
OR_10;
OR_10 -> term_20;
term_20;
OR_10 -> term_21;
term_21;
AND_00 -> term_11;
term_11;
}
)",
        R"(digraph G {
OR_00;
OR_00 -> AND_10;
AND_10;
AND_10 -> term_20;
term_20;
AND_10 -> term_21;
term_21;
OR_00 -> term_11;
term_11;
}
)",
        R"(digraph G {
NOT_00;
NOT_00 -> term_10;
term_10;
}
)",
        R"(digraph G {
NOT_00;
NOT_00 -> AND_10;
AND_10;
AND_10 -> term_20;
term_20;
AND_10 -> term_21;
term_21;
}
)",
        R"(digraph G {
NOT_00;
NOT_00 -> OR_10;
OR_10;
OR_10 -> term_20;
term_20;
OR_10 -> term_21;
term_21;
}
)",
        R"(digraph G {
NOT_00;
NOT_00 -> AND_10;
AND_10;
AND_10 -> OR_20;
OR_20;
OR_20 -> term_30;
term_30;
OR_20 -> term_31;
term_31;
AND_10 -> term_21;
term_21;
}
)",
        R"(digraph G {
OR_00;
OR_00 -> term_10;
term_10;
OR_00 -> AND_11;
AND_11;
AND_11 -> term_20;
term_20;
AND_11 -> term_21;
term_21;
}
)",
        R"(digraph G {
OR_00;
OR_00 -> AND_10;
AND_10;
AND_10 -> term_20;
term_20;
AND_10 -> NOT_21;
NOT_21;
NOT_21 -> term_30;
term_30;
OR_00 -> term_11;
term_11;
}
)",
    };

    for (auto i = 0; i < expressions.size(); ++i)
    {
        auto exp = Expression::create();
        EXPECT_NO_THROW(exp = parse(expressions[i]));
        EXPECT_EQ(Expression::toDotString(exp),
                  expectedGraph[i]);
    }
}
