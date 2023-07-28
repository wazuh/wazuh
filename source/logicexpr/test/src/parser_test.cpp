#include <gtest/gtest.h>

#include <logicexpr/parser.hpp>

using namespace logicexpr::parser;

TEST(LogicExpressionParser, ExpressionConstructs)
{
    // Empty expression
    EXPECT_NO_THROW(auto exp = Expression::create());

    auto expr = Expression::create();

    // From Token stack
    std::stack<Token> tokens;

    // Parenthesis
    tokens.push(ParenthOpenToken::create("(", 0));
    EXPECT_THROW(auto t = Expression::create(tokens), std::logic_error);
    tokens.pop();
    tokens.push(ParenthCloseToken::create(")", 0));
    EXPECT_THROW(auto t = Expression::create(tokens), std::logic_error);
    tokens.pop();

    // Term
    tokens.push(TermToken<std::string>::create("term val", "term", 0));
    EXPECT_NO_THROW(expr = Expression::create(tokens));

    // Simple expression
    tokens.push(TermToken<std::string>::create("term val", "term", 0));
    tokens.push(TermToken<std::string>::create("term val", "term", 0));
    tokens.push(AndToken::create("AND", 0));
    EXPECT_NO_THROW(expr = Expression::create(tokens));

    // Unbalanced expression
    tokens.push(TermToken<std::string>::create("term val", "term", 0));
    tokens.push(AndToken::create("AND", 0));
    EXPECT_THROW(Expression::create(tokens), std::logic_error);
}

TEST(LogicExpressionParser, ExpressionUtils)
{
    auto expr1 = Expression::create();
    auto expr2 = Expression::create();

    // Different ptrs
    EXPECT_FALSE(expr1 == expr2);

    // Same ptrs
    EXPECT_NO_THROW(expr2 = expr1->getPtr());
    EXPECT_TRUE(expr1 == expr2);

    // Visitor Pre-Order
    int i = 0;
    auto visitor = [&i](const Expression& expr)
    {
        EXPECT_EQ(expr.m_token->pos(), i);
        ++i;
    };

    std::stack<Token> tokens;
    tokens.push(TermToken<std::string>::create("term val", "term", 2));
    tokens.push(TermToken<std::string>::create("term val", "term", 1));
    tokens.push(AndToken::create("AND", 0));
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

// Test of the parser
using ErrorParserTest = testing::TestWithParam<std::string>;

TEST_P(ErrorParserTest, badExpression)
{
    parsec::Parser<std::string> p = [](std::string_view text, size_t pos) -> parsec::Result<std::string>
    {
        auto index = pos;
        // Skip spaces
        while (pos < text.size() && std::isspace(text[pos]))
        {
            ++pos;
        }
        auto start = pos;
        // Extract keyword until space, parenthesis or end of string
        while (pos < text.size() && !std::isspace(text[pos]) && text[pos] != '(' && text[pos] != ')')
        {
            ++pos;
        }


        if (start == pos)
        {
            return parsec::makeError<std::string>(std::string("Expected keyword"), pos);
        }

        // Check if keyword is a Operator checking if start with a uppercase letter
        if (std::isupper(text[start]))
        {
            return parsec::makeError<std::string>(std::string("Expected a non-operator keyword"), pos);
        }

        auto keyword = text.substr(start, pos - start);

        return parsec::makeSuccess(std::string(keyword), pos);
    };

    EXPECT_THROW(parse<decltype(p)>(GetParam(), std::move(p)), std::runtime_error) << "Parsing: " << GetParam();
}

INSTANTIATE_TEST_SUITE_P(Logicexpr,
                         ErrorParserTest,
                         ::testing::Values(R"(event.type=="test" AND (something) unexpectedTerm)",
                                           R"(event.type=="test" AND OR (something))",
                                           R"(AND term)",
                                           R"(term OR)",
                                           R"(term AND (notClosedParenthesis)",
                                           R"(term AND notOpenedParenthesis))",
                                           R"(NOT)",
                                           R"(AND)",
                                           R"(term NOT AND term),
                                           R"(term ! AND term),
                                           R"(( ))",
                                           R"()"));

using Okpair = std::pair<std::string, std::string>;
using OkParserTest = testing::TestWithParam<Okpair>;
TEST_P(OkParserTest, parsingOK)
{
    parsec::Parser<std::string> p = [](std::string_view text, size_t pos) -> parsec::Result<std::string>
    {
        auto index = pos;
        // Skip spaces
        while (pos < text.size() && std::isspace(text[pos]))
        {
            ++pos;
        }
        auto start = pos;
        // Extract keyword until space, parenthesis or end of string
        while (pos < text.size() && !std::isspace(text[pos]) && text[pos] != '(' && text[pos] != ')')
        {
            ++pos;
        }

        if (start == pos)
        {
            return parsec::makeError<std::string>(std::string("Expected keyword"), pos);
        }

        // Check if keyword is a Operator checking if start with a uppercase letter
        if (std::isupper(text[start]) || text[start] == '(' || text[start] == ')')
        {
            return parsec::makeError<std::string>(std::string("Expected a non-operator keyword"), pos);
        }

        auto keyword = text.substr(start, pos - start);

        return parsec::makeSuccess(std::string(keyword), pos);
    };

    auto [input, expected] = GetParam();
    auto expression = Expression::create();
    std::string result;

    EXPECT_NO_THROW(expression = parse<decltype(p)>(input, std::move(p))) << "Parsing: " << input;
    EXPECT_NO_THROW(result = Expression::toDotString(expression));

    EXPECT_EQ(result, expected) << "Parsing: " << input << "\n result: " << result << "\n expected: " << expected;
}

INSTANTIATE_TEST_SUITE_P(Logicexpr,
                         OkParserTest,
                         ::testing::Values(Okpair {R"(onlyOneTerm)", R"(digraph G {
onlyOneTerm_00;
}
)"},

                                           Okpair {R"(onlyOneTerm)", R"(digraph G {
onlyOneTerm_00;
}
)"},
                                           Okpair {R"(term AND term)", R"(digraph G {
AND_00;
AND_00 -> term_10;
term_10;
AND_00 -> term_11;
term_11;
}
)"},
                                           Okpair {R"(term OR term)", R"(digraph G {
OR_00;
OR_00 -> term_10;
term_10;
OR_00 -> term_11;
term_11;
}
)"},
                                           Okpair {R"(term AND (term OR term))", R"(digraph G {
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
)"},
                                           Okpair {R"(term OR (term AND term))", R"(digraph G {
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
)"},
                                           Okpair {R"(NOT term)", R"(digraph G {
NOT_00;
NOT_00 -> term_10;
term_10;
}
)"},
                                           Okpair {R"(NOT (term AND term))", R"(digraph G {
NOT_00;
NOT_00 -> AND_10;
AND_10;
AND_10 -> term_20;
term_20;
AND_10 -> term_21;
term_21;
}
)"},
                                           Okpair {R"(NOT (term OR term))", R"(digraph G {
NOT_00;
NOT_00 -> OR_10;
OR_10;
OR_10 -> term_20;
term_20;
OR_10 -> term_21;
term_21;
}
)"},
                                           Okpair {R"(NOT (term AND (term OR term)))", R"(digraph G {
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
)"},
                                           Okpair {R"(term AND term OR term)", R"(digraph G {
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
)"},
                                           Okpair {R"(termA OR NOT termB AND termC)", R"(digraph G {
OR_00;
OR_00 -> AND_10;
AND_10;
AND_10 -> termC_20;
termC_20;
AND_10 -> NOT_21;
NOT_21;
NOT_21 -> termB_30;
termB_30;
OR_00 -> termA_11;
termA_11;
}
)"}));


TEST(LogicExpressionParser, notCopiableTerm)
{

    class NotCopyableTerm
    {
    private:
        std::string m_value;

    public:
        NotCopyableTerm() = delete;
        NotCopyableTerm(const NotCopyableTerm&) = delete;
        NotCopyableTerm& operator=(const NotCopyableTerm&) = delete;

        NotCopyableTerm(NotCopyableTerm&&) noexcept = default;
        NotCopyableTerm& operator=(NotCopyableTerm&&) noexcept = default;

        explicit NotCopyableTerm(const std::string& value)
            : m_value(value)
        {
        }

        std::string value() const { return m_value; }
    };

    parsec::Parser<NotCopyableTerm> p = [](std::string_view text, size_t pos) -> parsec::Result<NotCopyableTerm>
    {
        auto index = pos;
        // Skip spaces
        while (pos < text.size() && std::isspace(text[pos]))
        {
            ++pos;
        }
        auto start = pos;
        // Extract keyword
        while (pos < text.size() && !std::isspace(text[pos]))
        {
            ++pos;
        }

        if (start == pos)
        {
            return parsec::makeError<NotCopyableTerm>(std::string("Expected keyword"), pos);
        }

        // Check if keyword is a Operator checking if start with a uppercase letter
        if (std::isupper(text[start]))
        {
            return parsec::makeError<NotCopyableTerm>(std::string("Expected a non-operator keyword"), pos);
        }

        auto keyword = text.substr(start, pos - start);

        return parsec::makeSuccess(NotCopyableTerm{std::string(keyword)}, pos);
    };

    std::string input = "termA AND termB";
    std::string expected = R"(digraph G {
AND_00;
AND_00 -> termB_10;
termB_10;
AND_00 -> termA_11;
termA_11;
}
)";
    auto expression = Expression::create();
    std::string result ;

    EXPECT_NO_THROW(expression = parse<decltype(p)>(input, std::move(p))) << "Parsing: " << input;
    EXPECT_NO_THROW(result = Expression::toDotString(expression));


    EXPECT_EQ(result, expected) << "Parsing: " << input << "\n result: " << result << "\n expected: " << expected;
}
