#include <logicExpressionParser.hpp>

#include "gtest/gtest.h"

using namespace std;

TEST(LogicExpressionParser, ParseErrors)
{
    const vector<string> expressions = {
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
        EXPECT_THROW(logicExpression::parse(expression), runtime_error);
    }
}

TEST(LogicExpressionParser, Parse)
{
    const vector<string> expressions = {
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

    const vector<string> expectedGraph = {
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
        auto exp = logicExpression::Expression::create();
        EXPECT_NO_THROW(exp = logicExpression::parse(expressions[i]));
        EXPECT_EQ(logicExpression::Expression::toDotString(exp),
                  expectedGraph[i]);
    }
}
