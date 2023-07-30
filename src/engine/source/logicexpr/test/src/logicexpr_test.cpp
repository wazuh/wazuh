#include <logicexpr/logicexpr.hpp>

#include "gtest/gtest.h"

using namespace logicexpr;

TEST(LogicExpression, buildDijstraEvaluator)
{
    // True if: (even or odd and not i>5) and i>1
    // tldr: true if 3,5 or even>1

    auto fakeTermBuilder = [](std::string s) -> std::function<bool(int)>
    {
        if (s == "even")
        {
            return [](int i)
            {
                return i % 2 == 0;
            };
        }
        else if (s == "odd")
        {
            return [](int i)
            {
                return i % 2 != 0;
            };
        }
        else if (s == "great5")
        {
            return [](int i)
            {
                return i > 5;
            };
        }
        else if (s == "great1")
        {
            return [](int i)
            {
                return i > 1;
            };
        }
        else
        {
            throw std::runtime_error(
                "Error test fakeBuilder, got unexpected term: " + s);
        }
    };

    parsec::Parser<std::string> termP = [](std::string_view text, size_t pos) -> parsec::Result<std::string>
    {
        // Until space, ( or ) without including it
        auto end = text.find_first_of(" ()", pos);
        if (end == std::string_view::npos)
        {
            end = text.size();
        }
        // the keyword cannot be a operator, so we check it here
        if (std::isupper(text[pos]) || text[pos] == '(' || text[pos] == ')')
        {
            return parsec::makeError<std::string>("Unexpected token", pos);
        }
        return parsec::makeSuccess<std::string>(std::string {text.substr(pos, end - pos)}, end);
    };

    auto expression = "(even OR odd AND NOT great5) AND great1";
    std::function<bool(int)> evaluator;
    EXPECT_NO_THROW((evaluator = buildDijstraEvaluator<int, std::string>(expression, fakeTermBuilder, termP)));

    EXPECT_FALSE(evaluator(0));
    EXPECT_FALSE(evaluator(1));
    EXPECT_TRUE(evaluator(2));
    EXPECT_TRUE(evaluator(3));
    EXPECT_TRUE(evaluator(4));
    EXPECT_TRUE(evaluator(5));
    EXPECT_TRUE(evaluator(6));
    EXPECT_FALSE(evaluator(7));
}
