#include <logicExpression/logicExpression.hpp>

#include "gtest/gtest.h"

using namespace std;
using namespace logicExpression;

TEST(LogicExpression, buildDijstraEvaluator)
{
    // True if: (pair or odd and not i>5) and i>1
    // tldr: true if 3,5 or pair>1

    auto fakeTermBuilder = [](string s) -> function<bool(int)>
    {
        if (s == "PAIR")
        {
            return [](int i)
            {
                return i % 2 == 0;
            };
        }
        else if (s == "ODD")
        {
            return [](int i)
            {
                return i % 2 != 0;
            };
        }
        else if (s == "GREAT5")
        {
            return [](int i)
            {
                return i > 5;
            };
        }
        else if (s == "GREAT1")
        {
            return [](int i)
            {
                return i > 1;
            };
        }
        else
        {
            throw runtime_error(
                "Error test fakeBuilder, got unexpected term: " + s);
        }
    };

    auto expression = "(PAIR OR ODD AND NOT GREAT5) AND GREAT1";
    function<bool(int)> evaluator;
    EXPECT_NO_THROW(evaluator = buildDijstraEvaluator<int>(expression, fakeTermBuilder));

    EXPECT_FALSE(evaluator(0));
    EXPECT_FALSE(evaluator(1));
    EXPECT_TRUE(evaluator(2));
    EXPECT_TRUE(evaluator(3));
    EXPECT_TRUE(evaluator(4));
    EXPECT_TRUE(evaluator(5));
    EXPECT_TRUE(evaluator(6));
    EXPECT_FALSE(evaluator(7));
}
