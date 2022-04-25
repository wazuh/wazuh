#include <logicExpressionEvaluator.hpp>

#include "gtest/gtest.h"

using namespace std;
using namespace logicExpression::evaluator;

TEST(LogicExpressionEvaluator, ExpressionConstructs)
{
    ASSERT_NO_THROW(Expression<int>::create());
    auto expression = Expression<int>::create();
    EXPECT_NO_THROW(expression =
                        Expression<int>::create([](int) { return true; }));
    EXPECT_TRUE(expression->m_function(0));
    EXPECT_THROW(expression = Expression<int>::create(TERM), runtime_error);

    EXPECT_NO_THROW(expression = Expression<int>::create(OR));
    EXPECT_NO_THROW(expression = Expression<int>::create(AND));
    EXPECT_NO_THROW(expression = Expression<int>::create(NOT));
}

TEST(LogicExpressionEvaluator, ExpressionUtils)
{
    auto expr1 = Expression<int>::create();
    auto expr2 = Expression<int>::create();

    // Different ptrs
    EXPECT_FALSE(expr1 == expr2);

    EXPECT_NO_THROW(expr2 = expr1->getPtr());
    EXPECT_TRUE(expr1 == expr2);

    // Visitor Pre-Order
    vector<int> expected = {TERM, NOT, TERM, OR};
    auto it = expected.end() - 1;
    auto visitor = [&it](const Expression<int>& expr)
    {
        EXPECT_EQ(expr.m_type, *it);
        --it;
    };

    auto root = Expression<int>::create(OR);
    root->m_left = Expression<int>::create([](int) { return true; });
    root->m_right = Expression<int>::create(NOT);
    root->m_right->m_left = Expression<int>::create([](int) { return true; });
    EXPECT_NO_THROW(Expression<int>::visitPreOrder(root, visitor));
}

TEST(LogicExpressionEvaluator, getDijstraEvaluator)
{
    // True if: (pair or odd and not i>5) and i>1
    // tldr: true if 3,5 or pair>1
    auto root = Expression<int>::create(AND);
    root->m_left = Expression<int>::create([](int i) { return i > 1; });
    root->m_right = Expression<int>::create(OR);
    root->m_right->m_left =
        Expression<int>::create([](int i) { return i % 2 == 0; });
    root->m_right->m_right = Expression<int>::create(NOT);
    root->m_right->m_right->m_left =
        Expression<int>::create([](int i) { return i > 5; });

    function<bool(int)> evaluator;
    ASSERT_NO_THROW(evaluator = getDijstraEvaluator<int>(root));

    EXPECT_FALSE(evaluator(0));
    EXPECT_FALSE(evaluator(1));
    EXPECT_TRUE(evaluator(2));
    EXPECT_TRUE(evaluator(3));
    EXPECT_TRUE(evaluator(4));
    EXPECT_TRUE(evaluator(5));
    EXPECT_TRUE(evaluator(6));
    EXPECT_FALSE(evaluator(7));
}
