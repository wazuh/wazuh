#include <logicexpr/evaluator.hpp>

#include "gtest/gtest.h"

using namespace logicexpr::evaluator;

TEST(LogicExpressionEvaluator, ExpressionConstructs)
{
    ASSERT_NO_THROW(Expression<int>::create());
    auto expression = Expression<int>::create();
    EXPECT_NO_THROW(expression = Expression<int>::create([](int) { return true; }));
    EXPECT_TRUE(expression->m_function(0));
    EXPECT_THROW(expression = Expression<int>::create(ExpressionType::TERM), std::runtime_error);

    EXPECT_NO_THROW(expression = Expression<int>::create(ExpressionType::OR));
    EXPECT_NO_THROW(expression = Expression<int>::create(ExpressionType::AND));
    EXPECT_NO_THROW(expression = Expression<int>::create(ExpressionType::NOT));
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
    std::vector<ExpressionType> expected = {
        ExpressionType::TERM, ExpressionType::NOT, ExpressionType::TERM, ExpressionType::OR};
    auto it = expected.end() - 1;
    auto visitor = [&it](const Expression<int>& expr)
    {
        EXPECT_EQ(expr.m_type, *it);
        --it;
    };

    auto root = Expression<int>::create(ExpressionType::OR);
    root->m_left = Expression<int>::create([](int) { return true; });
    root->m_right = Expression<int>::create(ExpressionType::NOT);
    root->m_right->m_left = Expression<int>::create([](int) { return true; });
    EXPECT_NO_THROW(Expression<int>::visitPreOrder(root, visitor));
}

TEST(LogicExpressionEvaluator, getDijstraEvaluator)
{
    // True if: (pair or odd and not i>5) and i>1
    // tldr: true if 3,5 or pair>1
    auto root = Expression<int>::create(ExpressionType::AND);
    root->m_left = Expression<int>::create([](int i) { return i > 1; });
    root->m_right = Expression<int>::create(ExpressionType::OR);
    root->m_right->m_left = Expression<int>::create([](int i) { return i % 2 == 0; });
    root->m_right->m_right = Expression<int>::create(ExpressionType::NOT);
    root->m_right->m_right->m_left = Expression<int>::create([](int i) { return i > 5; });

    std::function<bool(int)> evaluator;
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

TEST(LogicExpressionEvaluator, getDijstraEvaluatorNotTerm)
{
    // True if: not pair
    auto root = Expression<int>::create(ExpressionType::NOT);
    root->m_left = Expression<int>::create([](int i) { return i % 2 == 0; });

    std::function<bool(int)> evaluator;
    ASSERT_NO_THROW(evaluator = getDijstraEvaluator<int>(root));

    EXPECT_FALSE(evaluator(0));
    EXPECT_TRUE(evaluator(1));
    EXPECT_FALSE(evaluator(2));
    EXPECT_TRUE(evaluator(3));
    EXPECT_FALSE(evaluator(4));
    EXPECT_TRUE(evaluator(5));
    EXPECT_FALSE(evaluator(6));
    EXPECT_TRUE(evaluator(7));
}

TEST(LogicExpressionEvaluator, getDijstraEvaluatorSingleTerm)
{
    // True if: not pair
    auto root = Expression<int>::create([](int i) { return i % 2 == 0; });
    std::function<bool(int)> evaluator;
    ASSERT_NO_THROW(evaluator = getDijstraEvaluator<int>(root));

    EXPECT_TRUE(evaluator(0));
    EXPECT_FALSE(evaluator(1));
    EXPECT_TRUE(evaluator(2));
    EXPECT_FALSE(evaluator(3));
    EXPECT_TRUE(evaluator(4));
    EXPECT_FALSE(evaluator(5));
    EXPECT_TRUE(evaluator(6));
    EXPECT_FALSE(evaluator(7));
}
