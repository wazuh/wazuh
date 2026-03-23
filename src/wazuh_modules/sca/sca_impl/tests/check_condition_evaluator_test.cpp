#include <gtest/gtest.h>

#include <check_condition_evaluator.hpp>

TEST(CheckConditionEvaluatorTest, FromStringInvalidValueThrows)
{
    EXPECT_THROW(CheckConditionEvaluator::FromString("invalid"), std::invalid_argument);
}

TEST(CheckConditionEvaluatorTest, AllConditionBehavior)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    // No rules added yet: should be NotApplicable.
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
}

TEST(CheckConditionEvaluatorTest, AnyConditionBehavior)
{
    auto evaluator = CheckConditionEvaluator::FromString("any");

    // No rules added yet: should be NotApplicable.
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);
}

TEST(CheckConditionEvaluatorTest, NoneConditionBehavior)
{
    auto evaluator = CheckConditionEvaluator::FromString("none");

    // No rules added yet: should be NotApplicable.
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found)); // At least one passed -> should now be false.
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
}

TEST(CheckConditionEvaluatorTest, AddResultStopsAfterResultDetermined)
{
    auto evaluator = CheckConditionEvaluator::FromString("any");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found)); // Should determine result = true immediately
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound)); // Should have no effect
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);

    auto evaluator2 = CheckConditionEvaluator::FromString("all");

    evaluator2.AddResult(RuleEvaluationResult(RuleResult::NotFound)); // Should determine result = false immediately
    EXPECT_EQ(evaluator2.Result(), sca::CheckResult::Failed);

    evaluator2.AddResult(RuleEvaluationResult(RuleResult::Found)); // Should have no effect
    EXPECT_EQ(evaluator2.Result(), sca::CheckResult::Failed);
}

TEST(CheckConditionEvaluatorTest, AllConditionWithInvalidMakesResultNotApplicable)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);
}

TEST(CheckConditionEvaluatorTest, NoneConditionWithInvalidMakesResultNotApplicable)
{
    auto evaluator = CheckConditionEvaluator::FromString("none");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);
}

TEST(CheckConditionEvaluatorTest, AnyConditionWithInvalidCanBeTrueAsLongAsOnePassed)
{
    auto evaluator = CheckConditionEvaluator::FromString("any");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);
}
