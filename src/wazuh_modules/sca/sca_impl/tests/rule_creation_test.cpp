#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

template<typename T>
bool IsInstanceOf(const std::unique_ptr<IRuleEvaluator>& evaluator)
{
    return dynamic_cast<T*>(evaluator.get()) != nullptr;
}

TEST(RuleEvaluatorFactoryTest, FileRuleWithoutPattern)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("f:/etc/motd", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<FileRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, FileRuleWithPattern)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("f:/etc/passwd -> root", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<FileRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, NegatedFileRule)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("not f:/etc/shadow", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<FileRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, DirRule)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("d:/etc/audit", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<DirRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, DirRuleWithPattern)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("d:/etc/audit -> something", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<DirRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, ProcessRule)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("p:sshd", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<ProcessRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, NegatedProcessRule)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("not p:cron", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<ProcessRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, CommandRule)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("c:whoami", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<CommandRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, CommandRuleWithPattern)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("c:ls -> root", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    EXPECT_TRUE(IsInstanceOf<CommandRuleEvaluator>(evaluator));
}

TEST(RuleEvaluatorFactoryTest, InvalidType)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("x:/invalid", nullptr, nullptr);
    EXPECT_EQ(evaluator, nullptr);
}

TEST(RuleEvaluatorFactoryTest, MissingColon)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("not invalid", nullptr, nullptr);
    EXPECT_EQ(evaluator, nullptr);
}

TEST(RuleEvaluatorFactoryTest, IncompleteRule)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator(":", nullptr, nullptr);
    EXPECT_EQ(evaluator, nullptr);
}

TEST(RuleEvaluatorFactoryTest, EmptyInput)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("", nullptr, nullptr);
    EXPECT_EQ(evaluator, nullptr);
}

TEST(RuleEvaluatorFactoryTest, FileRuleWithoutPattern_ParsesCorrectContext)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("f:/etc/motd", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    ASSERT_TRUE(IsInstanceOf<FileRuleEvaluator>(evaluator));

    auto* base = dynamic_cast<RuleEvaluator*>(evaluator.get());
    ASSERT_NE(base, nullptr); // ensure cast succeeded

    const auto& ctx = base->GetContext();
    EXPECT_EQ(ctx.rule, "/etc/motd");
    EXPECT_FALSE(ctx.pattern.has_value());
    EXPECT_FALSE(ctx.isNegated);
}

TEST(RuleEvaluatorFactoryTest, FileRuleWithPattern_ParsesCorrectContext)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("f:/etc/passwd -> root", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    ASSERT_TRUE(IsInstanceOf<FileRuleEvaluator>(evaluator));

    auto* base = dynamic_cast<RuleEvaluator*>(evaluator.get());
    ASSERT_NE(base, nullptr);

    const auto& ctx = base->GetContext();
    EXPECT_EQ(ctx.rule, "/etc/passwd");
    ASSERT_TRUE(ctx.pattern.has_value());
    EXPECT_EQ(ctx.pattern.value(), "root"); // NOLINT(bugprone-unchecked-optional-access)
    EXPECT_FALSE(ctx.isNegated);
}

TEST(RuleEvaluatorFactoryTest, NegatedFileRule_ParsesCorrectContext)
{
    auto evaluator = RuleEvaluatorFactory::CreateEvaluator("not f:/etc/shadow", nullptr, nullptr);
    ASSERT_NE(evaluator, nullptr);
    ASSERT_TRUE(IsInstanceOf<FileRuleEvaluator>(evaluator));

    auto* base = dynamic_cast<RuleEvaluator*>(evaluator.get());
    ASSERT_NE(base, nullptr);

    const auto& ctx = base->GetContext();
    EXPECT_EQ(ctx.rule, "/etc/shadow");
    EXPECT_FALSE(ctx.pattern.has_value());
    EXPECT_TRUE(ctx.isNegated);
}
