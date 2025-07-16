#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include <mock_filesystem_wrapper.hpp>

#include <filesystem>
#include <memory>

class CommandRuleEvaluatorTest : public ::testing::Test
{
protected:
    PolicyEvaluationContext m_ctx;
    std::unique_ptr<MockFileSystemWrapper> m_fsMock;
    MockFileSystemWrapper* m_rawFsMock = nullptr;
    std::function<std::optional<CommandRuleEvaluator::ExecResult>(const std::string&)> m_execMock;

    void SetUp() override
    {
        m_fsMock = std::make_unique<MockFileSystemWrapper>();
        m_rawFsMock = m_fsMock.get();
    }

    CommandRuleEvaluator CreateEvaluator()
    {
        return {m_ctx, std::move(m_fsMock), m_execMock};
    }
};

TEST_F(CommandRuleEvaluatorTest, EvaluationReturnsFoundWhenCommandGivenButNoPattern)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::nullopt;

    m_execMock = [](const std::string&)
    {
        return std::make_optional<CommandRuleEvaluator::ExecResult>();
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(CommandRuleEvaluatorTest, CommandReturnsEmptyStringReturnsNotFound)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("some pattern");

    m_execMock = [](const std::string&)
    {
        return std::make_optional<CommandRuleEvaluator::ExecResult>();
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(CommandRuleEvaluatorTest, CommandOutputMatchesLiteralPatternReturnsFound)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("exact match");

    m_execMock = [](const std::string&)
    {
        CommandRuleEvaluator::ExecResult result;
        result.StdOut = "exact match";
        result.StdErr = "";
        result.ExitCode = 0;
        return std::make_optional<CommandRuleEvaluator::ExecResult>(result);
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(CommandRuleEvaluatorTest, CommandOutputDoesNotMatchLiteralPatternReturnsNotFound)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("exact match");

    m_execMock = [](const std::string&)
    {
        CommandRuleEvaluator::ExecResult result;
        result.StdOut = "something else";
        result.StdErr = "";
        result.ExitCode = 0;
        return std::make_optional<CommandRuleEvaluator::ExecResult>(result);
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(CommandRuleEvaluatorTest, RegexPatternMatchesOutputReturnsFound)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("r:success");

    m_execMock = [](const std::string&)
    {
        CommandRuleEvaluator::ExecResult result;
        result.StdOut = "success";
        result.StdErr = "";
        result.ExitCode = 0;
        return std::make_optional<CommandRuleEvaluator::ExecResult>(result);
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(CommandRuleEvaluatorTest, RegexPatternDoesNotMatchOutputReturnsNotFound)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("r:fail");

    m_execMock = [](const std::string&)
    {
        CommandRuleEvaluator::ExecResult result;
        result.StdOut = "ok";
        result.StdErr = "";
        result.ExitCode = 0;
        return std::make_optional<CommandRuleEvaluator::ExecResult>(result);
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(CommandRuleEvaluatorTest, PatternGivenButCommandOutputIsEmptyReturnsNotFound)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("r:foo");

    m_execMock = [](const std::string&)
    {
        return std::make_optional<CommandRuleEvaluator::ExecResult>();
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(CommandRuleEvaluatorTest, NumericPatternMatchesOutputReturnsFound)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("n:\\d+ compare <= 50");

    m_execMock = [](const std::string&)
    {
        CommandRuleEvaluator::ExecResult result;
        result.StdOut = "42";
        result.StdErr = "";
        result.ExitCode = 0;
        return std::make_optional<CommandRuleEvaluator::ExecResult>(result);
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(CommandRuleEvaluatorTest, NumericPatternWithStringMatchesOutputReturnsFound)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("n:Some string:\\s+(\\d+) compare >= 24");

    m_execMock = [](const std::string&)
    {
        CommandRuleEvaluator::ExecResult result;
        result.StdOut = "Some string:           42";
        result.StdErr = "";
        result.ExitCode = 0;
        return std::make_optional<CommandRuleEvaluator::ExecResult>(result);
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(CommandRuleEvaluatorTest, CommandExecutionReturnsNulloptIsInvalid)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("something");

    m_execMock = [](const std::string&) -> std::optional<CommandRuleEvaluator::ExecResult>
    {
        return std::nullopt;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}
