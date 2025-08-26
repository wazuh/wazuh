#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include <mock_filesystem_wrapper.hpp>

#include "logging_helper.hpp"

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
            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
                // Mock logging callback that does nothing
            });

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

TEST_F(CommandRuleEvaluatorTest, CommandsDisabledHasReasonString)
{
    m_ctx.rule = "echo test";
    m_ctx.commandsEnabled = false;

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetInvalidReason().empty());
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("Remote commands are disabled"));
}

TEST_F(CommandRuleEvaluatorTest, CommandExecutionFailureHasReasonString)
{
    m_ctx.rule = "some command";
    m_ctx.pattern = std::string("something");

    m_execMock = [](const std::string&) -> std::optional<CommandRuleEvaluator::ExecResult>
    {
        return std::nullopt;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetInvalidReason().empty());
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("some command"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("Command execution failed"));
}

TEST_F(CommandRuleEvaluatorTest, InvalidPatternHasReasonString)
{
    m_ctx.rule = "echo test";
    m_ctx.pattern = std::string("r:***invalid***");

    m_execMock = [](const std::string&) -> std::optional<CommandRuleEvaluator::ExecResult>
    {
        CommandRuleEvaluator::ExecResult result;
        result.StdOut = "test output";
        result.StdErr = "test error";
        result.ExitCode = 0;
        return result;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetInvalidReason().empty());
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("***invalid***"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("Invalid pattern"));
}
