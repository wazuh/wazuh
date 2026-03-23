#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include <mock_filesystem_wrapper.hpp>
#include <mock_sysinfo.hpp>

#include "logging_helper.hpp"

#include <filesystem>
#include <memory>

class ProcessRuleEvaluatorTest : public ::testing::Test
{
    protected:
        PolicyEvaluationContext m_ctx;
        std::unique_ptr<MockFileSystemWrapper> m_fsMock;
        MockFileSystemWrapper* m_rawFsMock = nullptr;
        std::unique_ptr<MockSysInfo> m_sysInfoMock;
        MockSysInfo* m_rawSysInfoMock = nullptr;
        std::function<std::vector<std::string>()> m_processesMock;

        void SetUp() override
        {
            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
                // Mock logging callback that does nothing
            });

            m_fsMock = std::make_unique<MockFileSystemWrapper>();
            m_rawFsMock = m_fsMock.get();
            m_sysInfoMock = std::make_unique<MockSysInfo>();
            m_rawSysInfoMock = m_sysInfoMock.get();
        }

        ProcessRuleEvaluator CreateEvaluator()
        {
            return ProcessRuleEvaluator{m_ctx, std::move(m_fsMock), std::move(m_sysInfoMock), m_processesMock};
        }
};

TEST_F(ProcessRuleEvaluatorTest, ProcessFoundReturnsFound)
{
    m_ctx.rule = "myprocess";

    m_processesMock = []
    {
        return std::vector<std::string> {"init", "myprocess", "sshd"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorTest, ProcessNotFoundReturnsNotFound)
{
    m_ctx.rule = "not-running";

    m_processesMock = []
    {
        return std::vector<std::string> {"systemd", "sshd", "nginx"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(ProcessRuleEvaluatorTest, EmptyProcessListReturnsNotFound)
{
    m_ctx.rule = "whatever";

    m_processesMock = []
    {
        return std::vector<std::string> {};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(ProcessRuleEvaluatorTest, ProcessListRetrievalFailsReturnsInvalid)
{
    m_ctx.rule = "anyprocess";

    m_processesMock = []() -> std::vector<std::string>
    {
        throw std::runtime_error("Failed to read /proc");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(ProcessRuleEvaluatorTest, GetProcessesFailureHasReasonString)
{
    m_ctx.rule = "test_process";

    m_processesMock = []() -> std::vector<std::string>
    {
        throw std::runtime_error("Failed to read /proc");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetInvalidReason().empty());
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("test_process"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("Failed to get process list"));
}

TEST_F(ProcessRuleEvaluatorTest, NegatedProcessFoundReturnsNotFound)
{
    m_ctx.rule = "myprocess";
    m_ctx.isNegated = true;

    m_processesMock = []
    {
        return std::vector<std::string> {"init", "myprocess", "sshd"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}
TEST_F(ProcessRuleEvaluatorTest, FullPathMatchReturnsFound)
{
    m_ctx.rule = "/usr/sbin/httpd";

    m_processesMock = []
    {
        return std::vector<std::string>{"init", "/usr/sbin/httpd", "sshd"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorTest, NegatedFullPathPresentReturnsNotFound)
{
    m_ctx.rule = "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent";
    m_ctx.isNegated = true;

    m_processesMock = []
    {
        return std::vector<std::string>{"ARDAgent", "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(ProcessRuleEvaluatorTest, NegatedFullPathAbsentReturnsFound)
{
    m_ctx.rule = "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent";
    m_ctx.isNegated = true;

    m_processesMock = []
    {
        return std::vector<std::string>{"launchd", "WindowServer"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}
