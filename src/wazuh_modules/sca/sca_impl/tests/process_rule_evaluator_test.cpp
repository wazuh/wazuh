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
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("test_process"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Failed to get process list"));
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

// Exercises the production process listing (no injected GetProcessesFunc) with the
// names a platform reports through ISysInfo::processNames().
class MockSysInfoWithNames : public MockSysInfo
{
    public:
        MOCK_METHOD(void, processNames, (std::function<void(const ProcessNames&)>), (override));
};

class ProcessRuleEvaluatorNamesTest : public ProcessRuleEvaluatorTest
{
    protected:
        ProcessRuleEvaluator CreateEvaluatorWithNames(std::vector<ProcessNames> names)
        {
            auto sysInfo = std::make_unique<MockSysInfoWithNames>();

            EXPECT_CALL(*sysInfo, processNames(::testing::_))
            .WillOnce([names = std::move(names)](const std::function<void(const ProcessNames&)>& callback)
            {
                for (const auto& process : names)
                {
                    callback(process);
                }
            });

            return ProcessRuleEvaluator{m_ctx, std::move(m_fsMock), std::move(sysInfo)};
        }
};

TEST_F(ProcessRuleEvaluatorNamesTest, ProcessThatRewritesArgv0IsFoundByComm)
{
    m_ctx.rule = "nginx";

    auto evaluator = CreateEvaluatorWithNames(
    {
        {"nginx -g daemon on; master_process on;", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", "nginx"},
        {"nginx: worker process", "nginx: worker process", "nginx"}
    });

    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorNamesTest, ScriptRunByAnInterpreterIsFoundByComm)
{
    m_ctx.rule = "firewalld";

    auto evaluator = CreateEvaluatorWithNames({{"python3", "/usr/bin/python3", "firewalld"}});

    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorNamesTest, NegatedRuleIsNotFoundWhenOnlyCommMatches)
{
    m_ctx.rule = "firewalld";
    m_ctx.isNegated = true;

    auto evaluator = CreateEvaluatorWithNames({{"python3", "/usr/bin/python3", "firewalld"}});

    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(ProcessRuleEvaluatorNamesTest, NameAndCommandLineAreStillMatched)
{
    m_ctx.rule = "/usr/sbin/systemd-journald";

    auto evaluator = CreateEvaluatorWithNames({{"systemd-journald", "/usr/sbin/systemd-journald", "systemd-journal"}});

    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorNamesTest, CommandLineNoneIsNotAProcessName)
{
    m_ctx.rule = "none";

    auto evaluator = CreateEvaluatorWithNames({{"System", "none", ""}});

    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(ProcessRuleEvaluatorTest, DefaultProcessNamesUsesTheProcessInventory)
{
    // MockSysInfo does not override processNames(), so ISysInfo's default builds the
    // names from processes(), as on platforms without a separate kernel task name.
    m_ctx.rule = "sshd.exe";

    EXPECT_CALL(*m_rawSysInfoMock, processes(::testing::An<std::function<void(nlohmann::json&)>>()))
    .WillOnce([](const std::function<void(nlohmann::json&)>& callback)
    {
        auto system = nlohmann::json {{"name", "System"}, {"command_line", "none"}};
        auto sshd = nlohmann::json {{"name", "sshd.exe"}, {"command_line", "C:\\Windows\\System32\\OpenSSH\\sshd.exe"}};
        auto noName = nlohmann::json {{"pid", "4"}};
        callback(system);
        callback(sshd);
        callback(noName);
    });

    auto evaluator = ProcessRuleEvaluator{m_ctx, std::move(m_fsMock), std::move(m_sysInfoMock)};
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorTest, PlainValueMatchesCaseInsensitively)
{
    m_ctx.rule = "SSHD.exe";

    m_processesMock = []
    {
        return std::vector<std::string> {"System", "sshd.exe"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorTest, RegexValueIsMatchedAgainstEachName)
{
    m_ctx.rule = "r:^nginx";

    m_processesMock = []
    {
        return std::vector<std::string> {"systemd", "nginx: worker process"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorTest, RegexValueWithoutMatchReturnsNotFound)
{
    m_ctx.rule = "r:^apache";

    m_processesMock = []
    {
        return std::vector<std::string> {"systemd", "nginx"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(ProcessRuleEvaluatorTest, CompoundValueNeedsOneNameToSatisfyEveryTerm)
{
    m_ctx.rule = "r:nginx && !r:worker";

    m_processesMock = []
    {
        return std::vector<std::string> {"nginx: worker process", "systemd"};
    };

    auto onlyWorkers = CreateEvaluator();
    EXPECT_EQ(onlyWorkers.Evaluate(), RuleResult::NotFound);

    m_fsMock = std::make_unique<MockFileSystemWrapper>();
    m_sysInfoMock = std::make_unique<MockSysInfo>();
    m_processesMock = []
    {
        return std::vector<std::string> {"nginx: worker process", "nginx"};
    };

    auto withMaster = CreateEvaluator();
    EXPECT_EQ(withMaster.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorTest, PlainTermInsideCompoundMatchesCaseInsensitively)
{
    m_ctx.rule = "SSHD && !r:worker";

    m_processesMock = []
    {
        return std::vector<std::string> {"systemd", "sshd"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorTest, NegatedPlainValueIsATerm)
{
    // As in 4.x, "!sshd" holds for any process that is not sshd; "not p:sshd" is the rule for "sshd is not running"
    m_ctx.rule = "!sshd";

    m_processesMock = []
    {
        return std::vector<std::string> {"sshd"};
    };

    auto onlySshd = CreateEvaluator();
    EXPECT_EQ(onlySshd.Evaluate(), RuleResult::NotFound);

    m_fsMock = std::make_unique<MockFileSystemWrapper>();
    m_sysInfoMock = std::make_unique<MockSysInfo>();
    m_processesMock = []
    {
        return std::vector<std::string> {"sshd", "systemd"};
    };

    auto withOthers = CreateEvaluator();
    EXPECT_EQ(withOthers.Evaluate(), RuleResult::Found);
}

TEST_F(ProcessRuleEvaluatorTest, CaseSensitiveRegexIsNotLowercased)
{
    m_ctx.rule = "r:(?-i)^NGINX$";

    m_processesMock = []
    {
        return std::vector<std::string> {"nginx"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(ProcessRuleEvaluatorTest, ContentPatternIsRejectedInsteadOfIgnored)
{
    m_ctx.rule = "nginx";
    m_ctx.pattern = "r:master";

    m_processesMock = []
    {
        return std::vector<std::string> {"nginx"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("not supported"));
}
