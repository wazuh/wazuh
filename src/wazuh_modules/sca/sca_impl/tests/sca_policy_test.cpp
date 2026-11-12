#include <gtest/gtest.h>

#include <sca_policy.hpp>
#include <sca_policy_check.hpp>

#include "logging_helper.hpp"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

/// @brief Rule whose reason only exists once it has been evaluated, like every real evaluator.
class DeferredReasonRule : public IRuleEvaluator
{
    public:
        DeferredReasonRule(RuleResult result, std::string reasonAfterEvaluation, std::string source = {})
            : m_result(result)
            , m_reasonAfterEvaluation(std::move(reasonAfterEvaluation))
        {
            m_ctx.source = std::move(source);
        }

        RuleResult Evaluate() override
        {
            m_reason = m_reasonAfterEvaluation;
            return m_result;
        }

        const PolicyEvaluationContext& GetContext() const override
        {
            return m_ctx;
        }

        std::string GetUnresolvedReason() const override
        {
            return m_reason;
        }

    private:
        RuleResult m_result;
        std::string m_reasonAfterEvaluation;
        std::string m_reason;
        PolicyEvaluationContext m_ctx;
};

/// @brief What a fake rule returns, the reason it then reports, and the rule text it stands for.
struct FakeRule
{
    RuleResult result;
    std::string reason;
    std::string source = {};
};

class SCAPolicyTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
                // Mock logging callback that does nothing
            });
        }

        static Check MakeCheck(const std::string& id,
                               const std::string& condition,
                               std::vector<FakeRule> rules)
        {
            Check check;
            check.id = id;
            check.condition = condition;

            for (auto& rule : rules)
            {
                check.rules.push_back(std::make_unique<DeferredReasonRule>(rule.result, rule.reason, rule.source));
            }

            return check;
        }

        static std::vector<CheckResult> RunPolicy(Check requirements, std::vector<Check> checks)
        {
            SCAPolicy policy("test_policy", std::move(requirements), std::move(checks));

            std::vector<CheckResult> reported;
            policy.Run([&reported](const CheckResult & result)
            {
                reported.push_back(result);
            });

            return reported;
        }
};

TEST_F(SCAPolicyTest, NotApplicableCheckCarriesTheReasonOfItsUnresolvedRule)
{
    std::vector<Check> checks;
    checks.push_back(MakeCheck("1000", "all", {{RuleResult::Invalid, "File '/etc/selinux/config' does not exist"}}));

    const auto reported = RunPolicy(Check {}, std::move(checks));

    ASSERT_EQ(reported.size(), 1U);
    EXPECT_EQ(reported[0].result, "Not applicable");
    EXPECT_EQ(reported[0].reason, "File '/etc/selinux/config' does not exist");
}

TEST_F(SCAPolicyTest, EveryUnresolvedRuleContributesItsReasonInRuleOrder)
{
    std::vector<Check> checks;
    checks.push_back(MakeCheck("1001",
                               "any",
    {
        {RuleResult::Invalid, "Command execution failed: modprobe -n -v cramfs"},
        {RuleResult::Invalid, "Command execution failed: lsmod"},
        {RuleResult::Invalid, "Path '/etc/modprobe.d/' does not exist"}
    }));

    const auto reported = RunPolicy(Check {}, std::move(checks));

    ASSERT_EQ(reported.size(), 1U);
    EXPECT_EQ(reported[0].result, "Not applicable");
    EXPECT_EQ(reported[0].reason,
              "Command execution failed: modprobe -n -v cramfs\n"
              "Command execution failed: lsmod\n"
              "Path '/etc/modprobe.d/' does not exist");
}

TEST_F(SCAPolicyTest, PassedCheckReportsNoReason)
{
    std::vector<Check> checks;
    checks.push_back(MakeCheck("1002", "all", {{RuleResult::Found, "", "f:/etc/passwd"}}));

    const auto reported = RunPolicy(Check {}, std::move(checks));

    ASSERT_EQ(reported.size(), 1U);
    EXPECT_EQ(reported[0].result, "Passed");
    EXPECT_TRUE(reported[0].reason.empty());
}

TEST_F(SCAPolicyTest, FailedCheckReportsTheRulesItDidNotSatisfy)
{
    std::vector<Check> checks;
    checks.push_back(MakeCheck("1003", "all",
    {
        {RuleResult::Found, "", "f:/etc/motd"},
        {RuleResult::NotFound, "", "f:/etc/motd -> r:Authorized uses only"}
    }));

    const auto reported = RunPolicy(Check {}, std::move(checks));

    ASSERT_EQ(reported.size(), 1U);
    EXPECT_EQ(reported[0].result, "Failed");
    EXPECT_EQ(reported[0].reason,
              "Rules not satisfied (condition 'all'):\n"
              "f:/etc/motd -> r:Authorized uses only");
}

TEST_F(SCAPolicyTest, RulesAfterTheVerdictAreStillEvaluatedAndListed)
{
    std::vector<Check> checks;
    checks.push_back(MakeCheck("1005", "all",
    {
        {RuleResult::NotFound, "", "c:sysctl net.ipv4.ip_forward -> r:= 0"},
        {RuleResult::NotFound, "", "c:sysctl net.ipv6.conf.all.forwarding -> r:= 0"}
    }));

    const auto reported = RunPolicy(Check {}, std::move(checks));

    ASSERT_EQ(reported.size(), 1U);
    EXPECT_EQ(reported[0].result, "Failed");
    EXPECT_EQ(reported[0].reason,
              "Rules not satisfied (condition 'all'):\n"
              "c:sysctl net.ipv4.ip_forward -> r:= 0\n"
              "c:sysctl net.ipv6.conf.all.forwarding -> r:= 0");
}

TEST_F(SCAPolicyTest, CheckResultIsLoggedOnOneLine)
{
    // The agent log timestamps each line, so a reason's line breaks would leave bare lines in it
    std::vector<std::string> logs;
    LoggingHelper::setLogCallback([&logs](const modules_log_level_t /* level */, const char* log)
    {
        logs.emplace_back(log);
    });

    std::vector<Check> checks;
    checks.push_back(MakeCheck("1006", "all",
    {
        {RuleResult::NotFound, "", "c:sysctl net.ipv4.ip_forward -> r:= 0"},
        {RuleResult::NotFound, "", "c:sysctl net.ipv6.conf.all.forwarding -> r:= 0"}
    }));

    RunPolicy(Check {}, std::move(checks));
    LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {});

    const auto line = std::find_if(logs.begin(), logs.end(), [](const std::string & log)
    {
        return log.find("Policy check \"1006\"") != std::string::npos;
    });

    ASSERT_NE(line, logs.end());
    EXPECT_EQ(*line,
              "Policy check \"1006\" evaluation completed for policy \"test_policy\", result: Failed, "
              "reason: Rules not satisfied (condition 'all'):\\n"
              "c:sysctl net.ipv4.ip_forward -> r:= 0\\n"
              "c:sysctl net.ipv6.conf.all.forwarding -> r:= 0");
}

// The event handler stores a "Not run" result in the agent database but keeps it out of the events
// and the index, so this pins the SCAPolicy contract rather than anything the console shows today.
TEST_F(SCAPolicyTest, NotRunRequirementsReportTheirReasonOnEveryCheck)
{
    auto requirements = MakeCheck("requirements", "all", {{RuleResult::NotRun, "Command timed out after 30 seconds: rpm -q"}});

    std::vector<Check> checks;
    checks.push_back(MakeCheck("1004", "all", {{RuleResult::Found, ""}}));

    const auto reported = RunPolicy(std::move(requirements), std::move(checks));

    ASSERT_EQ(reported.size(), 1U);
    EXPECT_EQ(reported[0].result, "Not run");
    EXPECT_EQ(reported[0].reason, "Command timed out after 30 seconds: rpm -q");
}

TEST_F(SCAPolicyTest, UnmetRequirementsAreLoggedAtInfo)
{
    std::vector<std::pair<modules_log_level_t, std::string>> logs;
    LoggingHelper::setLogCallback([&logs](const modules_log_level_t level, const char* log)
    {
        logs.emplace_back(level, log);
    });

    auto requirements = MakeCheck("requirements", "any", {{RuleResult::NotFound, "", "p:nginx"}});

    std::vector<Check> checks;
    checks.push_back(MakeCheck("1007", "all", {{RuleResult::Found, ""}}));

    const auto reported = RunPolicy(std::move(requirements), std::move(checks));
    LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {});

    ASSERT_EQ(reported.size(), 1U);
    EXPECT_EQ(reported[0].result, "Not applicable");

    const auto line = std::find_if(logs.begin(), logs.end(), [](const auto & log)
    {
        return log.first == LOG_INFO && log.second == "Policy \"test_policy\" skipped: its requirements are not met.";
    });

    EXPECT_NE(line, logs.end());
}

TEST_F(SCAPolicyTest, InvalidRequirementsAreLoggedAtInfoWithTheReason)
{
    std::vector<std::pair<modules_log_level_t, std::string>> logs;
    LoggingHelper::setLogCallback([&logs](const modules_log_level_t level, const char* log)
    {
        logs.emplace_back(level, log);
    });

    auto requirements = MakeCheck("requirements", "all",
    {{RuleResult::Invalid, "Patterns ('->') are not supported in process rule 'nginx'", "p:nginx -> r:master"}});

    std::vector<Check> checks;
    checks.push_back(MakeCheck("1009", "all", {{RuleResult::Found, ""}}));

    const auto reported = RunPolicy(std::move(requirements), std::move(checks));
    LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {});

    ASSERT_EQ(reported.size(), 1U);
    EXPECT_EQ(reported[0].result, "Not applicable");

    const auto line = std::find_if(logs.begin(), logs.end(), [](const auto & log)
    {
        return log.first == LOG_INFO &&
               log.second.find("Policy \"test_policy\" skipped: its requirements could not be evaluated: ") == 0 &&
               log.second.find("Patterns ('->') are not supported in process rule 'nginx'") != std::string::npos;
    });

    EXPECT_NE(line, logs.end());
    EXPECT_EQ(std::count_if(logs.begin(), logs.end(), [](const auto & log)
    {
        return log.second.find("its requirements are not met") != std::string::npos;
    }), 0);
}

TEST_F(SCAPolicyTest, MetRequirementsLogNothingAtInfo)
{
    std::vector<modules_log_level_t> levels;
    LoggingHelper::setLogCallback([&levels](const modules_log_level_t level, const char* /* log */)
    {
        levels.push_back(level);
    });

    auto requirements = MakeCheck("requirements", "any", {{RuleResult::Found, "", "p:nginx"}});

    std::vector<Check> checks;
    checks.push_back(MakeCheck("1008", "all", {{RuleResult::Found, ""}}));

    RunPolicy(std::move(requirements), std::move(checks));
    LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {});

    EXPECT_EQ(std::count(levels.begin(), levels.end(), LOG_INFO), 0);
}
