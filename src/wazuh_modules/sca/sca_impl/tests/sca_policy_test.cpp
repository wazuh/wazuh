#include <gtest/gtest.h>

#include <sca_policy.hpp>
#include <sca_policy_check.hpp>

#include "logging_helper.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

/// @brief Rule whose reason only exists once it has been evaluated, like every real evaluator.
class DeferredReasonRule : public IRuleEvaluator
{
    public:
        DeferredReasonRule(RuleResult result, std::string reasonAfterEvaluation)
            : m_result(result)
            , m_reasonAfterEvaluation(std::move(reasonAfterEvaluation))
        {
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
                               std::vector<std::pair<RuleResult, std::string>> rules)
        {
            Check check;
            check.id = id;
            check.condition = condition;

            for (auto& [result, reason] : rules)
            {
                check.rules.push_back(std::make_unique<DeferredReasonRule>(result, reason));
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

TEST_F(SCAPolicyTest, ResolvedCheckReportsNoReason)
{
    std::vector<Check> checks;
    checks.push_back(MakeCheck("1002", "all", {{RuleResult::Found, ""}}));
    checks.push_back(MakeCheck("1003", "all", {{RuleResult::NotFound, ""}}));

    const auto reported = RunPolicy(Check {}, std::move(checks));

    ASSERT_EQ(reported.size(), 2U);
    EXPECT_EQ(reported[0].result, "Passed");
    EXPECT_TRUE(reported[0].reason.empty());
    EXPECT_EQ(reported[1].result, "Failed");
    EXPECT_TRUE(reported[1].reason.empty());
}

// The event handler drops "Not run" checks before they reach the database event or the index, so
// this pins the SCAPolicy contract rather than anything an operator can see today.
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
