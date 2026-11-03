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

TEST(CheckConditionEvaluatorTest, NotRunSurfacesAsCheckResultNotRun)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotRun, "Command timed out after 30 seconds: sleep 60"));
    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotRun);
    EXPECT_NE(evaluator.GetUnresolvedReason().find("timed out"), std::string::npos);
}

TEST(CheckConditionEvaluatorTest, RepeatedReasonIsKeptOnce)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    const std::string reason = "File '/etc/aide/aide.conf' does not exist or is not a regular file";

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, reason));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, reason));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, reason));

    EXPECT_EQ(evaluator.GetUnresolvedReason(), reason);
}

TEST(CheckConditionEvaluatorTest, DistinctReasonsAreAllKeptInOrder)
{
    auto evaluator = CheckConditionEvaluator::FromString("any");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, "Command execution failed: modprobe -n -v cramfs"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, "Command execution failed: lsmod"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, "Command execution failed: modprobe -n -v cramfs"));

    EXPECT_EQ(evaluator.GetUnresolvedReason(),
              "Command execution failed: modprobe -n -v cramfs\n"
              "Command execution failed: lsmod");
}

TEST(CheckConditionEvaluatorTest, ReasonSharingAPrefixWithAnotherIsNotDroppedAsDuplicate)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, "Command execution failed: lsmod -a"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, "Command execution failed: lsmod"));

    EXPECT_EQ(evaluator.GetUnresolvedReason(),
              "Command execution failed: lsmod -a\n"
              "Command execution failed: lsmod");
}

TEST(CheckConditionEvaluatorTest, CheckWithNoEvaluableRulesExplainsItself)
{
    // The policy parser keeps a check whose every rule failed to parse, with no rules at all.
    const auto evaluator = CheckConditionEvaluator::FromString("all");

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
}

TEST(CheckConditionEvaluatorTest, UnresolvedRuleWithoutItsOwnReasonStillGetsOne)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);
    EXPECT_EQ(evaluator.GetUnresolvedReason(), "Unknown reason");
}

TEST(CheckConditionEvaluatorTest, ResolvedCheckHasNoReason)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Passed);
    EXPECT_TRUE(evaluator.GetUnresolvedReason().empty());
}

TEST(CheckConditionEvaluatorTest, AllConditionReasonListsTheRuleThatWasNotSatisfied)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found, "", "f:/etc/ssh/sshd_config"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "c:sshd -T -> r:^maxauthtries\\s+[1-4]"));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
    EXPECT_EQ(evaluator.Reason(),
              "Rules not satisfied (condition 'all'):\n"
              "c:sshd -T -> r:^maxauthtries\\s+[1-4]");
}

TEST(CheckConditionEvaluatorTest, AllConditionReasonListsUnsatisfiedRulesAfterTheVerdict)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "f:/etc/login.defs -> r:^PASS_MAX_DAYS\\s+365"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found, "", "f:/etc/login.defs"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "f:/etc/login.defs -> r:^PASS_MIN_DAYS\\s+1"));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
    EXPECT_EQ(evaluator.Reason(),
              "Rules not satisfied (condition 'all'):\n"
              "f:/etc/login.defs -> r:^PASS_MAX_DAYS\\s+365\n"
              "f:/etc/login.defs -> r:^PASS_MIN_DAYS\\s+1");
}

TEST(CheckConditionEvaluatorTest, NoneConditionReasonListsTheRulesThatWereSatisfied)
{
    auto evaluator = CheckConditionEvaluator::FromString("none");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "p:avahi-daemon"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found, "", "p:telnetd"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found, "", "p:rshd"));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
    EXPECT_EQ(evaluator.Reason(),
              "Rules satisfied (condition 'none'):\n"
              "p:telnetd\n"
              "p:rshd");
}

TEST(CheckConditionEvaluatorTest, NotApplicableReasonIsTheUnresolvedReason)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::Found, "", "f:/etc/modprobe.d"));
    evaluator.AddResult(RuleEvaluationResult(
                            RuleResult::Invalid, "Command execution failed: modprobe -n -v cramfs", "c:modprobe -n -v cramfs -> r:install /bin/true"));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotApplicable);
    EXPECT_EQ(evaluator.Reason(), "Command execution failed: modprobe -n -v cramfs");

    const auto noRules = CheckConditionEvaluator::FromString("all");

    EXPECT_EQ(noRules.Result(), sca::CheckResult::NotApplicable);
    EXPECT_EQ(noRules.Reason(), "None of the check's rules could be evaluated on this system");
}

TEST(CheckConditionEvaluatorTest, NotRunReasonIsTheUnresolvedReason)
{
    auto evaluator = CheckConditionEvaluator::FromString("any");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "f:/etc/issue -> r:Authorized"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotRun, "Command timed out after 30 seconds: sleep 60", "c:sleep 60"));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::NotRun);
    EXPECT_EQ(evaluator.Reason(), "Command timed out after 30 seconds: sleep 60");
}

TEST(CheckConditionEvaluatorTest, FailedCheckWithoutRuleTextHasNoReason)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
    EXPECT_EQ(evaluator.Reason(), "");
}

TEST(CheckConditionEvaluatorTest, AnyConditionReasonListsEveryRuleWhenNoneIsSatisfied)
{
    auto evaluator = CheckConditionEvaluator::FromString("any");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "f:/etc/issue -> r:Authorized uses only"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "f:/etc/issue.net -> r:Authorized uses only"));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
    EXPECT_EQ(evaluator.Reason(),
              "Rules not satisfied (condition 'any'):\n"
              "f:/etc/issue -> r:Authorized uses only\n"
              "f:/etc/issue.net -> r:Authorized uses only");
}

TEST(CheckConditionEvaluatorTest, PassedCheckHasNoReason)
{
    auto any = CheckConditionEvaluator::FromString("any");
    any.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "f:/etc/issue -> r:Authorized"));
    any.AddResult(RuleEvaluationResult(RuleResult::Found, "", "f:/etc/issue.net -> r:Authorized"));

    auto all = CheckConditionEvaluator::FromString("all");
    all.AddResult(RuleEvaluationResult(RuleResult::Found, "", "f:/etc/passwd"));

    auto none = CheckConditionEvaluator::FromString("none");
    none.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "p:telnetd"));

    for (const auto* evaluator :
            {
                &any, &all, &none
            })
    {
        EXPECT_EQ(evaluator->Result(), sca::CheckResult::Passed);
        EXPECT_EQ(evaluator->Reason(), "");
    }
}

TEST(CheckConditionEvaluatorTest, RepeatedFailingRuleIsListedOnce)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "c:sysctl net.ipv4.ip_forward -> r:= 0"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "c:sysctl net.ipv4.ip_forward -> r:= 0"));

    EXPECT_EQ(evaluator.Reason(),
              "Rules not satisfied (condition 'all'):\n"
              "c:sysctl net.ipv4.ip_forward -> r:= 0");
}

TEST(CheckConditionEvaluatorTest, FailedCheckReasonLeavesOutRulesThatCouldNotBeEvaluated)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(
                            RuleResult::Invalid, "File '/etc/aide/aide.conf' does not exist or is not a regular file", "f:/etc/aide/aide.conf -> r:^/boot"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "c:dpkg -s aide -> r:install ok installed"));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
    EXPECT_EQ(evaluator.Reason(),
              "Rules not satisfied (condition 'all'):\n"
              "c:dpkg -s aide -> r:install ok installed");
}

TEST(CheckConditionEvaluatorTest, RulesAfterTheVerdictLeaveTheUnresolvedReasonAlone)
{
    auto evaluator = CheckConditionEvaluator::FromString("all");

    evaluator.AddResult(RuleEvaluationResult(RuleResult::NotFound, "", "f:/etc/motd -> r:Authorized"));
    evaluator.AddResult(RuleEvaluationResult(RuleResult::Invalid, "Path '/etc/update-motd.d' does not exist", "d:/etc/update-motd.d"));

    EXPECT_EQ(evaluator.Result(), sca::CheckResult::Failed);
    EXPECT_EQ(evaluator.GetUnresolvedReason(), "");
}
