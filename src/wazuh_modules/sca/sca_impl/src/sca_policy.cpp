#include <sca_policy.hpp>

#include <check_condition_evaluator.hpp>
#include <sca_utils.hpp>

#include "logging_helper.hpp"

#include <stringHelper.h>

namespace
{
    /// @brief The reason as a single log line, its line breaks written as "\n" like in JSON.
    std::string OnOneLine(std::string reason)
    {
        Utils::replaceAll(reason, "\n", "\\n");
        return reason;
    }
} // namespace

SCAPolicy::SCAPolicy(std::string id, Check requirements, std::vector<Check> checks)
    : m_id(std::move(id))
    , m_requirements(std::move(requirements))
    , m_checks(std::move(checks))
{
}

SCAPolicy::SCAPolicy(SCAPolicy&& other) noexcept
    : m_id(std::move(other.m_id))
    , m_requirements(std::move(other.m_requirements))
    , m_checks(std::move(other.m_checks))
    , m_keepRunning(other.m_keepRunning.load())
    , m_scanInProgress(other.m_scanInProgress.load())
{
}

void SCAPolicy::Run(std::function<void(const CheckResult&)> reportCheckResult)
{
    m_scanInProgress = true;
    Scan(reportCheckResult);
    m_scanInProgress = false;
}

void SCAPolicy::Scan(
    const std::function<void(const CheckResult&)>& reportCheckResult)
{
    auto requirementsOk = sca::CheckResult::Passed;
    std::string requirementsReason;

    if (!m_requirements.rules.empty())
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Starting Policy requirements evaluation for policy \"" + m_id + "\".");

        auto resultEvaluator = CheckConditionEvaluator::FromString(m_requirements.condition);

        for (const auto& rule : m_requirements.rules)
        {
            if (!m_keepRunning)
            {
                return;
            }

            const auto ruleResult = rule->Evaluate();
            resultEvaluator.AddResult(RuleEvaluationResult(ruleResult, rule->GetUnresolvedReason(), rule->GetContext().source));
        }

        requirementsOk = resultEvaluator.Result();

        if (requirementsOk == sca::CheckResult::NotRun || requirementsOk == sca::CheckResult::NotApplicable)
        {
            requirementsReason = resultEvaluator.GetUnresolvedReason();
        }

        LoggingHelper::getInstance().log(LOG_DEBUG, "Policy requirements evaluation completed for policy \"" + m_id + "\", result: " + sca::CheckResultToString(requirementsOk));
    }

    if (requirementsOk == sca::CheckResult::Passed)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Starting Policy checks evaluation for policy \"" + m_id + "\".");

        for (const auto& check : m_checks)
        {
            auto resultEvaluator = CheckConditionEvaluator::FromString(check.condition);

            for (const auto& rule : check.rules)
            {
                if (!m_keepRunning)
                {
                    return;
                }

                const auto ruleResult = rule->Evaluate();
                resultEvaluator.AddResult(RuleEvaluationResult(ruleResult, rule->GetUnresolvedReason(), rule->GetContext().source));
            }

            const auto result = resultEvaluator.Result();
            const auto reason = resultEvaluator.Reason();

            // NOLINTBEGIN(bugprone-unchecked-optional-access)
            LoggingHelper::getInstance().log(
                LOG_DEBUG,
                "Policy check \"" +
                check.id.value() +
                "\" evaluation completed for policy \"" +
                m_id +
                "\", result: " +
                sca::CheckResultToString(result) +
                (reason.empty() ? "" : ", reason: " + OnOneLine(reason))
            );

            reportCheckResult({m_id, check.id.value(), sca::CheckResultToString(result), reason});
            // NOLINTEND(bugprone-unchecked-optional-access)
        }

        LoggingHelper::getInstance().log(LOG_DEBUG, "Policy checks evaluation completed for policy \"" + m_id + "\"");
    }
    else if (requirementsOk == sca::CheckResult::NotRun)
    {
        // A requirement rule timed out — we can't determine whether the policy applies,
        // so don't overwrite the manager's last known state for any check in this policy.
        for (const auto& check : m_checks)
        {
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            reportCheckResult({m_id, check.id.value(), sca::CheckResultToString(sca::CheckResult::NotRun), requirementsReason});
        }
    }
    else
    {
        // Without this a policy whose requirements fail only shows its checks as not
        // applicable, and the reason is visible at debug level only. A requirement rule that
        // cannot be evaluated (an invalid rule) is not a failed one, so say which it was.
        if (requirementsOk == sca::CheckResult::NotApplicable)
        {
            LoggingHelper::getInstance().log(LOG_INFO,
                                             "Policy \"" + m_id + "\" skipped: its requirements could not be evaluated: " +
                                             requirementsReason);
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_INFO, "Policy \"" + m_id + "\" skipped: its requirements are not met.");
        }

        for (const auto& check : m_checks)
        {
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            reportCheckResult({m_id, check.id.value(), sca::CheckResultToString(sca::CheckResult::NotApplicable), "Policy requirements not met"});
        }
    }
}

void SCAPolicy::Stop()
{
    if (m_scanInProgress)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Aborting current scan for policy \"" + m_id + "\"");
    }

    m_keepRunning = false;
}
