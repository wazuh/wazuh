#include <check_condition_evaluator.hpp>

#include <stdexcept>

namespace
{
    std::string ConditionName(const ConditionType type)
    {
        switch (type)
        {
            case ConditionType::All:
                return "all";

            case ConditionType::Any:
                return "any";

            case ConditionType::None:
                return "none";
        }

        return {}; // LCOV_EXCL_LINE - unreachable
    }
} // namespace

CheckConditionEvaluator CheckConditionEvaluator::FromString(const std::string& str)
{
    if (str == "all")
    {
        return CheckConditionEvaluator {ConditionType::All};
    }

    if (str == "any")
    {
        return CheckConditionEvaluator {ConditionType::Any};
    }

    if (str == "none")
    {
        return CheckConditionEvaluator {ConditionType::None};
    }

    throw std::invalid_argument("Invalid condition type: " + str);
}

CheckConditionEvaluator::CheckConditionEvaluator(ConditionType type)
    : m_type {type}
{
}

void CheckConditionEvaluator::AddResult(const RuleEvaluationResult& result)
{
    // Every failing rule is listed, also those after the verdict is settled
    RecordFailingRule(result);

    if (m_result.has_value())
    {
        return;
    }

    RecordUnresolvedRule(result);
    ++m_totalRules;
    UpdateVerdict(result.result);
}

void CheckConditionEvaluator::RecordFailingRule(const RuleEvaluationResult& result)
{
    // A "none" check fails on what was found, the others on what was not
    const auto failing = (m_type == ConditionType::None) ? RuleResult::Found : RuleResult::NotFound;

    if (result.result == failing)
    {
        m_failingRules.Add(result.source);
    }
}

void CheckConditionEvaluator::RecordUnresolvedRule(const RuleEvaluationResult& result)
{
    if (result.result != RuleResult::Invalid && result.result != RuleResult::NotRun)
    {
        return;
    }

    m_hasInvalid = m_hasInvalid || (result.result == RuleResult::Invalid);
    m_hasNotRun = m_hasNotRun || (result.result == RuleResult::NotRun);
    m_unresolvedReasons.Add(result.reason);
}

void CheckConditionEvaluator::UpdateVerdict(const RuleResult result)
{
    switch (m_type)
    {
        case ConditionType::All:
            if (RuleResult::NotFound == result)
            {
                m_result = false;
            }

            break;

        case ConditionType::Any:
            if (RuleResult::Found == result)
            {
                m_result = true;
            }

            break;

        case ConditionType::None:
            if (RuleResult::Found == result)
            {
                m_result = false;
            }

            break;
    }
}

sca::CheckResult CheckConditionEvaluator::Result() const
{
    if (m_result.has_value())
    {
        return *m_result ? sca::CheckResult::Passed : sca::CheckResult::Failed;
    }

    if (m_hasNotRun)
    {
        return sca::CheckResult::NotRun;
    }

    if (m_totalRules == 0 || m_hasInvalid)
    {
        return sca::CheckResult::NotApplicable;
    }

    switch (m_type)
    {
        case ConditionType::All:
            return sca::CheckResult::Passed;

        case ConditionType::Any:
            return sca::CheckResult::Failed;

        case ConditionType::None:
            return sca::CheckResult::Passed;

        // LCOV_EXCL_START - UNREACHABLE
        default:
            throw std::runtime_error("Invalid condition type");
            // LCOV_EXCL_STOP
    }
}

std::string CheckConditionEvaluator::Reason() const
{
    const auto result = Result();

    if (result == sca::CheckResult::Failed)
    {
        return FailingRulesReason();
    }

    if (result == sca::CheckResult::NotApplicable || result == sca::CheckResult::NotRun)
    {
        return GetUnresolvedReason();
    }

    return {};
}

std::string CheckConditionEvaluator::FailingRulesReason() const
{
    if (m_failingRules.Empty())
    {
        return {};
    }

    const std::string verdict = (m_type == ConditionType::None) ? "Rules satisfied" : "Rules not satisfied";
    return verdict + " (condition '" + ConditionName(m_type) + "'):\n" + m_failingRules.Join();
}

std::string CheckConditionEvaluator::GetUnresolvedReason() const
{
    if (!m_unresolvedReasons.Empty())
    {
        return m_unresolvedReasons.Join();
    }

    if (m_totalRules == 0)
    {
        return "None of the check's rules could be evaluated on this system";
    }

    if (m_hasInvalid || m_hasNotRun)
    {
        return "Unknown reason";
    }

    return {};
}
