#include <check_condition_evaluator.hpp>

#include <stdexcept>

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
    if (m_result.has_value())
    {
        return;
    }

    if (result.result == RuleResult::Invalid)
    {
        m_hasInvalid = true;

        if (!result.reason.empty())
        {
            if (!m_invalidReason.empty())
            {
                m_invalidReason += "\n";
            }

            m_invalidReason += result.reason;
        }
    }

    ++m_totalRules;
    m_passedRules += (RuleResult::Found == result.result) ? 1 : 0;

    switch (m_type)
    {
        case ConditionType::All:
            if (RuleResult::NotFound == result.result)
            {
                m_result = false;
            }

            break;

        case ConditionType::Any:
            if (RuleResult::Found == result.result)
            {
                m_result = true;
            }

            break;

        case ConditionType::None:
            if (RuleResult::Found == result.result)
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

std::string CheckConditionEvaluator::GetInvalidReason() const
{
    return m_invalidReason;
}
