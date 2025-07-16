#pragma once

#include <sca_policy_check.hpp>
#include <sca_utils.hpp>

#include <optional>
#include <string>

enum class ConditionType
{
    All,
    Any,
    None
};

class CheckConditionEvaluator
{
public:
    static CheckConditionEvaluator FromString(const std::string& str);

    explicit CheckConditionEvaluator(ConditionType type);

    void AddResult(RuleResult result);

    sca::CheckResult Result() const;

private:
    ConditionType m_type;
    int m_totalRules {0};
    int m_passedRules {0};
    std::optional<bool> m_result;
    bool m_hasInvalid = false;
};
