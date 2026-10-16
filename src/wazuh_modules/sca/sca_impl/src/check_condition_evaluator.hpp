#pragma once

#include <sca_policy_check.hpp>
#include <sca_utils.hpp>
#include <unique_lines.hpp>

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

        void AddResult(const RuleEvaluationResult& result);

        sca::CheckResult Result() const;
        std::string GetUnresolvedReason() const;

    private:
        /// @brief Notes a rule that could not be evaluated and keeps its reason.
        void RecordUnresolvedRule(const RuleEvaluationResult& result);

        /// @brief Settles the verdict when this rule decides it under the check's condition.
        void UpdateVerdict(RuleResult result);

        ConditionType m_type;
        int m_totalRules {0};
        std::optional<bool> m_result;
        bool m_hasInvalid = false;
        bool m_hasNotRun = false;

        /// Reasons from rules that didn't resolve to Found/NotFound, covering both
        /// Invalid (e.g. missing file, disabled commands) and NotRun (command timeout)
        /// cases.
        UniqueLines m_unresolvedReasons;
};
