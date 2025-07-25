#include <sca_policy_check.hpp>

#include <sca_utils.hpp>

#include <registryHelper.h>

#include <windows.h>

#include <stdexcept>
#include <system_error>

#include "logging_helper.hpp"
namespace
{
    std::pair<std::string, std::string> SplitRegistryKey(std::string_view fullKey)
    {
        if (fullKey.empty())
        {
            return {"", ""};
        }

        const size_t separator = fullKey.find('\\');

        if (separator == std::string_view::npos)
        {
            return {std::string(fullKey), ""};
        }
        return {std::string(fullKey.substr(0, separator)), std::string(fullKey.substr(separator + 1))};
    }

    // Checks if a registry key exists
    const RegistryRuleEvaluator::IsValidKeyFunc DEFAULT_IS_VALID_KEY = [](const std::string& rootKey) -> bool
    {
        try
        {
            const auto [key, subkey] = SplitRegistryKey(rootKey);
            return Utils::Registry::KeyExists(key, subkey);
        }
        catch (const std::system_error& e)
        {
            if (e.code().value() == ERROR_ACCESS_DENIED)
            {
                throw std::runtime_error("Access denied to registry key");
            }
            return false;
        }
        catch (const std::exception& e)
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, std::string("RegistryRuleEvaluator::IsValidKey: Exception: ") + e.what());
            return false;
        }
    };

    // Gets subkeys
    const RegistryRuleEvaluator::EnumKeysFunc DEFAULT_ENUM_KEYS =
        [](const std::string& root) -> std::vector<std::string>
    {
        try
        {
            const auto [key, path] = SplitRegistryKey(root);
            return Utils::Registry(key, path).enumerate();
        }
        catch (...)
        {
            return {};
        }
    };

    // Gets values from a key
    const RegistryRuleEvaluator::EnumValuesFunc DEFAULT_ENUM_VALUES =
        [](const std::string& root) -> std::vector<std::string>
    {
        try
        {
            const auto [key, path] = SplitRegistryKey(root);
            return Utils::Registry(key, path).enumerateValueKey();
        }
        catch (...)
        {
            return {};
        }
    };

    const RegistryRuleEvaluator::GetValueFunc DEFAULT_GET_VALUE =
        [](const std::string& root, const std::string& value) -> std::optional<std::string>
    {
        try
        {
            const auto [key, path] = SplitRegistryKey(root);
            return Utils::Registry(key, path).getValue(value);
        }
        catch (...)
        {
            return std::nullopt;
        }
    };

    bool CaseInsensitiveEqual(const std::string& a, const std::string& b)
    {
        return a.size() == b.size() && std::equal(a.begin(),
                                                  a.end(),
                                                  b.begin(),
                                                  [](char a, char b) {
                                                      return std::tolower(static_cast<unsigned char>(a)) ==
                                                             std::tolower(static_cast<unsigned char>(b));
                                                  });
    }

    RuleResult CheckMatch(const std::string& candidate, const std::string& pattern, bool isRegex)
    {
        if (isRegex)
        {
            const auto patternMatch = sca::PatternMatches(candidate, pattern);
            if (patternMatch.has_value() && patternMatch.value())
            {
                return RuleResult::Found;
            }
        }
        else if (CaseInsensitiveEqual(candidate, pattern))
        {
            return RuleResult::Found;
        }

        return RuleResult::NotFound;
    }
} // namespace

RegistryRuleEvaluator::RegistryRuleEvaluator(PolicyEvaluationContext ctx,
                                             IsValidKeyFunc isValidKey,
                                             EnumKeysFunc enumKeys,
                                             EnumValuesFunc enumValues,
                                             GetValueFunc getValue)
    : RuleEvaluator(std::move(ctx), nullptr)
    , m_isValidKey(isValidKey ? isValidKey : DEFAULT_IS_VALID_KEY)
    , m_enumKeys(enumKeys ? enumKeys : DEFAULT_ENUM_KEYS)
    , m_enumValues(enumValues ? enumValues : DEFAULT_ENUM_VALUES)
    , m_getValue(getValue ? getValue : DEFAULT_GET_VALUE)
{
}

RuleResult RegistryRuleEvaluator::Evaluate()
{
    if (m_ctx.pattern)
    {
        return CheckKeyForContents();
    }
    return CheckKeyExistence();
}

RuleResult RegistryRuleEvaluator::CheckKeyForContents()
{
    const auto pattern = *m_ctx.pattern; // NOLINT(bugprone-unchecked-optional-access)

    LoggingHelper::getInstance().log(LOG_DEBUG, std::string("Processing registry rule: ") + (m_ctx.isNegated ? "NOT " : "") + m_ctx.rule + " -> " + pattern);

    // First check that the key exists
    try
    {
        if (!m_isValidKey(m_ctx.rule))
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Key '{}' does not exist" + m_ctx.rule);
            return RuleResult::Invalid;
        }
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, std::string("RegistryRuleEvaluator::Evaluate: Exception: {}") + e.what());
        return RuleResult::Invalid;
    }

    auto result = RuleResult::NotFound;

    if (const auto content = sca::GetPattern(pattern))
    {
        const auto valueName = pattern.substr(0, m_ctx.pattern->find(" -> "));

        const auto obtainedValue = m_getValue(m_ctx.rule, valueName);

        // Check that the value exists
        if (!obtainedValue.has_value())
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Value '{}' does not exist" + valueName);
            return RuleResult::Invalid;
        }

        result = CheckMatch(obtainedValue.value(), content.value(), sca::IsRegexOrNumericPattern(content.value()));
    }
    else
    {
        // Will check for key or value existence
        const auto isRegex = sca::IsRegexPattern(pattern);

        for (const auto& key : m_enumKeys(m_ctx.rule))
        {
            if (CheckMatch(key, pattern, isRegex) == RuleResult::Found)
            {
                result = RuleResult::Found;
                LoggingHelper::getInstance().log(LOG_DEBUG, "Key '{}' exists" + pattern);
                break;
            }
        }

        if (result == RuleResult::NotFound)
        {
            for (const auto& value : m_enumValues(m_ctx.rule))
            {
                if (CheckMatch(value, pattern, isRegex) == RuleResult::Found)
                {
                    result = RuleResult::Found;
                    LoggingHelper::getInstance().log(LOG_DEBUG, "Value '{}' exists" + pattern);
                    break;
                }
            }
        }
    }

    const RuleResult retVal =
        m_ctx.isNegated ? (result == RuleResult::Found ? RuleResult::NotFound : RuleResult::Found) : result;

    LoggingHelper::getInstance().log(LOG_DEBUG, std::string("Registry rule evaluation ") + (retVal == RuleResult::Found ? "passed" : "failed"));
    return retVal;
}

RuleResult RegistryRuleEvaluator::CheckKeyExistence()
{
    auto result = RuleResult::NotFound;

    LoggingHelper::getInstance().log(LOG_DEBUG, std::string("Processing registry rule: ") + (m_ctx.isNegated ? "NOT " : "" + m_ctx.rule));

    try
    {
        if (!m_isValidKey(m_ctx.rule))
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, std::string("Key does not exist. Rule ") + (m_ctx.isNegated ? "passed" : "failed"));
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, std::string("Key exists.  Rule {}") + (m_ctx.isNegated ? "failed" : "passed"));
            result = RuleResult::Found;
        }
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, std::string("RegistryRuleEvaluator::Evaluate: Exception: ") + e.what());
        return RuleResult::Invalid;
    }

    return m_ctx.isNegated ? (result == RuleResult::Found ? RuleResult::NotFound : RuleResult::Found) : result;
}
