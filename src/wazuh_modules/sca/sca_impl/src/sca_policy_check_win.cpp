#include <sca_policy_check.hpp>

#include <sca_utils.hpp>

#include <registryHelper.h>

#include <windows.h>

#include <array>
#include <stdexcept>
#include <system_error>

#include "logging_helper.hpp"

namespace sca::win
{
    // ExpandEnvironmentStringsA leaves unknown "%VAR%" tokens in place
    std::string ExpandEnvironmentVariables(const std::string& input)
    {
        const auto requiredSize = ExpandEnvironmentStringsA(input.c_str(), nullptr, 0);

        if (requiredSize == 0)
        {
            LoggingHelper::getInstance().log(
                LOG_DEBUG,
                "Error while getting length of expanded path in SCA rule: '" + input + "'");
            return input;
        }

        std::string expanded(requiredSize, '\0');
        const auto writtenSize = ExpandEnvironmentStringsA(input.c_str(), expanded.data(), requiredSize);

        if (writtenSize == 0 || writtenSize > requiredSize)
        {
            LoggingHelper::getInstance().log(
                LOG_DEBUG,
                "Error while getting expanded path in SCA rule: '" + input + "'");
            return input;
        }

        // ExpandEnvironmentStringsA returns the length including the
        // terminating null character
        expanded.resize(writtenSize - 1);
        return expanded;
    }
}

// LCOV_EXCL_START
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

    // Registry access rights for a read in the given view. Without an explicit view flag, WOW64
    // redirects the 32-bit agent to WOW6432Node for most of HKLM\SOFTWARE.
    REGSAM ReadAccess(const RegistryView view)
    {
        return KEY_READ | (view == RegistryView::Bits64 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY);
    }

    // Checks if a registry key exists
    const RegistryRuleEvaluator::IsValidKeyFunc DEFAULT_IS_VALID_KEY =
        [](const std::string& rootKey, const RegistryView view) -> bool
    {
        try
        {
            const auto [key, subkey] = SplitRegistryKey(rootKey);
            return Utils::Registry::KeyExists(key, subkey, ReadAccess(view));
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
        [](const std::string& root, const RegistryView view) -> std::vector<std::string>
    {
        try
        {
            const auto [key, path] = SplitRegistryKey(root);
            return Utils::Registry(key, path, ReadAccess(view)).enumerate();
        }
        catch (...)
        {
            return {};
        }
    };

    // Gets values from a key
    const RegistryRuleEvaluator::EnumValuesFunc DEFAULT_ENUM_VALUES =
        [](const std::string& root, const RegistryView view) -> std::vector<std::string>
    {
        try
        {
            const auto [key, path] = SplitRegistryKey(root);
            return Utils::Registry(key, path, ReadAccess(view)).enumerateValueKey();
        }
        catch (...)
        {
            return {};
        }
    };

    const RegistryRuleEvaluator::GetValueFunc DEFAULT_GET_VALUE =
        [](const std::string& root, const std::string& value, const RegistryView view) -> std::optional<std::string>
    {
        try
        {
            const auto [key, path] = SplitRegistryKey(root);
            return Utils::Registry(key, path, ReadAccess(view)).getValue(value);
        }
        catch (...)
        {
            return std::nullopt;
        }
    };

    // The 64-bit view is the native one on 64-bit Windows, so it is looked up first
    constexpr std::array<RegistryView, 2> VIEWS_IN_LOOKUP_ORDER {RegistryView::Bits64, RegistryView::Bits32};

    std::string ViewName(const RegistryView view)
    {
        return view == RegistryView::Bits64 ? "64-bit" : "32-bit";
    }

    bool CaseInsensitiveEqual(const std::string& a, const std::string& b)
    {
        return a.size() == b.size() && std::equal(a.begin(),
                                                  a.end(),
                                                  b.begin(),
                                                  [](char str_a, char str_b)
        {
            return std::tolower(static_cast<unsigned char>(str_a)) ==
                   std::tolower(static_cast<unsigned char>(str_b));
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
// LCOV_EXCL_STOP

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
    LoggingHelper::getInstance().log(LOG_DEBUG,
                                     std::string("Processing registry rule: ") + (m_ctx.isNegated ? "NOT " : "") + m_ctx.rule +
                                     (m_ctx.pattern ? " -> " + *m_ctx.pattern : ""));

    // Look in the 64-bit view first and fall back to the 32-bit one, so a key is found wherever it
    // lives. Combining is done before negating: a negated rule must fail if either view matches.
    auto combined = RuleResult::NotFound;
    auto allInvalid = true;
    std::string invalidReason;
    auto invalidReasonHasKey = false;

    for (const auto view : VIEWS_IN_LOOKUP_ORDER)
    {
        // A previous evaluation of this rule must not explain this one
        m_lastUnresolvedReason.clear();
        m_lastKeyExists = false;

        const auto result = m_ctx.pattern ? CheckKeyForContents(view) : CheckKeyExistence(view);

        if (result == RuleResult::Found)
        {
            combined = RuleResult::Found;
            allInvalid = false;
            break;
        }

        if (result != RuleResult::Invalid)
        {
            allInvalid = false;
        }
        // A view where the key exists explains the failure better (missing value, unsupported type)
        // than a view where the key itself is missing, e.g. a key present only in WOW6432Node.
        else if (invalidReason.empty() || (m_lastKeyExists && !invalidReasonHasKey))
        {
            invalidReason = m_lastUnresolvedReason;
            invalidReasonHasKey = m_lastKeyExists;
        }
    }

    if (allInvalid)
    {
        m_lastUnresolvedReason = invalidReason;
        LoggingHelper::getInstance().log(LOG_DEBUG, "Registry rule could not be evaluated in any registry view");
        return RuleResult::Invalid;
    }

    m_lastUnresolvedReason.clear();

    const RuleResult retVal =
        m_ctx.isNegated ? (combined == RuleResult::Found ? RuleResult::NotFound : RuleResult::Found) : combined;

    LoggingHelper::getInstance().log(LOG_DEBUG, std::string("Registry rule evaluation ") + (retVal == RuleResult::Found ? "passed" : "failed"));
    return retVal;
}

RuleResult RegistryRuleEvaluator::CheckKeyForContents(const RegistryView view)
{
    const auto pattern = *m_ctx.pattern; // NOLINT(bugprone-unchecked-optional-access)

    // First check that the key exists
    try
    {
        if (!m_isValidKey(m_ctx.rule, view))
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Key '" + m_ctx.rule + "' does not exist in the " + ViewName(view) + " registry view");
            m_lastUnresolvedReason = "Registry key '" + m_ctx.rule + "' does not exist";
            return RuleResult::Invalid;
        }
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, std::string("RegistryRuleEvaluator::Evaluate: Exception: ") + e.what());
        m_lastUnresolvedReason = "Exception accessing registry key '" + m_ctx.rule + "': " + e.what();
        return RuleResult::Invalid;
    }

    m_lastKeyExists = true;
    auto result = RuleResult::NotFound;

    if (const auto content = sca::GetPattern(pattern))
    {
        const auto valueName = pattern.substr(0, m_ctx.pattern->find(" -> "));

        const auto obtainedValue = m_getValue(m_ctx.rule, valueName, view);

        // Check that the value exists
        if (!obtainedValue.has_value())
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Value '" + valueName + "' does not exist in the " + ViewName(view) + " registry view");
            m_lastUnresolvedReason = "Registry value '" + valueName + "' does not exist in key '" + m_ctx.rule + "'";
            return RuleResult::Invalid;
        }

        result = CheckMatch(obtainedValue.value(), content.value(), sca::IsRegexOrNumericPattern(content.value()));
    }
    else
    {
        // Will check for key or value existence
        const auto isRegex = sca::IsRegexPattern(pattern);

        for (const auto& key : m_enumKeys(m_ctx.rule, view))
        {
            if (CheckMatch(key, pattern, isRegex) == RuleResult::Found)
            {
                result = RuleResult::Found;
                LoggingHelper::getInstance().log(LOG_DEBUG, "Key '" + pattern + "' exists");
                break;
            }
        }

        if (result == RuleResult::NotFound)
        {
            for (const auto& value : m_enumValues(m_ctx.rule, view))
            {
                if (CheckMatch(value, pattern, isRegex) == RuleResult::Found)
                {
                    result = RuleResult::Found;
                    LoggingHelper::getInstance().log(LOG_DEBUG, "Value '" + pattern + "' exists");
                    break;
                }
            }
        }
    }

    return result;
}

RuleResult RegistryRuleEvaluator::CheckKeyExistence(const RegistryView view)
{
    try
    {
        if (m_isValidKey(m_ctx.rule, view))
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Key exists in the " + ViewName(view) + " registry view");
            return RuleResult::Found;
        }

        LoggingHelper::getInstance().log(LOG_DEBUG, "Key does not exist in the " + ViewName(view) + " registry view");
        return RuleResult::NotFound;
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, std::string("RegistryRuleEvaluator::Evaluate: Exception: ") + e.what());
        m_lastUnresolvedReason = "Exception checking registry key existence '" + m_ctx.rule + "': " + e.what();
        return RuleResult::Invalid;
    }
}
