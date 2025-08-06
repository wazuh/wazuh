#pragma once

#include <optional>
#include <string>
#include <vector>

namespace sca
{
    /// @brief Types of supported regex engines.
    enum class RegexEngineType
    {
        PCRE2,
        Invalid
    };

    /// @brief Types of supported rules.
    enum WM_SCA_TYPE
    {
        WM_SCA_TYPE_FILE,
        WM_SCA_TYPE_REGISTRY,
        WM_SCA_TYPE_PROCESS,
        WM_SCA_TYPE_DIR,
        WM_SCA_TYPE_COMMAND
    };

    /// @brief Types of supported check results.
    enum class CheckResult
    {
        Passed,
        Failed,
        NotApplicable,
        NotRun
    };

    /// @brief Structure to pass policy data.
    struct PolicyData
    {
        std::string path;
        bool isEnabled;
        bool isRemote;
    };

    /// @brief Converts a CheckResult enum value to its string representation.
    /// @param result The CheckResult enum value to convert.
    /// @return The string representation of the CheckResult enum value.
    std::string CheckResultToString(const CheckResult result);

    /// @brief Parses the rule type from the input string.
    /// @param input The input string to parse.
    /// @return An optional pair containing the rule type and its string representation if successful.
    std::optional<std::pair<int, std::string>> ParseRuleType(const std::string& input);

    /// @brief Retrieves the pattern from the rule string.
    /// @param rule The rule string to extract the pattern from.
    /// @return An optional string containing the extracted pattern if successful.
    /// @details The pattern to be returned is everything to the right of the first " -> "
    std::optional<std::string> GetPattern(const std::string& rule);

    /// @brief Checks if the content matches the given pattern using the specified regex engine.
    /// @param content The content to check against the pattern.
    /// @param pattern The pattern to match.
    /// @param engine The regex engine to use for matching.
    /// @return An optional boolean indicating if the content matches the pattern.
    std::optional<bool> PatternMatches(const std::string& content,
                                       const std::string& pattern,
                                       RegexEngineType engine = RegexEngineType::PCRE2);

    /// @brief Checks if the given pattern is a regex pattern.
    /// @param pattern The pattern to check.
    /// @return True if the pattern is a regex pattern, false otherwise.
    bool IsRegexPattern(const std::string& pattern);

    /// @brief Checks if the given pattern is a regex pattern or a numeric pattern.
    /// @param pattern The pattern to check.
    /// @return True if the pattern is a regex pattern or a numeric pattern, false otherwise.
    bool IsRegexOrNumericPattern(const std::string& pattern);
} // namespace sca
