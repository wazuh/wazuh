#include <sca_utils.hpp>

// #include <logger.hpp>
#include <stringHelper.h>

#include <pcre2.h>

#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>

namespace
{
    std::pair<bool, std::string> Pcre2Match(const std::string& content, const std::string& pattern)
    {
        int errorCode = 0;
        PCRE2_SIZE error_offset = 0;

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto patternPtr = reinterpret_cast<PCRE2_SPTR8>(pattern.c_str());

        auto* re = pcre2_compile(
            patternPtr, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | PCRE2_CASELESS, &errorCode, &error_offset, nullptr);

        if (!re)
        {
            throw std::runtime_error(
                [&errorCode, &error_offset]()
                {
                    std::vector<PCRE2_UCHAR> buffer(256); // NOLINT(cppcoreguidelines-avoid-magic-numbers)
                    pcre2_get_error_message(errorCode, buffer.data(), buffer.size());

                    return "PCRE2 compilation failed at offset " + std::to_string(error_offset) + ": " +
                           // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                           reinterpret_cast<char*>(buffer.data());
                }());
        }

        auto* matchData = pcre2_match_data_create_from_pattern(re, nullptr);

        if (!matchData)
        {
            pcre2_code_free(re);
            throw std::runtime_error("PCRE2 match data creation failed");
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto contentPtr = reinterpret_cast<PCRE2_SPTR8>(content.c_str());
        const auto rc = pcre2_match(re, contentPtr, content.size(), 0, 0, matchData, nullptr);

        auto pcre2CleanUp = [matchData, re]()
        {
            pcre2_match_data_free(matchData);
            pcre2_code_free(re);
        };

        if (rc == PCRE2_ERROR_NOMATCH)
        {
            // No match, but not an error
            pcre2CleanUp();
            return {false, ""};
        }
        else if (rc < 0)
        {
            // Other matching error
            pcre2CleanUp();
            throw std::runtime_error("PCRE2 match error: " + std::to_string(rc));
        }

        const auto* ovector = pcre2_get_ovector_pointer(matchData);

        if (!ovector)
        {
            pcre2CleanUp();
            throw std::runtime_error("PCRE2 ovector pointer is null");
        }

        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const auto match = rc >= 2 ? content.substr(ovector[2], ovector[3] - ovector[2])
                                   : content.substr(ovector[0], ovector[1] - ovector[0]);
        // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        pcre2CleanUp();

        return {true, match};
        // return {true, ""};
    }

    bool
    EvaluateNumericRegexComparison(const std::string& content, const std::string& expr, sca::RegexEngineType engine)
    {
        std::string pattern, opStr, expectedValueStr;
        std::pair<bool, std::string> matchResult {false, ""};

        const std::string compareWord = "compare";
        const auto comparePos = expr.find(compareWord);
        if (comparePos == std::string::npos)
        {
            throw std::runtime_error("Invalid expression format, 'compare' keyword missing");
        }

        pattern = expr.substr(0, comparePos - 1);
        const auto remainder = expr.substr(comparePos + compareWord.size() + 1);

        std::istringstream remainderStream(remainder);
        remainderStream >> opStr >> expectedValueStr;

        if (opStr.empty() || expectedValueStr.empty())
        {
            throw std::runtime_error("Invalid operator or expected value in numeric comparison");
        }

        const int expectedValue = std::stoi(expectedValueStr);

        if (engine == sca::RegexEngineType::PCRE2)
        {
            matchResult = Pcre2Match(content, pattern);
        }

        if (!matchResult.first)
        {
            return false;
        }

        const int actualValue = std::stoi(matchResult.second);

        if (opStr == "<")
        {
            return actualValue < expectedValue;
        }
        if (opStr == "<=")
        {
            return actualValue <= expectedValue;
        }
        if (opStr == "==")
        {
            return actualValue == expectedValue;
        }
        if (opStr == "!=")
        {
            return actualValue != expectedValue;
        }
        if (opStr == ">=")
        {
            return actualValue >= expectedValue;
        }
        if (opStr == ">")
        {
            return actualValue > expectedValue;
        }

        throw std::runtime_error("Invalid operator in numeric comparison");
    }

    bool EvaluateMinterm(const std::string& minterm, const std::string& content, sca::RegexEngineType engine)
    {
        if (minterm.size() >= 2 && minterm.compare(0, 2, "r:") == 0)
        {
            const auto pattern = minterm.substr(2);
            if (engine == sca::RegexEngineType::PCRE2)
            {
            return Pcre2Match(content, pattern).first;
            }
        }
        else if (minterm.size() >= 2 && minterm.compare(0, 2, "n:") == 0)
        {
            const auto expression = minterm.substr(2);
            return EvaluateNumericRegexComparison(content, expression, engine);
        }
        else
        {
            return content == minterm;
        }

        return false;
    }

} // namespace

namespace sca
{
    std::string CheckResultToString(const CheckResult result)
    {
        switch (result)
        {
            case CheckResult::Passed: return "Passed";
            case CheckResult::Failed: return "Failed";
            case CheckResult::NotApplicable: return "Not applicable";
            case CheckResult::NotRun: return "Not run";
            default: return "Unknown";
        }
    }

    std::optional<std::pair<int, std::string>> ParseRuleType(const std::string& input)
    {
        const auto delimeterPos = input.find(':');

        if (delimeterPos == std::string::npos)
        {
            return std::nullopt;
        }

        auto key = input.substr(0, delimeterPos);
        const auto value = input.substr(delimeterPos + 1);

        if (!key.empty() && key.front() == '!')
        {
            key.erase(0, 1);
        }

        static const std::map<std::string, int> typeMap = {{"f", WM_SCA_TYPE_FILE},
                                                           {"r", WM_SCA_TYPE_REGISTRY},
                                                           {"p", WM_SCA_TYPE_PROCESS},
                                                           {"d", WM_SCA_TYPE_DIR},
                                                           {"c", WM_SCA_TYPE_COMMAND}};

        const auto it = typeMap.find(key);

        if (it == typeMap.end())
        {
            return std::nullopt;
        }

        return std::make_pair(it->second, value);
    }

    std::optional<std::string> GetPattern(const std::string& rule)
    {
        const std::string delimiter = " -> ";
        const auto pos = rule.find(delimiter);

        if (pos != std::string::npos)
        {
            return rule.substr(pos + delimiter.size());
        }

        return std::nullopt;
    }

    std::optional<bool> PatternMatches(const std::string& content, const std::string& pattern, RegexEngineType engine)
    {
        try
        {
            if (content.empty())
            {
                return false;
            }

            // Split the pattern into individual conditions (minterms)
            constexpr std::string_view delimiter = " && ";
            std::vector<std::pair<bool, std::string>> minterms; // (negated, pattern)

            size_t start = 0;

            // Loop over each minterm (subpattern) in the compound pattern
            while (start < pattern.size())
            {
                // Find the next delimiter and extract the substring for this minterm
                const auto end = pattern.find(delimiter, start);
                auto minterm = pattern.substr(start, end - start);

                // Advance the start position for the next iteration
                start = (end == std::string::npos) ? end : end + delimiter.length();

                // Check if the minterm is negated
                bool negated = false;
                if (!minterm.empty() && minterm[0] == '!')
                {
                    negated = true;
                    minterm.erase(0, 1); // Remove the '!' for pattern matching
                }

                minterms.emplace_back(negated, minterm);
            }

            // Special case: if there's only one minterm and it's negated
            if (minterms.size() == 1 && minterms[0].first)
            {
                const auto& minterm = minterms[0].second;
                std::istringstream stream(content);
                std::string line;
                while (std::getline(stream, line))
                {
                    if (EvaluateMinterm(minterm, line, engine))
                    {
                        return false; // A line matched the negated pattern → fail
                    }
                }
                return true; // No line matched the negated pattern → pass
            }

            // Regular compound pattern logic
            std::istringstream stream(content);
            std::string line;

            while (std::getline(stream, line))
            {
                bool allMintermsPassed = true;

                for (const auto& [negated, minterm] : minterms)
                {
                    const bool match = EvaluateMinterm(minterm, line, engine);
                    if ((negated && match) || (!negated && !match))
                    {
                        allMintermsPassed = false;
                        break;
                    }
                }

                if (allMintermsPassed)
                {
                    return true; // A line satisfied all minterms
                }
            }

            return false; // No line satisfied all minterms
        }
        catch (const std::exception& e)
        {
            // LogError("Exception '{}' was caught while evaluating pattern '{}'.", e.what(), pattern);
            return std::nullopt;
        }
    }

    bool IsRegexPattern(const std::string& pattern)
    {
        return (pattern.size() >= 2 && pattern.compare(0, 2, "r:") == 0) ||
               (pattern.size() >= 3 && pattern.compare(0, 3, "!r:") == 0);
    }

    bool IsRegexOrNumericPattern(const std::string& pattern)
    {
        return IsRegexPattern(pattern) ||
               (pattern.size() >= 2 && pattern.compare(0, 2, "n:") == 0) ||
               (pattern.size() >= 3 && pattern.compare(0, 3, "!n:") == 0);
    }

} // namespace sca
