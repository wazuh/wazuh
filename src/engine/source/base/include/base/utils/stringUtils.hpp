// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _STRING_UTILS_H
#define _STRING_UTILS_H

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace base::utils::string
{

/**
 * @brief Split a string into a vector of strings
 *
 * @param str String to be split
 * @param delimiter Delimiter to split the string
 * @return std::vector<std::string>
 */
std::vector<std::string> split(std::string_view str, const char delimiter);

/**
 * @brief Concatenates all the strings of a vector, separated by `separator`.
 *
 * @param strVector Vector to concatenate
 * @param separator Concatenated between or also at the start
 * @param startsWithSeparator If true starts with separator
 * @return std::string Concatenation of the vector
 */
std::string join(const std::vector<std::string>& strVector,
                 std::string_view separator = "",
                 const bool startsWithSeparator = false);

/**
 * @brief Split a string in items defined by splitChar and allowing it to be escaped
 * by escape char.
 *
 * @param input String to be split
 * @param splitChar Char used to split the input string, '/' by default
 * @param escape Char used to escape the splitChar when needed, '\\' by default
 * @return std::vector<std::string>
 */
std::vector<std::string> splitEscaped(std::string_view input, const char& splitChar = '/', const char& escape = '\\');

using Delimeter = std::pair<char, bool>;

/**
 * @brief Split a string into a vector of strings
 *
 * @tparam Delim Expecting Pair (or any structure that implements Delim.first
 * and Delim.second as char and bool respectively) with delimiter char and a
 * boolean indicating if the delimiter should also be included in the result
 * @param input Input string
 * @param delimiters Delimiters to split the string
 * @return std::vector<std::string> Vector of strings
 */
template<typename... Delim>
std::vector<std::string> splitMulti(std::string_view input, Delim&&... delimiters)
{
    std::vector<std::string> splitted;
    for (auto i = 0, last = i; i < input.size(); ++i)
    {
        for (auto delimiter : {delimiters...})
        {
            if (input[i] == delimiter.first)
            {
                auto substr = input.substr(last, i - last);
                if (!substr.empty())
                {
                    splitted.push_back(std::string(substr));
                }

                if (delimiter.second)
                {
                    splitted.push_back({delimiter.first});
                }

                last = i + 1;
                break;
            }
        }
        if (i == input.size() - 1)
        {
            auto substr = input.substr(last);
            if (!substr.empty())
            {
                splitted.push_back(std::string(substr));
            }
        }
    }

    return splitted;
}

/**
 * @brief Check if a string starts with a given prefix
 *
 * @param str String to be checked
 * @param prefix Prefix to check against
 * @return true if the string starts with the prefix
 * @return false otherwise
 */
inline bool startsWith(std::string_view str, std::string_view prefix)
{
    return str.substr(0, prefix.size()) == prefix;
}

/**
 * @brief Check if a string endss with a given prefix
 *
 * @param str String to be checked
 * @param suffix suffix to check against
 * @return true if the string ends with the prefix
 * @return false otherwise
 */
inline bool endsWith(std::string_view str, std::string_view suffix)
{
    if (suffix.size() > str.size())
    {
        return false;
    }

    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/// Longest piece of caller input an error message repeats back.
inline constexpr std::size_t MAX_ECHOED_INPUT_LENGTH = 128;

/**
 * @brief Bound a caller-supplied value before an error message repeats it back.
 *
 * @param value The value taken from the caller.
 * @param maxLength Longest text kept (MAX_ECHOED_INPUT_LENGTH by default).
 * @return std::string The value itself when it fits, else its first characters followed by "... (<n> bytes)".
 */
inline std::string truncateForMessage(std::string_view value, std::size_t maxLength = MAX_ECHOED_INPUT_LENGTH)
{
    if (value.size() <= maxLength)
    {
        return std::string {value};
    }
    return std::string {value.substr(0, maxLength)} + "... (" + std::to_string(value.size()) + " bytes)";
}

/**
 * @brief Unescapes a string by removing escape characters and replacing escaped characters with their original values.
 *
 * If the escapeChar is not escaped is added to the result.
 * If the escapeChar is followed by a character that is not escapedChars is added to the result.
 * If the escapeChar is followed by escapeChar only one escapeChar is added to the result.
 * @param str The string to unescape.
 * @param escapeChar The character used to escape other characters.
 * @param escapedChars A string containing all characters that can be escaped.
 * @param strictMode If true an exception is thrown if an invalid escape sequence is found.
 * @return The unescaped string.
 * @todo: Add support for strict mode where an exception is thrown if an invalid escape sequence is found.
 */
std::string
unescapeString(std::string_view str, char escapeChar, const std::string& escapedChars, const bool strictMode = false);

inline std::string
unescapeString(std::string_view str, char escapeChar, const char escapedChar, const bool strictMode = false)
{
    return unescapeString(str, escapeChar, std::string(1, escapedChar), strictMode);
}

// TODO Add scape string with char. Implement on test handler location.

/**
 * @brief Convert a string to uppercase.
 *
 * @param str Input string.
 * @return std::string The uppercase version of the input.
 */
std::string toUpperCase(std::string_view str);

/**
 * @brief Convert a string to lowercase.
 *
 * @param str Input string.
 * @return std::string The lowercase version of the input.
 */
std::string toLowerCase(std::string_view str);

/**
 * @brief Replace the first occurrence of a substring.
 *
 * @param data String to modify in-place.
 * @param toSearch Substring to search for.
 * @param toReplace Replacement string.
 * @return true if a replacement was made.
 * @return false otherwise.
 */
bool replaceFirst(std::string& data, const std::string& toSearch, const std::string& toReplace);

/**
 * @brief Trim characters from the left side of a string.
 *
 * @param str Input string.
 * @param args Characters to trim (default: space).
 * @return std::string The left-trimmed string.
 */
std::string leftTrim(const std::string& str, const std::string& args = " ");

/**
 * @brief Trim characters from the right side of a string.
 *
 * @param str Input string.
 * @param args Characters to trim (default: space).
 * @return std::string The right-trimmed string.
 */
std::string rightTrim(const std::string& str, const std::string& args = " ");

/**
 * @brief Trim characters from both sides of a string.
 *
 * @param str Input string.
 * @param args Characters to trim (default: space).
 * @return std::string The trimmed string.
 */
std::string trim(const std::string& str, const std::string& args = " ");

/**
 * @brief Convert a string to sentence case (first letter uppercase, rest lowercase).
 *
 * @param str Input string.
 * @return std::string The sentence-cased string.
 */
std::string toSentenceCase(const std::string& str);

/**
 * @brief Check if a string represents a positive integer number
 *
 * @param str String to be checked
 * @return true if the string represents a positive integer number
 * @return false otherwise
 */
bool isNumber(const std::string& str);

/**
 * @brief Replace all occurrences of a substring.
 *
 * @param data String to modify in-place.
 * @param toSearch Substring to search for.
 * @param toReplace Replacement string.
 * @return true if at least one replacement was made.
 * @return false if no replacement was made or if toSearch is empty / equals toReplace / toReplace contains toSearch.
 */
bool replaceAll(std::string& data, const std::string_view toSearch, const std::string_view toReplace);

/**
 * @brief Check if a string contains any uppercase characters.
 *
 * @param str String to check.
 * @return true if the string has at least one uppercase character.
 * @return false otherwise.
 */
bool haveUpperCaseCharacters(const std::string& str);

/**
 * @brief Decode a string of hexadecimal digits (base 16) into an ASCII string.
 *
 * The input is valid when it has an even number of characters, every character is a hexadecimal digit
 * ([0-9A-Fa-f], either case) and every decoded byte is ASCII (0x00-0x7F). An empty input is valid and decodes to an
 * empty string. Signs, whitespace and a "0x" prefix are not accepted.
 *
 * @param hex String of hexadecimal digits, e.g. "48656C6C6F".
 * @return std::optional<std::string> The decoded string (e.g. "Hello"), or std::nullopt when the input is not valid.
 */
std::optional<std::string> hexToAscii(std::string_view hex);

/**
 * @brief Decode a string of hexadecimal digits (base 16) into a UTF-8 string.
 *
 * The input is valid when it has an even number of characters, every character is a hexadecimal digit and the decoded
 * bytes are well-formed UTF-8 (see isValidUtf8). An empty input is valid and decodes to an empty string. Signs,
 * whitespace and a "0x" prefix are not accepted.
 *
 * @param hex String of hexadecimal digits, e.g. "636166C3A9".
 * @param upperCaseOnly When true, only the digits [0-9A-F] are accepted (a lower-case letter makes the input invalid).
 * @return std::optional<std::string> The decoded string (e.g. "café"), or std::nullopt when the input is not valid.
 */
std::optional<std::string> hexToUtf8(std::string_view hex, bool upperCaseOnly = false);

/**
 * @brief Check whether a byte sequence is well-formed UTF-8 (RFC 3629).
 *
 * Overlong encodings, UTF-16 surrogates (U+D800-U+DFFF), code points above U+10FFFF and truncated sequences are
 * rejected. ASCII control bytes, including NUL, are valid.
 *
 * @param str Byte sequence to check.
 * @return true if every byte belongs to a well-formed UTF-8 sequence.
 */
bool isValidUtf8(std::string_view str);

} // namespace base::utils::string

#endif // _STRING_UTILS_H
