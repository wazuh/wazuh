/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STRING_UTILS_H
#define _STRING_UTILS_H

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

} // namespace base::utils::string

#endif // _STRING_UTILS_H
