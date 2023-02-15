/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stringUtils.hpp"

namespace utils::string
{

std::vector<std::string> split(std::string_view str, const char delimiter)
{
    std::vector<std::string> ret;
    while (true)
    {
        auto pos = str.find(delimiter);
        if (pos == str.npos)
        {
            break;
        }
        ret.emplace_back(str.substr(0, pos));
        str = str.substr(pos + 1);
    }

    if (!str.empty())
    {
        ret.emplace_back(str);
    }

    return ret;
}

std::string join(const std::vector<std::string>& strVector,
                 std::string_view separator,
                 const bool startsWithSeparator)
{
    std::string strResult {};
    for (std::size_t i = 0; i < strVector.size(); ++i)
    {
        strResult.append((!startsWithSeparator && 0 == i) ? "" : separator);
        strResult.append(strVector.at(i));
    }

    return strResult;
}

std::vector<std::string>
splitEscaped(std::string_view input, const char& splitChar, const char& escape)
{
    std::vector<std::string> splitted;

    // Replace escaped chars in between sections
    const auto removeOnlyEscapedSplitted =
        [](std::string& auxSubStr, const char& escape, const char& splitChar)
    {
        for (auto j = auxSubStr.find(escape, 0); j != std::string::npos;
             j = auxSubStr.find(escape, j))
        {
            if (auxSubStr.at(j+1) == splitChar)
            {
                auxSubStr.erase(j, 1);
                j++;
            }
            else
            {
                // If not escaping splitChar then fail
                return false;
            }
        }
        return true;
    };

    // Check if last char is escaped
    const auto endingEscaped = [](std::string_view& vs, const char& escape)
    {
        std::string auxSubStr {vs.data(), vs.size()};
        auto j = auxSubStr.rfind(escape);
        if (std::string::npos != j)
        {
            return (j == auxSubStr.size() - 1);
        }
        return false;
    };

    for (auto i = 0, last = i; i < input.size(); ++i)
    {
        // Ending section
        if (input.size() - 1 == i)
        {
            auto substr = input.substr(last);
            // Workaround to fix last segment empty
            if (substr.size() == 1 && (substr.at(substr.size() - 1) == splitChar))
            {
                substr = "";
            }
            splitted.push_back(std::string(substr));
            break;
        }

        if (splitChar == input[i])
        {
            auto substr = input.substr(last, i - last);
            // Check if substr last char is escaped, if so continue
            if (endingEscaped(substr, escape))
            {
                continue;
            }
            else
            {
                // If not then ending in escaped then split
                splitted.push_back(std::string(substr));
                last = i + 1;
            }
        }
    }

    // Apply escaped in each item and return empty array when error
    for (auto& item : splitted)
    {
        if(!removeOnlyEscapedSplitted(item, escape, splitChar))
        {
            return {};
        }
    }

    return splitted;
}

} // namespace utils::string
