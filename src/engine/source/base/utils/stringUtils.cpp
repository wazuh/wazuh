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

std::string join(const std::vector<std::string>& strVector, std::string_view separator, const bool startsWithSeparator)
{
    std::string strResult {};
    for (std::size_t i = 0; i < strVector.size(); ++i)
    {
        strResult.append((!startsWithSeparator && 0 == i) ? "" : separator);
        strResult.append(strVector.at(i));
    }

    return strResult;
}

std::vector<std::string> splitEscaped(std::string_view input, const char& splitChar, const char& escape)
{
    std::vector<std::string> splitted;
    // Add first segment
    splitted.push_back("");

    auto i = 0;
    for (; i < input.size() - 1; ++i)
    {
        auto thisChar = input.at(i);
        if (thisChar == escape)
        {
            auto nextChar = input.at(i+1);
            // Escape char
            if (nextChar == escape || nextChar == splitChar)
            {
                splitted.back() += nextChar;
                ++i;
            }
            else
            {
                splitted.back() += thisChar;
            }
        }
        else if (thisChar == splitChar)
        {
            // Add another segment
            splitted.push_back("");
        }
        else
        {
            splitted.back() += thisChar;
        }
    }

    // Handle last character
    if ((i == input.size() - 1) && input.at(i) != splitChar)
    {
        splitted.back() += input.at(i);
    }

    return splitted;
}

} // namespace utils::string
