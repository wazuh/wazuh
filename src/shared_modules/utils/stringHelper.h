/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STRING_HELPER_H
#define _STRING_HELPER_H

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static bool replaceAll(std::string& data,
                           const std::string& toSearch,
                           const std::string& toReplace)
    {
        auto pos { data.find(toSearch) };
        const auto ret{ std::string::npos != pos };
        while (std::string::npos != pos)
        {
            data.replace(pos, toSearch.size(), toReplace);
            pos = data.find(toSearch, pos);
        }
        return ret;
    }

    static bool replaceFirst(std::string& data,
                             const std::string& toSearch,
                             const std::string& toReplace)
    {
        auto pos { data.find(toSearch) };
        auto ret { false };
        if (std::string::npos != pos)
        {
            data.replace(pos, toSearch.size(), toReplace);
            ret = true;
        }
        return ret;
    }

    static std::vector<std::string> split(const std::string& str,
                                          const char delimiter)
    {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream{ str };
        while (std::getline(tokenStream, token, delimiter))
        {
            tokens.push_back(token);
        }
        return tokens;
    }

    static std::string splitIndex(const std::string& str,
                                  const char delimiter,
                                  const size_t index)
    {
        std::string retVal;
        const auto& splitResult { split(str, delimiter) };

        if(index < splitResult.size())
        {
            retVal = splitResult.at(index);
        }
        else
        {
            throw std::runtime_error("Invalid index to get values.");
        }
        return retVal;
    }

    static std::vector<std::string> splitNullTerminatedStrings(const char* buffer)
    {
        constexpr auto NULL_TERMINATED_DELIMITER {'\0'};
        std::vector<std::string> ret;
        while(buffer[0] != NULL_TERMINATED_DELIMITER)
        {
            const std::string token(buffer);
            if (!token.empty())
            {
                ret.push_back(token);
            }
            buffer += token.size() + 1;
        }
        return ret;
    }

    static std::string asciiToHex(const std::vector<unsigned char>& asciiData)
    {
        std::string ret;
        std::stringstream ss;
        for (const auto& val : asciiData)
        {
            ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(val);
        }
        if (ss.good())
        {
            ret = ss.str();
        }
        // LCOV_EXCL_START
        else
        {
            const auto size{asciiData.size() * 2};
            const auto buffer{std::make_unique<char[]>(size + 1)};
            char* output{buffer.get()};
            for (const auto& value : asciiData)
            {
                snprintf(output, 3, "%02x", value);
                output += 2;
            }
            ret = std::string{buffer.get(), size};
        }
        // LCOV_EXCL_STOP
        return ret;
    }

    static std::string leftTrim(const std::string& str, const std::string& args = " ")
    {
        const auto pos{ str.find_first_not_of(args) };
        if (pos != std::string::npos)
        {
            return str.substr(pos);
        }
        return str;
    }

    static std::string rightTrim(const std::string& str, const std::string& args = " ")
    {
        const auto pos{ str.find_last_not_of(args) };
        if (pos != std::string::npos)
        {
            return str.substr(0, pos + 1);
        }
        return str;
    }

    static std::string trim(const std::string& str, const std::string& args = " ")
    {
        return leftTrim(rightTrim(str, args), args);
    }

    static std::string toUpperCase(const std::string& str)
    {
        std::string temp{ str };
        std::transform(std::begin(temp),
                       std::end(temp),
                       std::begin(temp),
                       [](std::string::value_type character) { return std::toupper(character); });
        return temp;
    }

    static bool startsWith(const std::string& str, const std::string& start)
    {
        if (!str.empty() && str.length() >= start.length())
        {
            return str.compare(0, start.length(), start) == 0;
        }
        return false;
    }

    static bool endsWith(const std::string& str, const std::string& ending)
    {
        if (!str.empty() && str.length() >= ending.length())
        {
            const auto endLength{ ending.length()};
            const auto token{ str.substr(str.length() - endLength, endLength) };
            return token == ending;
        }
        return false;
    }

    static std::string substrOnFirstOccurrence(const std::string& str, const std::string& args = " ")
    {
        const auto pos{ str.find(args) };
        if (pos != std::string::npos)
        {
            return str.substr(0, pos);
        }
        return str;
    }
}

#pragma GCC diagnostic pop

#endif // _STRING_HELPER_H