/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once
#include <string>
#include <sstream>

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
            pos = data.find(toSearch, pos + toReplace.size());
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
}