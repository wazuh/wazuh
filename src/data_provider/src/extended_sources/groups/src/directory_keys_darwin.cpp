/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <cctype>
#include <iterator>

#include "directory_keys_darwin.hpp"

static std::string mapChars(std::string value, int (*convert)(int))
{
    std::transform(value.begin(), value.end(), value.begin(), [convert](unsigned char c)
    {
        return convert(c);
    });
    return value;
}

static std::set<std::string> mapAll(const std::set<std::string>& values, std::string (*convert)(std::string))
{
    std::set<std::string> mapped;
    std::transform(values.begin(), values.end(), std::inserter(mapped, mapped.end()), convert);
    return mapped;
}

std::string DirectoryKeys::name(std::string accountName)
{
    return mapChars(std::move(accountName), ::tolower);
}

std::string DirectoryKeys::guid(std::string value)
{
    return mapChars(std::move(value), ::toupper);
}

std::set<std::string> DirectoryKeys::names(const std::set<std::string>& accountNames)
{
    return mapAll(accountNames, name);
}

std::set<std::string> DirectoryKeys::guids(const std::set<std::string>& values)
{
    return mapAll(values, guid);
}

std::map<std::string, std::string> DirectoryKeys::byName(const std::map<std::string, std::string>& valueByAccountName)
{
    std::map<std::string, std::string> folded;

    for (const auto& [accountName, value] : valueByAccountName)
    {
        folded[name(accountName)] = value;
    }

    return folded;
}
