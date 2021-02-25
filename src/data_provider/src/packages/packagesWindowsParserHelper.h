/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGES_WINDOWS_PARSER_HELPER_H
#define _PACKAGES_WINDOWS_PARSER_HELPER_H

#include <regex>
#include "json.hpp"
#include "registryHelper.h"
#include "stringHelper.h"


namespace PackageWindowsHelper
{
    constexpr auto WIN_REG_HOTFIX{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"};
    constexpr auto VISTA_REG_HOTFIX{"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix"};

    static std::string extractHFValue(std::string input)
    {
        constexpr auto KB_FORMAT_REGEX_STR { "(KB+[0-9]{6,})"};
        std::string ret;
        input = Utils::toUpperCase(input);
        std::smatch match;
        if (std::regex_search(input, match, std::regex(KB_FORMAT_REGEX_STR)))
        {
            // KB format is correct
            ret = match[1];
        }
        return ret;
    }

    static void getHotFixFromReg(const HKEY key, const std::string& subKey, nlohmann::json& data)
    {
        try
        {
            std::set<std::string> hotfixes;
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
            const auto packages{root.enumerate()};
            for (const auto& package : packages)
            {
                if (Utils::startsWith(package, "Package_"))
                {
                    std::string value;
                    Utils::Registry packageReg{key, subKey + "\\" + package, KEY_WOW64_64KEY | KEY_READ};
                    if (packageReg.string("InstallLocation", value))
                    {
                        const auto hfValue { extractHFValue(value) };
                        if (!hfValue.empty())
                        {
                            hotfixes.insert(hfValue);
                        }
                    }
                }
            }
            for (const auto& hotfix : hotfixes)
            {
                nlohmann::json hotfixValue;
                hotfixValue["hotfix"] = hotfix;
                data.push_back(hotfixValue);
            }
        }
        catch(...)
        {
        }
    }

    static void getHotFixFromRegNT(const HKEY key, const std::string& subKey, nlohmann::json& data)
    {
        static const std::string KB_PREFIX{"KB"};
        static const auto KB_PREFIX_SIZE{KB_PREFIX.size()};
        try
        {
            std::set<std::string> hotfixes;
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
            const auto packages{root.enumerate()};
            for (const auto& package : packages)
            {
                auto value{Utils::toUpperCase(package)};
                if (Utils::startsWith(value, KB_PREFIX))
                {
                    value = value.substr(KB_PREFIX_SIZE);
                    value = Utils::trim(value.substr(0, value.find_first_not_of("1234567890")));
                    hotfixes.insert(KB_PREFIX + value);
                }
            }
            for (const auto& hotfix : hotfixes)
            {
                data.push_back({{"hotfix", hotfix}});
            }
        }
        catch(...)
        {
        }
    }
};

#endif // _PACKAGES_WINDOWS_PARSER_HELPER_H