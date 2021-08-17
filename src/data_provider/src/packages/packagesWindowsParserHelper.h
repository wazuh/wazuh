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
    constexpr auto WIN_REG_HOTFIX {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"};
    constexpr auto VISTA_REG_HOTFIX {"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix"};

    static std::string extractHFValue(std::string input)
    {
        constexpr auto KB_FORMAT_REGEX_STR { "(KB+[0-9]{6,})"};
        static std::regex rex{KB_FORMAT_REGEX_STR};
        std::string ret;
        input = Utils::toUpperCase(input);
        std::smatch match;

        if (std::regex_search(input, match, rex))
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
            const auto callback
            {
                [&key, &subKey, &hotfixes](const std::string & package)
                {
                    if (Utils::startsWith(package, "Package_"))
                    {
                        auto hfValue { extractHFValue(package) };

                        if (!hfValue.empty())
                        {
                            hotfixes.insert(std::move(hfValue));
                        }
                        else if (package.find("RollupFix") != std::string::npos)
                        {
                            std::string value;
                            Utils::Registry packageReg{key, subKey + "\\" + package, KEY_WOW64_64KEY | KEY_READ};

                            if (packageReg.string("InstallLocation", value))
                            {
                                auto rollUpValue { extractHFValue(value) };

                                if (!rollUpValue.empty())
                                {
                                    hotfixes.insert(std::move(rollUpValue));
                                }
                            }
                        }
                    }
                }
            };
            root.enumerate(callback);

            for (auto& hotfix : hotfixes)
            {
                nlohmann::json hotfixValue;
                hotfixValue["hotfix"] = std::move(hotfix);
                data.push_back(std::move(hotfixValue));
            }
        }
        catch (...)
        {
        }
    }

    static void getHotFixFromRegNT(const HKEY key, const std::string& subKey, nlohmann::json& data)
    {
        try
        {
            std::set<std::string> hotfixes;
            const auto callback
            {
                [&key, &subKey, &hotfixes](const std::string & package)
                {
                    auto hfValue { extractHFValue(package) };

                    if (!hfValue.empty())
                    {
                        hotfixes.insert(std::move(hfValue));
                    }
                }
            };
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
            root.enumerate(callback);

            for (auto& hotfix : hotfixes)
            {
                nlohmann::json hotfixValue;
                hotfixValue["hotfix"] = std::move(hotfix);
                data.push_back(std::move(hotfixValue));
            }
        }
        catch (...)
        {
        }
    }
};

#endif // _PACKAGES_WINDOWS_PARSER_HELPER_H
