/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * February 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGES_WINDOWS_PARSER_HELPER_H
#define _PACKAGES_WINDOWS_PARSER_HELPER_H

#include <cstdio>
#include <regex>
#include <vector>
#include "json.hpp"
#include "registryHelper.h"
#include "stringHelper.h"


namespace PackageWindowsHelper
{
    constexpr auto WIN_REG_HOTFIX {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"};
    constexpr auto VISTA_REG_HOTFIX {"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix"};
    constexpr auto WIN_REG_PRODUCT_HOTFIX {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products"};
    constexpr auto WIN_REG_WOW_HOTFIX {"SOFTWARE\\WOW6432Node\\Microsoft\\Updates"};

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

    static void getHotFixFromReg(const HKEY key, const std::string& subKey, std::set<std::string>& hotfixes)
    {
        try
        {
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
        }
        catch (...)
        {
        }
    }

    static void getHotFixFromRegNT(const HKEY key, const std::string& subKey, std::set<std::string>& hotfixes)
    {
        try
        {
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

        }
        catch (...)
        {
        }
    }

    static void getHotFixFromRegWOW(const HKEY key, const std::string& subKey, std::set<std::string>& hotfixes)
    {
        try
        {
            const auto callback
            {
                [&key, &subKey, &hotfixes](const std::string & packageKey)
                {
                    const auto callbackKey
                    {
                        [&key, &subKey, &packageKey, &hotfixes](const std::string & package)
                        {
                            auto hfValue { extractHFValue(package) };

                            if (!hfValue.empty())
                            {
                                hotfixes.insert(std::move(hfValue));
                            }
                        }
                    };
                    Utils::Registry packageReg{key, subKey + "\\" + packageKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
                    packageReg.enumerate(callbackKey);
                }
            };
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
            root.enumerate(callback);
        }
        catch (...)
        {
        }

    }

    static void getHotFixFromRegProduct(const HKEY key, const std::string& subKey, std::set<std::string>& hotfixes)
    {
        try
        {
            const auto callback
            {
                [&key, &subKey, &hotfixes](const std::string & packageKey)
                {
                    const auto callbackKey
                    {
                        [&key, &subKey, &packageKey, &hotfixes](const std::string & package)
                        {

                            if (Utils::startsWith(package, "InstallProperties"))
                            {

                                Utils::Registry packageReg{key, subKey + "\\" + packageKey + "\\" + package, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
                                std::string value;

                                if (packageReg.string("DisplayName", value))
                                {
                                    auto hfValue { extractHFValue(value) };

                                    if (!hfValue.empty())
                                    {
                                        hotfixes.insert(std::move(hfValue));
                                    }
                                }
                            }
                            else if (Utils::startsWith(package, "Patches"))
                            {
                                const auto callbackPatch
                                {
                                    [&key, &subKey, &packageKey, &package, &hotfixes](const std::string & packagePatch)
                                    {

                                        Utils::Registry packageReg{key, subKey + "\\" + packageKey + "\\" + package + "\\" + packagePatch, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
                                        std::string value;

                                        if (packageReg.string("DisplayName", value))
                                        {
                                            auto hfValue { extractHFValue(value) };

                                            if (!hfValue.empty())
                                            {
                                                hotfixes.insert(std::move(hfValue));
                                            }
                                        }
                                    }
                                };
                                Utils::Registry rootPatch{key, subKey + "\\" + packageKey + "\\" + package, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
                                rootPatch.enumerate(callbackPatch);

                            }
                        }
                    };
                    Utils::Registry rootKey{key, subKey + "\\" + packageKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
                    rootKey.enumerate(callbackKey);
                }
            };
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
            root.enumerate(callback);

        }
        catch (...)
        {
        }

    }

    /*
     * @brief Gets the product version published on the VERSIONINFO resource of a file.
     *
     * The resource is read as plain file data (no code from the target file is executed).
     *
     * @param[in] filePath Path of the file to read.
     *
     * @return Returns the product version, or an empty string if the file has no readable VERSIONINFO.
     */
    static std::string getProductVersion(const std::string& filePath)
    {
        std::string version;
        DWORD handle { 0 };
        const auto size { GetFileVersionInfoSizeA(filePath.c_str(), &handle) };

        if (size)
        {
            std::vector<unsigned char> buffer(size);

            if (GetFileVersionInfoA(filePath.c_str(), 0, size, buffer.data()))
            {
                struct LangCodePage
                {
                    unsigned short language;
                    unsigned short codePage;
                }* translation { nullptr };
                UINT length { 0 };

                if (VerQueryValueA(buffer.data(), "\\VarFileInfo\\Translation", reinterpret_cast<LPVOID*>(&translation), &length)
                        && translation && length >= sizeof(LangCodePage))
                {
                    char subBlock[64] {};
                    snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%04x%04x\\ProductVersion", translation->language, translation->codePage);
                    char* value { nullptr };
                    UINT valueLength { 0 };

                    if (VerQueryValueA(buffer.data(), subBlock, reinterpret_cast<LPVOID*>(&value), &valueLength) && value && valueLength)
                    {
                        version = Utils::trim(std::string(value), " \t");
                    }
                }
            }
        }

        return version;
    }
};

#endif // _PACKAGES_WINDOWS_PARSER_HELPER_H
