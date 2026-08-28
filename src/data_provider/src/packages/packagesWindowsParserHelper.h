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

    /*
     * @brief Checks whether a version string is a bare numeric version (no build/hotfix qualifier).
     *
     * DisplayVersion values with no separator beyond dots are the ones an installer may have
     * under-reported relative to the executable's own VERSIONINFO resource, and are the only
     * ones worth spending a file read on to look for a more detailed version.
     *
     * @param[in] version Version string to check.
     *
     * @return Returns true if the version is composed of 2 to 4 dot-separated numeric components.
     */
    static bool isBareNumericVersion(const std::string& version)
    {
        static const std::regex bareVersionRegex{R"(^[0-9]+(\.[0-9]+){1,3}$)"};
        return std::regex_match(version, bareVersionRegex);
    }

    /*
     * @brief Resolves the executable path published on a package's DisplayIcon value.
     *
     * DisplayIcon commonly points at the package's main executable, optionally quoted and
     * followed by a ",<icon index>" suffix (e.g. "C:\App\app.exe",0). Paths pointing at
     * anything other than an executable (a shared system icon, a bare .ico file) are rejected,
     * since there is no VERSIONINFO resource to read from them.
     *
     * @param[in] displayIcon Raw DisplayIcon registry value.
     *
     * @return Returns the resolved executable path, or an empty string if none can be resolved.
     */
    static std::string resolveExecutablePath(std::string displayIcon)
    {
        if (displayIcon.empty())
        {
            return {};
        }

        if (displayIcon.front() == '"')
        {
            const auto closingQuote { displayIcon.find('"', 1) };
            displayIcon = displayIcon.substr(1, closingQuote == std::string::npos ? std::string::npos : closingQuote - 1);
        }
        else
        {
            // Unquoted "<path>,<icon index>" — only strip the suffix if it's actually numeric,
            // since an unquoted path could legitimately contain a comma.
            const auto comma { displayIcon.rfind(',') };

            if (comma != std::string::npos && displayIcon.find_first_not_of("-0123456789", comma + 1) == std::string::npos)
            {
                displayIcon = displayIcon.substr(0, comma);
            }
        }

        if (displayIcon.find('%') != std::string::npos)
        {
            char expanded[MAX_PATH] {};

            if (ExpandEnvironmentStringsA(displayIcon.c_str(), expanded, MAX_PATH))
            {
                displayIcon = expanded;
            }
        }

        return Utils::endsWith(Utils::toLowerCase(displayIcon), ".exe") ? displayIcon : std::string();
    }

    /*
     * @brief Checks whether a candidate version is a genuine refinement of a base version.
     *
     * A refinement must extend the base version with a separator, not just happen to share it
     * as a string prefix (e.g. "6.3.30" is not a refinement of "6.3.3"), so that an executable's
     * unrelated VERSIONINFO value is never mistaken for extra detail on the reported version.
     *
     * @param[in] baseVersion Version read from the package registry key.
     * @param[in] candidateVersion Version read from the executable's VERSIONINFO resource.
     *
     * @return Returns true if candidateVersion refines baseVersion.
     */
    static bool isVersionRefinement(const std::string& baseVersion, const std::string& candidateVersion)
    {
        if (candidateVersion.size() <= baseVersion.size()
                || candidateVersion.compare(0, baseVersion.size(), baseVersion) != 0)
        {
            return false;
        }

        const auto nextChar { candidateVersion[baseVersion.size()] };
        return nextChar == '-' || nextChar == '.' || nextChar == '+';
    }
};

#endif // _PACKAGES_WINDOWS_PARSER_HELPER_H
