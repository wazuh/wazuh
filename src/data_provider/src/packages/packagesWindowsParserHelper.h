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
#include <functional>
#include <map>
#include <memory>
#include <regex>
#include <set>
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

    // CBS CurrentState values whose payload is on the system: superseded (replaced by a newer
    // package), partially installed, installed and permanent. Staged, pending and absent packages
    // are not installed.
    constexpr DWORD CBS_STATE_ABSENT {0x00};
    constexpr DWORD CBS_STATE_UNINSTALL_PENDING {0x05};
    constexpr DWORD CBS_STATE_SUPERSEDED {0x50};
    constexpr DWORD CBS_STATE_PARTIALLY_INSTALLED {0x65};
    constexpr DWORD CBS_STATE_INSTALLED {0x70};
    constexpr DWORD CBS_STATE_PERMANENT {0x80};

    static bool isCbsPackageInstalled(const DWORD currentState)
    {
        return currentState == CBS_STATE_SUPERSEDED ||
               currentState == CBS_STATE_PARTIALLY_INSTALLED ||
               currentState == CBS_STATE_INSTALLED ||
               currentState == CBS_STATE_PERMANENT;
    }

    // True while the payload of the package runs on the system: installed, or uninstalled but
    // waiting for a reboot.
    static bool isCbsPackageApplied(const DWORD currentState)
    {
        return isCbsPackageInstalled(currentState) || currentState == CBS_STATE_UNINSTALL_PENDING;
    }

    // KB of a CBS package named after a KB, or of a RollupFix (taken from its InstallLocation).
    struct CbsPackage
    {
        std::string hotfix;
        DWORD state {0};
        bool rollup {false};
    };

    // State of the CBS packages of one KB.
    struct CbsHotfixState
    {
        bool applied {false};           // Any of its packages is applied.
        bool rollup {false};            // It has a RollupFix package.
        bool rollupApplied {false};     // Any of its RollupFix packages is applied.
    };

    // Empty KB for other packages and for packages without a CurrentState.
    static CbsPackage getCbsPackageHotfix(const std::string& package,
                                          const std::function<bool(DWORD&)>& readCurrentState,
                                          const std::function<bool(std::string&)>& readInstallLocation)
    {
        if (!Utils::startsWith(package, "Package_"))
        {
            return {};
        }

        auto hfValue { extractHFValue(package) };
        const bool isRollup = hfValue.empty() && package.find("RollupFix") != std::string::npos;

        if (hfValue.empty() && !isRollup)
        {
            return {};
        }

        DWORD currentState {0};

        if (!readCurrentState(currentState))
        {
            return {};
        }

        if (isRollup)
        {
            std::string value;
            hfValue = readInstallLocation(value) ? extractHFValue(value) : std::string {};
        }

        return {hfValue, currentState, isRollup};
    }

    // Absent packages (optional parts never installed) say nothing about the KB, so they are skipped.
    static void addCbsPackageState(std::map<std::string, CbsHotfixState>& states, const CbsPackage& package)
    {
        if (!package.hotfix.empty() && package.state != CBS_STATE_ABSENT)
        {
            auto& state {states[package.hotfix]};
            const bool applied {isCbsPackageApplied(package.state)};
            state.applied = state.applied || applied;
            state.rollup = state.rollup || package.rollup;
            state.rollupApplied = state.rollupApplied || (package.rollup && applied);
        }
    }

    // State of every KB with a CBS package under the given key.
    static std::map<std::string, CbsHotfixState> getCbsHotfixStates(const HKEY key, const std::string& subKey)
    {
        std::map<std::string, CbsHotfixState> states;

        try
        {
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
            const auto callback
            {
                [&key, &subKey, &states](const std::string & package)
                {
                    // One unreadable package must not end the enumeration of the others.
                    try
                    {
                        std::unique_ptr<Utils::Registry> packageReg;
                        const auto openPackage
                        {
                            [&]() -> Utils::Registry&
                            {
                                if (!packageReg)
                                {
                                    packageReg = std::make_unique<Utils::Registry>(key, subKey + "\\" + package, KEY_WOW64_64KEY | KEY_READ);
                                }

                                return *packageReg;
                            }
                        };

                        addCbsPackageState(states,
                                           getCbsPackageHotfix(package,
                                                               [&](DWORD & state)
                        {
                            return openPackage().dword("CurrentState", state);
                        },
                        [&](std::string & location)
                        {
                            return openPackage().string("InstallLocation", location);
                        }));
                    }
                    catch (...)
                    {
                    }
                }
            };
            root.enumerate(callback);
        }
        catch (...)
        {
        }

        return states;
    }

    static void addCbsAppliedHotfixes(const std::map<std::string, CbsHotfixState>& states, std::set<std::string>& hotfixes)
    {
        for (const auto& [hotfix, state] : states)
        {
            if (state.applied)
            {
                hotfixes.insert(hotfix);
            }
        }
    }

    static void getHotFixFromReg(const HKEY key, const std::string& subKey, std::set<std::string>& hotfixes)
    {
        addCbsAppliedHotfixes(getCbsHotfixStates(key, subKey), hotfixes);
    }

    // Removes, whatever source listed them, the KBs whose cumulative update (RollupFix) is not applied:
    // staged or failed, or installed but waiting for a reboot, since its payload does not run until
    // then. A cumulative update applies all or nothing, so only its RollupFix packages decide.
    // Packages named after a KB can be optional parts left staged next to an applied payload, so
    // they neither remove nor keep a KB here.
    static void removeCbsUnappliedHotfixes(const std::map<std::string, CbsHotfixState>& states, std::set<std::string>& hotfixes)
    {
        for (const auto& [hotfix, state] : states)
        {
            if (state.rollup && !state.rollupApplied)
            {
                hotfixes.erase(hotfix);
            }
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

    // .NET Framework 4.0 products under WOW6432Node\Microsoft\Updates. Where .NET Framework 4.x is
    // part of the OS (Windows 8 and later), the OS image writes their KBs as already included.
    static bool isInboxDotNet4UpdatesKey(const std::string& packageKey)
    {
        return packageKey == "Microsoft .NET Framework 4 Client Profile" ||
               packageKey == "Microsoft .NET Framework 4 Extended";
    }

    static void getHotFixFromRegWOW(const HKEY key,
                                    const std::string& subKey,
                                    std::set<std::string>& hotfixes,
                                    const bool skipInboxDotNet4 = false)
    {
        try
        {
            const auto callback
            {
                [&key, &subKey, &hotfixes, skipInboxDotNet4](const std::string & packageKey)
                {
                    if (skipInboxDotNet4 && isInboxDotNet4UpdatesKey(packageKey))
                    {
                        return;
                    }

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
                        version = Utils::trim(std::string(value, strnlen(value, valueLength)), " \t");
                    }
                }
            }
        }

        return version;
    }
};

#endif // _PACKAGES_WINDOWS_PARSER_HELPER_H
