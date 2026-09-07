/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "platform.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace
{
    using namespace std::string_view_literals;

    /// @brief Platforms with no WPK at all. Checked first and unconditionally.
    constexpr std::array INVALID_PLATFORMS {"solaris"sv, "sunos"sv, "aix"sv, "hp-ux"sv, "bsd"sv};

    /// @brief Platforms with no meaningful OS version, so the os_major requirement does not apply.
    constexpr std::array ROLLING_PLATFORMS {"opensuse-tumbleweed"sv, "arch"sv};

    constexpr std::array DEB_PLATFORMS {"debian"sv, "ubuntu"sv};

    constexpr std::array RPM_PLATFORMS {"amzn"sv,
                                        "centos"sv,
                                        "fedora"sv,
                                        "ol"sv,
                                        "opensuse"sv,
                                        "opensuse-leap"sv,
                                        "opensuse-tumbleweed"sv,
                                        "rhel"sv,
                                        "sles"sv,
                                        "suse"sv,
                                        "rocky"sv,
                                        "almalinux"sv};

    /// @brief (platform, os_major) pairs that are past end of life and cannot be upgraded remotely.
    constexpr std::array<std::pair<std::string_view, std::string_view>, 5> END_OF_LIFE {
        {{"sles"sv, "11"sv}, {"suse"sv, "11"sv}, {"ol"sv, "5"sv}, {"rhel"sv, "5"sv}, {"centos"sv, "5"sv}}};

    template<typename Container>
    bool contains(const Container& container, const std::string_view value)
    {
        return std::find(container.begin(), container.end(), value) != container.end();
    }
} // namespace

namespace task_manager::upgrade
{
    PlatformVerdict resolvePackageType(const std::string_view platform,
                                       const std::string_view osMajor,
                                       const std::string_view osMinor,
                                       const std::string_view architecture)
    {
        PlatformVerdict verdict;

        if (platform.empty())
        {
            return verdict; // GlobalDbFailure: nothing is known about this agent.
        }

        if (contains(INVALID_PLATFORMS, platform))
        {
            verdict.error = UpgradeError::SystemNotSupported;
            return verdict;
        }

        if (platform == "windows"sv)
        {
            verdict.error = UpgradeError::Success;
            verdict.packageType = "msi";
            return verdict;
        }

        if (platform == "darwin"sv)
        {
            if (!architecture.empty())
            {
                verdict.error = UpgradeError::Success;
                verdict.packageType = "pkg";
            }
            return verdict; // Without an architecture: GlobalDbFailure.
        }

        if (architecture.empty())
        {
            return verdict; // GlobalDbFailure.
        }

        // ubuntu needs a minor version too -- its repository path is "<major>.<minor>".
        const bool hasUsableVersion {!osMajor.empty() && (platform != "ubuntu"sv || !osMinor.empty())};

        if (hasUsableVersion)
        {
            verdict.error = UpgradeError::Success;

            const auto endOfLife {std::find_if(END_OF_LIFE.begin(),
                                               END_OF_LIFE.end(),
                                               [&](const auto& entry)
                                               { return entry.first == platform && entry.second == osMajor; })};
            if (endOfLife != END_OF_LIFE.end())
            {
                verdict.error = UpgradeError::SystemNotSupported;
            }
        }
        else if (contains(ROLLING_PLATFORMS, platform))
        {
            verdict.error = UpgradeError::Success;
        }

        if (verdict.error == UpgradeError::Success)
        {
            if (contains(DEB_PLATFORMS, platform))
            {
                verdict.packageType = "deb";
            }
            else if (contains(RPM_PLATFORMS, platform))
            {
                verdict.packageType = "rpm";
            }
            // Otherwise empty, deliberately: an unrecognised distribution can still be upgraded if
            // the caller names a package_type, and is rejected by the repository layer if not.
        }

        return verdict;
    }

    std::string translateArch(const std::string_view platform,
                              const std::string_view packageType,
                              const std::string_view architecture)
    {
        if (architecture == "x86_64"sv)
        {
            if (platform == "darwin"sv)
            {
                if (packageType == "pkg"sv)
                {
                    return "intel64";
                }
            }
            else if (packageType == "deb"sv)
            {
                return "amd64";
            }
        }
        else if (architecture == "aarch64"sv)
        {
            if (platform == "darwin"sv)
            {
                if (packageType == "pkg"sv)
                {
                    return "arm64";
                }
            }
            else if (packageType == "deb"sv)
            {
                return "arm64";
            }
        }

        return std::string {architecture};
    }
} // namespace task_manager::upgrade
