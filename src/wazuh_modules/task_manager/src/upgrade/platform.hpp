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

#ifndef _TASK_MANAGER_UPGRADE_PLATFORM_HPP
#define _TASK_MANAGER_UPGRADE_PLATFORM_HPP

#include "errorCodes.hpp"

#include <string>
#include <string_view>

namespace task_manager::upgrade
{
    /**
     * @brief What wazuh-db knows about an agent, which is all the upgrade path ever knows.
     *
     * Every field is optional in practice: wazuh-db returns whatever the agent last reported, and a
     * never-connected agent reports none of it. Emptiness is therefore normal input, not a bug, and
     * drives the SystemNotSupported / GlobalDbFailure decisions below.
     */
    struct AgentInfo
    {
        int agentId {0};
        std::string platform;
        std::string majorVersion;
        std::string minorVersion;
        std::string architecture;
        std::string wazuhVersion;
        /// @brief Derived by resolvePackageType(), not reported by the agent.
        std::string packageType;
    };

    /**
     * @brief Outcome of classifying an agent's operating system.
     */
    struct PlatformVerdict
    {
        UpgradeError error {UpgradeError::GlobalDbFailure};
        /// @brief "msi", "pkg", "deb", "rpm", or empty when the platform has no package family.
        std::string packageType;
    };

    /**
     * @brief Decide whether an agent's OS can be upgraded, and which package family it belongs to.
     *
     * Ported from wm_agent_upgrade_validate_system(). The decision order is load-bearing and is
     * preserved exactly:
     *
     *   1. A blacklisted platform is SystemNotSupported, whatever else is known.
     *   2. windows -> msi. darwin (with an architecture) -> pkg.
     *   3. Otherwise an architecture is required, plus EITHER an OS major version -- and a minor
     *      version too when the platform is ubuntu, because its repository layout is
     *      "<major>.<minor>" -- OR membership of the rolling-release whitelist, which has no
     *      meaningful version at all.
     *   4. Five specific end-of-life major versions are rejected even though they satisfy (3).
     *   5. Only then is the deb/rpm family resolved; an unrecognised distribution yields an EMPTY
     *      packageType with Success, which the repository layer resolves later (a caller-supplied
     *      package_type can still rescue it) or rejects as SystemNotSupported.
     *
     * An empty platform is GlobalDbFailure, not SystemNotSupported: nothing is known about the
     * agent, which is a different thing from knowing it cannot be upgraded.
     */
    PlatformVerdict resolvePackageType(std::string_view platform,
                                       std::string_view osMajor,
                                       std::string_view osMinor,
                                       std::string_view architecture);

    /**
     * @brief Map an agent-reported architecture onto the one the repository uses.
     *
     * Ported from wm_agent_upgrade_translate_arch(). Only deb and macOS pkg rename anything; rpm
     * and msi use the agent's own string. An unrecognised architecture passes through unchanged, so
     * this is safe to call unconditionally.
     */
    std::string translateArch(std::string_view platform, std::string_view packageType, std::string_view architecture);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_PLATFORM_HPP
