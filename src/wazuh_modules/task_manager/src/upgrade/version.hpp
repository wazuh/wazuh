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

#ifndef _TASK_MANAGER_UPGRADE_VERSION_HPP
#define _TASK_MANAGER_UPGRADE_VERSION_HPP

#include <string>
#include <string_view>

namespace task_manager::upgrade
{
    /// @brief Version constants, byte-identical to the retired wm_agent_upgrade_manager.h.
    constexpr const char* MINIMAL_VERSION_SUPPORT {"v3.0.0"};
    constexpr const char* NEW_LINUX_VERSION_REPOSITORY {"v3.4.0"};
    constexpr const char* NEW_VERSION_STRUCTURE_REPOSITORY {"v4.9.0"};
    constexpr const char* REQUIRED_INTERMEDIATE_VERSION {"v4.14.0"};
    constexpr const char* FIVE_X_MINIMUM_VERSION {"v5.0.0"};

    /**
     * @brief A Wazuh version, parsed into its three numeric components.
     */
    struct SemVersion
    {
        int major {0};
        int minor {0};
        int patch {0};
    };

    /**
     * @brief Parse a version string into its components.
     *
     * Accepts "v4.14.0", "4.14.0", "4.14", "4" and anything in between; absent components are zero,
     * which is what the retired C did and what the callers rely on ("4.14" must compare equal to
     * "4.14.0" when patches are ignored).
     *
     * The 'v' rule is copied deliberately, warts and all: the FIRST 'v' anywhere in the string is
     * found and parsing starts after it, so "Wazuh v4.5.0" parses as 4.5.0 and "4.0.0v" parses as
     * 0.0.0. Callers pass agent-reported strings whose exact shape has varied across releases, and
     * narrowing this to a leading-'v'-only rule would change which agents are considered upgradable.
     *
     * Each component stops at the first character that is not a digit, so a build suffix such as
     * "4.14.0-rc1" yields 4.14.0 rather than a parse failure.
     */
    SemVersion parseVersion(std::string_view version);

    /**
     * @brief Three-way comparison of two Wazuh versions.
     *
     * @param version1     Left operand.
     * @param version2     Right operand.
     * @param comparePatch When false, the patch component is ignored and 4.14.1 == 4.14.9.
     * @return -1, 0 or 1.
     *
     * This replaces compare_wazuh_versions() from src/shared/src/version_op.c rather than calling
     * it, and not only because the module must not link libwazuh. That function copies each argument
     * into a `char[10]` -- silently truncating "v10.14.100" to "v10.14.10", i.e. reporting a LOWER
     * version than the one it was given -- and splits with strtok(), which keeps its cursor in a
     * process-global. It is unsafe to call from two threads at once and survives today only because
     * its single caller is single-threaded. This one is reentrant and does not truncate.
     */
    int compareVersions(std::string_view version1, std::string_view version2, bool comparePatch);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_VERSION_HPP
