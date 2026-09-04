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

#ifndef _TASK_MANAGER_UPGRADE_VERSION_POLICY_HPP
#define _TASK_MANAGER_UPGRADE_VERSION_POLICY_HPP

#include "errorCodes.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace task_manager::upgrade
{
    /**
     * @brief Outcome of the version gates.
     */
    struct VersionVerdict
    {
        UpgradeError error {UpgradeError::GlobalDbFailure};
        /// @brief The version whose WPK will be installed. Empty on the custom-WPK path, where the
        ///        file itself decides and its name is not authoritative.
        std::string wpkVersion;
    };

    /**
     * @brief Extract the target version from a canonical WPK filename.
     *
     * Canonical means "wazuh_agent_v<VERSION>_<rest>.wpk": the token after the first "_v" and up to
     * the next '_', returned WITH its leading 'v' so it can be compared directly. Returns nullopt
     * for a renamed or otherwise non-canonical file, which is not an error -- it means the filename
     * carries no claim about the version, and the agent-side preinst check becomes the only gate.
     */
    std::optional<std::string> parseWpkCustomVersion(std::string_view filePath);

    /**
     * @brief Version gates for a repository upgrade.
     *
     * Ported from wm_agent_upgrade_validate_version()'s WM_UPGRADE_UPGRADE branch, in order:
     *
     *   - An agent version that is neither 'v'-tagged nor digit-led is GlobalDbFailure. The agent
     *     never reported anything usable, so no gate below can be evaluated honestly.
     *   - Below v3.0.0 -> NotMinimalVersionSupported.
     *   - Target is `customVersion` when the caller named one, otherwise the manager's own version.
     *   - Target >= v5.0.0 while the agent is below v4.14.0 -> IntermediateVersionRequired. This is
     *     checked BEFORE the force branch and is deliberately NOT overridable: the 5.x agent cannot
     *     re-enroll from a pre-4.14 state, so forcing it strands the agent.
     *   - Without force: target <= current -> NewVersionLessOrEqualThanCurrent; target above the
     *     manager's own version -> NewVersionGreaterMaster.
     *
     * @param managerVersion The manager's own version. Passed in rather than read from the
     *                       libwazuh global __wazuh_version, which this shared object cannot link --
     *                       and which the retired unit tests had to #undef to test at all. A string
     *                       with no 'v' anywhere yields GlobalDbFailure, matching the C.
     */
    VersionVerdict checkRepositoryUpgrade(std::string_view agentVersion,
                                          std::string_view managerVersion,
                                          std::string_view customVersion,
                                          bool forceUpgrade);

    /**
     * @brief Version gates for a custom-WPK upgrade.
     *
     * Only the intermediate-version rule applies, and only when the filename is canonical. There is
     * no "greater than the manager" or "not newer than current" gate here: the operator supplied the
     * file deliberately, and its real target version is unknowable from the manager's side.
     */
    VersionVerdict checkCustomUpgrade(std::string_view agentVersion, std::string_view customFilePath);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_VERSION_POLICY_HPP
