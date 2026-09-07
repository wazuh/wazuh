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

#include "versionPolicy.hpp"

#include "version.hpp"

#include <cctype>

namespace
{
    using namespace task_manager::upgrade;

    /**
     * @brief The usable part of an agent-reported version string, or nullopt.
     *
     * Ported from the two-branch test in wm_agent_upgrade_validate_version(): a 'v' ANYWHERE makes
     * the substring from that 'v' onwards usable; failing that, a leading digit makes the whole
     * string usable; anything else means the agent reported something this code cannot read.
     */
    std::optional<std::string_view> usableVersion(const std::string_view version)
    {
        if (const auto marker {version.find('v')}; marker != std::string_view::npos)
        {
            return version.substr(marker);
        }

        if (!version.empty() && std::isdigit(static_cast<unsigned char>(version.front())) != 0)
        {
            return version;
        }

        return std::nullopt;
    }
} // namespace

namespace task_manager::upgrade
{
    std::optional<std::string> parseWpkCustomVersion(const std::string_view filePath)
    {
        if (filePath.empty())
        {
            return std::nullopt;
        }

        const auto slash {filePath.rfind('/')};
        const std::string_view fileName {slash == std::string_view::npos ? filePath : filePath.substr(slash + 1)};

        const auto marker {fileName.find("_v")};
        if (marker == std::string_view::npos)
        {
            return std::nullopt;
        }

        // Point AT the 'v', not past it, so the token can be compared without re-tagging it.
        const std::string_view tail {fileName.substr(marker + 1)};
        const auto end {tail.find('_')};
        if (end == std::string_view::npos || end == 0)
        {
            return std::nullopt;
        }

        return std::string {tail.substr(0, end)};
    }

    VersionVerdict checkRepositoryUpgrade(const std::string_view agentVersion,
                                          const std::string_view managerVersion,
                                          const std::string_view customVersion,
                                          const bool forceUpgrade)
    {
        VersionVerdict verdict;

        const auto agent {usableVersion(agentVersion)};
        if (!agent.has_value())
        {
            return verdict; // GlobalDbFailure.
        }

        if (compareVersions(*agent, MINIMAL_VERSION_SUPPORT, true) < 0)
        {
            verdict.error = UpgradeError::NotMinimalVersionSupported;
            return verdict;
        }

        // The manager's version must itself be 'v'-tagged; the C read it with strchr and did nothing
        // at all when that failed, leaving the caller with GlobalDbFailure.
        const auto managerMarker {managerVersion.find('v')};
        if (managerMarker == std::string_view::npos)
        {
            return verdict; // GlobalDbFailure.
        }
        const std::string_view manager {managerVersion.substr(managerMarker)};

        verdict.error = UpgradeError::Success;
        verdict.wpkVersion = customVersion.empty() ? std::string {manager} : std::string {customVersion};

        if (compareVersions(verdict.wpkVersion, FIVE_X_MINIMUM_VERSION, true) >= 0 &&
            compareVersions(*agent, REQUIRED_INTERMEDIATE_VERSION, true) < 0)
        {
            // Checked before force, and not overridable by it -- see the header.
            verdict.error = UpgradeError::IntermediateVersionRequired;
        }
        else if (!forceUpgrade)
        {
            if (compareVersions(*agent, verdict.wpkVersion, true) >= 0)
            {
                verdict.error = UpgradeError::NewVersionLessOrEqualThanCurrent;
            }
            else if (compareVersions(verdict.wpkVersion, manager, true) > 0)
            {
                verdict.error = UpgradeError::NewVersionGreaterMaster;
            }
        }

        return verdict;
    }

    VersionVerdict checkCustomUpgrade(const std::string_view agentVersion, const std::string_view customFilePath)
    {
        VersionVerdict verdict;

        const auto agent {usableVersion(agentVersion)};
        if (!agent.has_value())
        {
            return verdict; // GlobalDbFailure.
        }

        if (compareVersions(*agent, MINIMAL_VERSION_SUPPORT, true) < 0)
        {
            verdict.error = UpgradeError::NotMinimalVersionSupported;
            return verdict;
        }

        verdict.error = UpgradeError::Success;

        if (const auto target {parseWpkCustomVersion(customFilePath)};
            target.has_value() && compareVersions(*target, FIVE_X_MINIMUM_VERSION, true) >= 0 &&
            compareVersions(*agent, REQUIRED_INTERMEDIATE_VERSION, true) < 0)
        {
            verdict.error = UpgradeError::IntermediateVersionRequired;
        }

        return verdict;
    }
} // namespace task_manager::upgrade
