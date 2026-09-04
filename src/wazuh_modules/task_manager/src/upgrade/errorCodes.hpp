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

#ifndef _TASK_MANAGER_UPGRADE_ERROR_CODES_HPP
#define _TASK_MANAGER_UPGRADE_ERROR_CODES_HPP

#include <array>
#include <cstddef>

namespace task_manager::upgrade
{
    /**
     * @brief Per-agent result of an upgrade request.
     *
     * THE NUMERIC VALUES ARE WIRE FORMAT. The Server API turns each one into an exception code by
     * adding 1810 (framework/wazuh/agent.py), and three of those codes are then classified by
     * literal value: ERROR_CODES_UPGRADE_SOCKET = [1819, 1820, 1821, 1822, 1823, 1828],
     * ERROR_CODES_UPGRADE_SOCKET_BAD_REQUEST = [1824, 1826], and 1816 is silently skipped. None of
     * the 1810..1828 range has an entry in framework/wazuh/core/exception.py, so the human-readable
     * text the user sees is the MESSAGES string below, lifted verbatim off the wire.
     *
     * So: append only, never reorder, and never edit a message without accepting that the change is
     * user-visible. LegacyDeliveryDisabled sits after UnknownError for exactly this reason -- it was
     * added last, and inserting it in a "logical" place would have shifted UnknownError's value.
     */
    enum class UpgradeError : int
    {
        Success = 0,
        ParsingError = 1,
        ParsingRequiredParameter = 2,
        TaskConfigurations = 3,
        TaskManagerCommunication = 4,
        TaskManagerFailure = 5,
        GlobalDbFailure = 6,
        SystemNotSupported = 7,
        NotMinimalVersionSupported = 8,
        IntermediateVersionRequired = 9,
        NewVersionLessOrEqualThanCurrent = 10,
        NewVersionGreaterMaster = 11,
        UrlNotFound = 12,
        WpkVersionDoesNotExist = 13,
        WpkFileDoesNotExist = 14,
        WpkSha1DoesNotMatch = 15,
        HttpsVerificationModeUnsafe = 16,
        UnknownError = 17,
        LegacyDeliveryDisabled = 18
    };

    /// @brief One past the highest valid UpgradeError, for bounds checks and array sizing.
    constexpr std::size_t UPGRADE_ERROR_COUNT {19};

    /**
     * @brief The message for each code, byte-identical to upgrade_error_codes[] in the retired
     *        wm_agent_upgrade_manager.c.
     *
     * TaskManagerFailure is deliberately empty: the retired code reserved it for text the task
     * manager would supply. Nothing ever supplied any, and it is kept only so the numbering holds.
     */
    constexpr std::array<const char*, UPGRADE_ERROR_COUNT> UPGRADE_ERROR_MESSAGES {
        "Success",
        "Could not parse message JSON",
        "Required parameters in json message where not found",
        "JSON parameter not recognized",
        "Task manager communication error",
        "",
        "Agent information not found in database",
        "The WPK for this platform is not available",
        "Remote upgrade is not available for this agent version",
        "Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first",
        "Current agent version is greater or equal",
        "Upgrading an agent to a version higher than the manager requires the force flag",
        "The repository is not reachable",
        "The version of the WPK does not exist in the repository",
        "The WPK file does not exist",
        "The WPK sha1 of the file is not valid",
        "The manager's HTTPS verification_mode is not 'none'; a just-upgraded agent may be unable to "
        "reconnect. Use the force option to proceed anyway.",
        "Upgrade procedure could not start",
        "The agent is below v5.0.0 and the manager's legacy delivery (remote.legacy.enabled) is "
        "disabled; the upgrade task could never be delivered."};

    /**
     * @brief The wire value of a code.
     */
    constexpr int errorValue(const UpgradeError error)
    {
        return static_cast<int>(error);
    }

    /**
     * @brief The message for a code, or the empty string if it is out of range.
     *
     * Out of range cannot happen through the enum, but this is also reached with values parsed off
     * the wire in tests, so it does not index blindly.
     */
    constexpr const char* errorMessage(const UpgradeError error)
    {
        const auto index {static_cast<std::size_t>(error)};
        return index < UPGRADE_ERROR_COUNT ? UPGRADE_ERROR_MESSAGES[index] : "";
    }
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_ERROR_CODES_HPP
