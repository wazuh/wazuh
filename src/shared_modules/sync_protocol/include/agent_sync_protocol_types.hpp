/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <functional>
#include <string>

#include "agent_sync_protocol_c_interface_types.h"

using LoggerFunc = std::function<void(modules_log_level_t, const std::string&)>;

/// @brief Result status for sync operations, especially for integrity checks
enum class SyncResult
{
    SUCCESS,             ///< Operation completed successfully
    COMMUNICATION_ERROR, ///< Failed to communicate with the manager
    CHECKSUM_ERROR,      ///< Checksum validation failed
    START_TIMEOUT_ERROR,       ///< Exceeded maximum retries waiting for a response for the Start message
    END_TIMEOUT_ERROR,       ///< Exceeded maximum retries waiting for a response for the End message
    PROTOCOL_ERROR,       ///< Manager sent an unexpected or invalid response
    NO_GROUPS_ERROR,     ///< No groups available in metadata.
    PAYLOAD_TOO_LARGE,   ///< Manager rejected the session as larger than its total in-flight
    ///< budget (HTTP 413); the session must be split and resent smaller.
    NO_VD_OFFSET_ERROR,  ///< VD (VDFirst/VDSync) sync attempted before any feed offset has
    ///< been received from the manager yet.
};

struct SyncModuleResult
{
    bool success{false};
    std::string failureReason;
    /// @brief True when the operation was aborted because a stop/shutdown was requested.
    /// Lets the calling module demote an expected shutdown-time failure from WARNING to
    /// INFO/DEBUG.
    bool stopped{false};
    /// @brief True when the manager did not answer the handshake, or answered that it cannot serve
    /// this agent yet (Offline). This describes what happened, not whether it is harmless: the same
    /// condition covers a brief window after an agent restart and a lasting outage (for example the
    /// manager having no indexer available). Use it together with @ref consecutiveFailures to decide
    /// the log level.
    bool managerNotReady{false};
    /// @brief Number of consecutive failed synchronizations for this module, including this one.
    /// Reset to zero on the first success. A single failure that recovers on the next cycle is an
    /// expected hiccup; a growing count means the condition is not clearing and deserves a WARNING.
    unsigned int consecutiveFailures{0};
    /// @brief True when the sync was aborted because a prerequisite the manager has to supply
    /// first (assigned groups, or -- for a VD sync -- a feed offset) has not arrived yet. Same
    /// intent as @ref stopped: lets the calling module demote this from WARNING to INFO/DEBUG,
    /// since it is expected and normally clears within the next cycle or two (e.g. right after
    /// an agent restart, before the first /control round trip completes).
    bool awaitingPrerequisite{false};
};
