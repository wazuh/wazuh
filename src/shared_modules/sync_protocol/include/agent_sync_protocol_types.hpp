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
    TIMEOUT_ERROR,       ///< Exceeded maximum retries waiting for a response
    PROTOCOL_ERROR,       ///< Manager sent an unexpected or invalid response
    NO_GROUPS_ERROR,     ///< No groups available in metadata.
};

struct SyncModuleResult
{
    bool success;
    std::string failureReason;
};
