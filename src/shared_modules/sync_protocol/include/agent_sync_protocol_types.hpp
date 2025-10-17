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
    COMMUNICATION_ERROR, ///< Manager is offline or unreachable
    CHECKSUM_ERROR       ///< Checksum validation failed
};
