/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * October 22 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
// We avoid the definition __declspec(dllimport) as a workaround for the MinGW bug
// for delayed loaded DLLs in 32bits (https://www.sourceware.org/bugzilla/show_bug.cgi?id=14339)
#define EXPORTED
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#ifdef __cplusplus
#include "agent_sync_protocol.hpp"
#include <string>

extern "C"
{
#else
#include "agent_sync_protocol_c_interface_types.h"
#endif

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
// Callback type for testing synchronizeModule: allows mocking sync behavior
typedef bool (*SynchronizeModuleCallback)(void);
#else
typedef bool (*SynchronizeModuleCallback)(void);
#endif

/**
 * @brief Persists a table's contents in memory and triggers a full resync
 * @param table_name The table to resync
 * @param sync_response_timeout Timeout for the sync process
 * @param sync_max_eps Max eps for the sync process
 * @param handle Sync Protocol handle
 * @param test_callback Optional callback for testing synchronizeModule (pass NULL for production use)
 */
EXPORTED void fim_recovery_persist_table_and_resync(char* table_name, uint32_t sync_response_timeout, long sync_max_eps, AgentSyncProtocolHandle* handle, SynchronizeModuleCallback test_callback);

/**
 * @brief Checks if a full sync is required by calculating the checksum-of-checksums for a table and comparing it with the manager's
 * @param table_name The table to check
 * @param sync_response_timeout Timeout for the checksum validation process
 * @param sync_max_eps Max eps for the checksum validation process
 * @param handle Sync Protocol handle
 * @returns true if a full sync is required, false if a delta sync is sufficient
 */
EXPORTED bool fim_recovery_check_if_full_sync_required(char* table_name, uint32_t sync_response_timeout, long sync_max_eps, AgentSyncProtocolHandle* handle);

/**
 * @brief Checks if integrity_interval has elapsed for a table
 * @param table_name The table to check
 * @param integrity_interval Value to check
 * @returns true if interval has elapsed, false otherwise
 */
EXPORTED bool fim_recovery_integrity_interval_has_elapsed(char* table_name, int64_t integrity_interval);

#ifdef __cplusplus
}
#endif // _cplusplus
