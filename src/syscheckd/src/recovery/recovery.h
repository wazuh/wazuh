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
#include <cJSON.h>
#include "logging_helper.h"
#include "list_op.h"

#ifdef __cplusplus
// Callback type for testing synchronizeModule: allows mocking sync behavior
typedef bool (*SynchronizeModuleCallback)(void);
#else
typedef bool (*SynchronizeModuleCallback)(void);
#endif

/**
 * @brief Persists a table's contents in memory and triggers a full resync
 * @param table_name The table to resync
 * @param handle Sync Protocol handle
 * @param directories_list The OSList of directory_t objects to use for configuration lookup (must not be NULL)
 */
EXPORTED void fim_recovery_persist_table_and_resync(char* table_name, AgentSyncProtocolHandle* handle, const OSList *directories_list);

/**
 * @brief Checks if a full sync is required by calculating the checksum-of-checksums for a table and comparing it with the manager's
 * @param table_name The table to check
 * @param handle Sync Protocol handle
 * @returns true if a full sync is required, false if a delta sync is sufficient
 */
EXPORTED bool fim_recovery_check_if_full_sync_required(char* table_name, AgentSyncProtocolHandle* handle);

/**
 * @brief Checks if integrity_interval has elapsed for a table
 * @param table_name The table to check
 * @param integrity_interval Value to check
 * @returns true if interval has elapsed, false otherwise
 */
EXPORTED bool fim_recovery_integrity_interval_has_elapsed(char* table_name, int64_t integrity_interval);

/**
 * @brief Build stateful event for a file from cJSON object
 * @param path File path
 * @param file_data cJSON object containing file attributes
 * @param sha1_hash SHA1 hash of the file
 * @param document_version Version number of the document
 * @param directories_list The OSList of directory_t objects to use for configuration lookup (must not be NULL)
 * @return Stateful event as a cJSON object (must be freed by caller), NULL on error
 */
EXPORTED cJSON* buildFileStatefulEvent(const char* path, cJSON* file_data, const char* sha1_hash, uint64_t document_version, const OSList *directories_list);

#ifdef WIN32
/**
 * @brief Build stateful event for a registry key from cJSON object
 * @param path Registry key path
 * @param key_data cJSON object containing registry key attributes
 * @param sha1_hash SHA1 hash of the key
 * @param document_version Version number of the document
 * @param arch Architecture (ARCH_32BIT or ARCH_64BIT)
 * @return Stateful event as a cJSON object (must be freed by caller), NULL on error
 */
EXPORTED cJSON* buildRegistryKeyStatefulEvent(const char* path, cJSON* key_data, const char* sha1_hash, uint64_t document_version, int arch);

/**
 * @brief Build stateful event for a registry value from cJSON object
 * @param path Registry value path
 * @param value Value name
 * @param value_data cJSON object containing registry value attributes
 * @param sha1_hash SHA1 hash of the value
 * @param document_version Version number of the document
 * @param arch Architecture (ARCH_32BIT or ARCH_64BIT)
 * @return Stateful event as a cJSON object (must be freed by caller), NULL on error
 */
EXPORTED cJSON* buildRegistryValueStatefulEvent(const char* path, char* value, cJSON* value_data, const char* sha1_hash, uint64_t document_version, int arch);
#endif // WIN32

#ifdef __cplusplus
}
#endif // _cplusplus
