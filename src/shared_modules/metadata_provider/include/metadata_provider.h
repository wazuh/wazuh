/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef METADATA_PROVIDER_H
#define METADATA_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Agent metadata structure containing system and agent information
 *
 * This structure holds all metadata fields required by the sync protocol.
 * All string fields are null-terminated C strings with fixed maximum lengths.
 */
typedef struct {
    char agent_id[256];           ///< Agent identifier (e.g., "001", "000" for server)
    char agent_name[256];         ///< Agent name
    char agent_version[256];      ///< Wazuh agent version
    char architecture[256];       ///< System architecture (e.g., "x86_64")
    char hostname[256];           ///< System hostname
    char os_name[256];            ///< Operating system name
    char os_type[256];            ///< Operating system type (e.g., "linux", "windows")
    char os_version[256];         ///< Operating system version
    char checksum_metadata[256];  ///< Checksum of metadata fields
    uint64_t global_version;      ///< Global version counter
    char** groups;                ///< Array of group names (NULL-terminated strings)
    size_t groups_count;          ///< Number of groups in the array
} agent_metadata_t;

/**
 * @brief Callback function type for metadata updates
 *
 * @param metadata Pointer to the updated metadata structure
 * @param user_data Optional user data passed during registration
 */
typedef void (*metadata_update_callback_t)(const agent_metadata_t* metadata, void* user_data);

/**
 * @brief Initialize the metadata provider
 *
 * Must be called before any other metadata_provider functions.
 * Safe to call multiple times (idempotent).
 *
 * @return 0 on success, -1 on error
 */
int metadata_provider_init(void);

/**
 * @brief Update the stored metadata
 *
 * Thread-safe. Notifies all registered callbacks after update.
 * The provider makes an internal copy of the metadata.
 *
 * @param metadata Pointer to metadata structure to store
 * @return 0 on success, -1 on error (NULL pointer or uninitialized)
 */
int metadata_provider_update(const agent_metadata_t* metadata);

/**
 * @brief Get a copy of the current metadata
 *
 * Thread-safe. Returns the most recently updated metadata.
 * The caller is responsible for freeing the groups array if groups_count > 0.
 *
 * @param out_metadata Pointer to structure to fill with metadata
 * @return 0 on success, -1 on error (NULL pointer, uninitialized, or no metadata available)
 */
int metadata_provider_get(agent_metadata_t* out_metadata);

/**
 * @brief Register a callback for metadata updates
 *
 * The callback will be invoked whenever metadata is updated via metadata_provider_update().
 * Callbacks are invoked synchronously in the context of the update call.
 *
 * @param callback Function to call on metadata updates
 * @param user_data Optional user data to pass to callback (can be NULL)
 * @return Callback ID on success (>= 0), -1 on error
 */
int metadata_provider_register_callback(metadata_update_callback_t callback, void* user_data);

/**
 * @brief Unregister a previously registered callback
 *
 * @param callback_id ID returned from metadata_provider_register_callback
 * @return 0 on success, -1 if callback_id not found
 */
int metadata_provider_unregister_callback(int callback_id);

/**
 * @brief Free resources allocated in agent_metadata_t structure
 *
 * Frees the groups array and its contents. Safe to call on zero-initialized
 * or already-freed metadata structures.
 *
 * @param metadata Pointer to metadata structure to free
 */
void metadata_provider_free_metadata(agent_metadata_t* metadata);

/**
 * @brief Shutdown the metadata provider and release all resources
 *
 * Unregisters all callbacks and frees internal state.
 * Safe to call multiple times.
 */
void metadata_provider_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif // METADATA_PROVIDER_H
