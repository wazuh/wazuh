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
    char os_type[256];            ///< Operating system type (e.g., "linux", "windows", "darwin")
    char os_platform[256];        ///< Operating system platform/distribution (e.g., "ubuntu", "centos", "windows")
    char os_version[256];         ///< Operating system version
    char** groups;                ///< Array of group names (NULL-terminated strings)
    size_t groups_count;          ///< Number of groups in the array
} agent_metadata_t;

/**
 * @brief Update the stored metadata
 *
 * Thread-safe. The provider makes an internal copy of the metadata.
 *
 * @param metadata Pointer to metadata structure to store
 * @return 0 on success, -1 on error (NULL pointer)
 */
int metadata_provider_update(const agent_metadata_t* metadata);

/**
 * @brief Get a copy of the current metadata
 *
 * Thread-safe. Returns the most recently updated metadata.
 * The caller is responsible for freeing the groups array if groups_count > 0.
 *
 * @param out_metadata Pointer to structure to fill with metadata
 * @return 0 on success, -1 on error (NULL pointer or no metadata available)
 */
int metadata_provider_get(agent_metadata_t* out_metadata);

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
 * @brief Reset the metadata provider state (for testing purposes only)
 *
 * Clears all stored metadata. This function is intended for use in unit tests
 * to ensure test isolation.
 */
void metadata_provider_reset(void);

#ifdef __cplusplus
}
#endif

#endif // METADATA_PROVIDER_H
