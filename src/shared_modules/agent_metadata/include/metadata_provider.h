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
typedef struct
{
    char agent_id[256];           ///< Agent identifier (e.g., "001")
    char agent_name[256];         ///< Agent name
    char agent_version[256];      ///< Wazuh agent version
    char architecture[256];       ///< System architecture (e.g., "x86_64")
    char hostname[256];           ///< System hostname
    char os_name[256];            ///< Operating system name
    char os_type[256];            ///< Operating system type (e.g., "linux", "windows", "darwin")
    char os_platform[256];        ///< Operating system platform/distribution (e.g., "ubuntu", "centos", "windows")
    char os_version[256];         ///< Operating system version
    char cluster_name[256];       ///< Cluster name from manager (received during handshake)
    char** groups;                ///< Array of group names (NULL-terminated strings)
    size_t groups_count;          ///< Number of groups in the array
    uint64_t vd_feed_offset;      ///< Last observed VD feed offset (0 = not yet received from the manager)
} agent_metadata_t;

/**
 * @brief Update the stored metadata
 *
 * Thread-safe: internally serialized against every other writer (this function,
 * metadata_provider_update_vd_feed_offset(), and metadata_provider_reset()) within this
 * process. The provider makes an internal copy of the metadata.
 *
 * Does NOT touch `vd_feed_offset`, even though the passed-in struct may carry a value in
 * that field -- the field is exclusively owned by metadata_provider_update_vd_feed_offset(),
 * which is the only function that ever writes it. This is deliberate: a caller of this
 * function (e.g. a periodic metadata-gathering cycle) typically read its own copy of the
 * offset from a separate, possibly-stale source (a DB snapshot) some time before this call
 * actually runs, and blindly writing it here could clobber a fresher value
 * metadata_provider_update_vd_feed_offset() published in the meantime (#39543). Callers may
 * still populate this field in the struct they pass -- it is simply ignored.
 *
 * @param metadata Pointer to metadata structure to store
 * @return 0 on success, -1 on error (NULL pointer)
 */
int metadata_provider_update(const agent_metadata_t* metadata);

/**
 * @brief Update only the VD feed offset field, leaving every other field untouched
 *
 * Thread-safe: internally serialized against every other writer (metadata_provider_update(),
 * this function, and metadata_provider_reset()) within this process. This is the sole writer
 * of `vd_feed_offset` -- metadata_provider_update() never touches it (see its own doc
 * comment) -- so this function's value always wins regardless of how the two interleave.
 * Lets the agent publish a fresh feed offset the moment it is observed (e.g. from the IPC
 * handler that receives it, independent of the next full metadata_provider_update() cycle)
 * without clobbering the rest of the snapshot with blank fields.
 *
 * A no-op, returning -1, when no full metadata_provider_update() has ever
 * succeeded yet (has_metadata is still false): there is no existing snapshot to patch a
 * single field into without producing one with blank hostname/os fields, which other
 * consumers (e.g. syscollector's own Start message) also read. In that case the offset is
 * simply picked up the next time this function is called successfully (has_metadata true by
 * then), independent of metadata_provider_update() calls.
 *
 * @param offset The feed offset to store
 * @return 0 on success, -1 on error (no metadata snapshot yet, or provider unavailable)
 */
int metadata_provider_update_vd_feed_offset(uint64_t offset);

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
