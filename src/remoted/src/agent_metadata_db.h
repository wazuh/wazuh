/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENT_METADATA_DB_H
#define AGENT_METADATA_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

typedef struct agent_meta
{
    int agent_id;
    char* agent_name;
    char* agent_version;
    char* os_name;
    char* os_version;
    char* os_platform;
    char* os_type;
    char* arch;
    char* hostname;
    char* cluster_name;
    char** groups;
    size_t groups_count;
    time_t lastmsg;  // Last time a keepalive was received
    bool shutdown_pending;  // Agent has sent shutdown, waiting for queue to drain
} agent_meta_t;

/* Forward declaration is OK in the header (we only need the pointer type here) */
struct agent_info_data;

void agent_metadata_init(void);
void agent_metadata_teardown(void);

agent_meta_t* agent_meta_from_agent_info(const char* id_str, const char* agent_name, const struct agent_info_data* ai);

int agent_meta_upsert_locked(const char* agent_id_str, agent_meta_t* fresh);

/* Snapshot helper (copies strings; caller frees with agent_meta_free) */
int agent_meta_snapshot_str(const char* agent_id_str, agent_meta_t* out);

/* Result of comparing a connected agent's self-reported version against a threshold, via
 * agent_meta_check_version(). */
typedef enum {
    AGENT_VERSION_CHECK_UNKNOWN,     /* No version known at all (cache miss + wazuh-db miss). */
    AGENT_VERSION_CHECK_UNPARSEABLE, /* A version string was found but has no 'v' token. */
    AGENT_VERSION_CHECK_GE_MIN,      /* Resolved version is >= min_version. */
    AGENT_VERSION_CHECK_LT_MIN       /* Resolved version is < min_version. */
} agent_version_check_t;

/**
 * @brief Resolve a connected agent's self-reported version (cache-first via
 * agent_meta_snapshot_str(), wdb_get_agent_info() fallback on a cache miss) and classify it
 * against min_version.
 * @param agent_id_str Agent identifier.
 * @param min_version Version threshold to compare against (e.g. "v5.0.0").
 * @param out_version If a version string was resolved (any result but UNKNOWN), set to a
 * caller-owned copy of it (must be freed with os_free); left untouched on UNKNOWN. May be NULL if
 * the caller doesn't need the raw string.
 * @return Classification of the agent's version relative to min_version.
 */
agent_version_check_t agent_meta_check_version(const char* agent_id_str, const char* min_version, char** out_version);

/* Forward declaration for events queue type */
struct w_rr_queue;

/* Cleanup expired cache entries based on lastmsg timestamp and shutdown agents */
void agent_meta_cleanup_expired(time_t expire_threshold, struct w_rr_queue *events_queue);

/* Mark agent metadata for deletion after shutdown (pending queue drain) */
void agent_meta_mark_shutdown(const char* agent_id_str);

/* Periodic cleanup thread */
void* agent_meta_cleanup_thread(void* events_queue);

void agent_meta_free(agent_meta_t* m);
void agent_meta_clear(agent_meta_t* m);

#endif /* AGENT_METADATA_DB_H */
