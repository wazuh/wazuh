/*
 * Wazuh Module for Task Manager
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"
#include "wm_task_manager_tasks.h"
#include "hash_op.h"
#include "openssl/sha.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// Simplified cache for "no pending tasks" state using OSHash
// Only stores agent IDs that have no pending tasks
// Cache is invalidated when new tasks are created via wm_task_manager_create_task()
// Uses Wazuh's OSHash for efficient lookups
static OSHash *g_task_cache = NULL;

// Generate deterministic task ID
char* wm_task_manager_generate_task_id(
    const char *source_id,
    const char *agent_id,
    const char *task_type,
    time_t create_time
) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char input[OS_MAXSTR];
    char *task_id = NULL;

    // Build deterministic input string
    if (source_id && *source_id) {
        snprintf(input, OS_MAXSTR, "%s:%s:%s:%ld",
                 source_id, agent_id, task_type, (long)create_time);
    } else {
        snprintf(input, OS_MAXSTR, "%s:%s:%ld",
                 agent_id, task_type, (long)create_time);
    }

    // SHA256 hash
    SHA256((unsigned char*)input, strlen(input), hash);

    // Format as UUID-like string (first 16 bytes)
    os_calloc(37, sizeof(char), task_id);
    snprintf(task_id, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             hash[0], hash[1], hash[2], hash[3],
             hash[4], hash[5], hash[6], hash[7],
             hash[8], hash[9], hash[10], hash[11],
             hash[12], hash[13], hash[14], hash[15]);

    return task_id;
}

// Initialize cache
void wm_task_cache_init(void) {
    // Clean up existing cache if any
    if (g_task_cache) {
        wm_task_cache_destroy();
    }

    g_task_cache = OSHash_Create();
    if (!g_task_cache) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to create task cache");
        return;
    }
}

// Get from cache
// Returns empty array if agent has no pending tasks (cached state)
// Returns NULL if cache miss (need to query DB)
cJSON* wm_task_cache_get(const char *agent_id) {
    if (!g_task_cache) return NULL;

    // Check if agent is in cache (meaning it has no pending tasks)
    void *result = OSHash_Get(g_task_cache, agent_id);

    if (result) {
        // Cache hit: agent has no pending tasks
        return cJSON_CreateArray();
    }

    // Cache miss
    return NULL;
}

// Set in cache
// Only call this when agent has NO pending tasks
// NEVER cache actual tasks - they must be delivered only once
void wm_task_cache_set(const char *agent_id, cJSON *tasks) {
    if (!g_task_cache) return;

    // Only cache empty states
    if (!tasks || cJSON_GetArraySize(tasks) > 0) {
        return;
    }

    // Add agent to cache (value is just a marker, we use (void*)1)
    // OSHash_Set will add or update, no need to check if exists
    int result = OSHash_Set(g_task_cache, agent_id, (void*)1);

    if (result != OSHASH_SUCCESS && result != OSHASH_DUPLICATE) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to cache empty state for agent %s", agent_id);
    }
}

// Invalidate cache entry
void wm_task_cache_invalidate(const char *agent_id) {
    if (!g_task_cache) return;

    // Remove agent from cache
    OSHash_Delete(g_task_cache, agent_id);
}

// Destroy cache
void wm_task_cache_destroy(void) {
    if (!g_task_cache) return;

    // OSHash_Free handles all cleanup including mutex
    OSHash_Free(g_task_cache);
    g_task_cache = NULL;
}
