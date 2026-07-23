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
#include "openssl/sha.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// In-memory cache structure
typedef struct cache_entry {
    char *agent_id;
    cJSON *tasks;
    time_t timestamp;
    struct cache_entry *next;
} cache_entry_t;

typedef struct {
    cache_entry_t *head;
    pthread_rwlock_t lock;
    int ttl;
} task_cache_t;

// Global cache instance
static task_cache_t *g_task_cache = NULL;

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
void wm_task_cache_init(int ttl) {
    g_task_cache = calloc(1, sizeof(task_cache_t));
    if (!g_task_cache) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to allocate task cache");
        return;
    }
    g_task_cache->ttl = ttl;
    pthread_rwlock_init(&g_task_cache->lock, NULL);
    g_task_cache->head = NULL;
}

// Get from cache
cJSON* wm_task_cache_get(const char *agent_id) {
    if (!g_task_cache) return NULL;

    pthread_rwlock_rdlock(&g_task_cache->lock);

    time_t now = time(NULL);
    cache_entry_t *entry = g_task_cache->head;

    while (entry) {
        if (strcmp(entry->agent_id, agent_id) == 0) {
            // Check if expired
            if (now - entry->timestamp < g_task_cache->ttl) {
                cJSON *tasks_copy = cJSON_Duplicate(entry->tasks, 1);
                pthread_rwlock_unlock(&g_task_cache->lock);
                return tasks_copy;
            }
            break;
        }
        entry = entry->next;
    }

    pthread_rwlock_unlock(&g_task_cache->lock);
    return NULL;
}

// Set in cache
void wm_task_cache_set(const char *agent_id, cJSON *tasks) {
    if (!g_task_cache) return;

    pthread_rwlock_wrlock(&g_task_cache->lock);

    // Remove existing entry
    cache_entry_t *prev = NULL;
    cache_entry_t *entry = g_task_cache->head;

    while (entry) {
        if (strcmp(entry->agent_id, agent_id) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                g_task_cache->head = entry->next;
            }
            free(entry->agent_id);
            cJSON_Delete(entry->tasks);
            free(entry);
            break;
        }
        prev = entry;
        entry = entry->next;
    }

    // Add new entry
    cache_entry_t *new_entry = calloc(1, sizeof(cache_entry_t));
    if (new_entry) {
        new_entry->agent_id = strdup(agent_id);
        new_entry->tasks = cJSON_Duplicate(tasks, 1);

        // Check for allocation failures
        if (!new_entry->agent_id || !new_entry->tasks) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Failed to allocate cache entry for agent %s", agent_id);
            if (new_entry->agent_id) {
                free(new_entry->agent_id);
            }
            if (new_entry->tasks) {
                cJSON_Delete(new_entry->tasks);
            }
            free(new_entry);
        } else {
            new_entry->timestamp = time(NULL);
            new_entry->next = g_task_cache->head;
            g_task_cache->head = new_entry;
        }
    }

    pthread_rwlock_unlock(&g_task_cache->lock);
}

// Invalidate cache entry
void wm_task_cache_invalidate(const char *agent_id) {
    if (!g_task_cache) return;

    pthread_rwlock_wrlock(&g_task_cache->lock);

    cache_entry_t *prev = NULL;
    cache_entry_t *entry = g_task_cache->head;

    while (entry) {
        if (strcmp(entry->agent_id, agent_id) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                g_task_cache->head = entry->next;
            }
            free(entry->agent_id);
            cJSON_Delete(entry->tasks);
            free(entry);
            break;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_rwlock_unlock(&g_task_cache->lock);
}
