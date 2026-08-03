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
#ifndef WM_TASK_MANAGER_TASKS_H
#define WM_TASK_MANAGER_TASKS_H

#include "wm_task_manager.h"

/**
 * Generate deterministic task ID from source information
 * All managers generate IDENTICAL ID from same inputs
 *
 * @param source_id Optional source ID (AR document ID, API request ID, etc.)
 * @param agent_id Agent identifier
 * @param task_type Task type string ("active_response", "remote_upgrade", etc.)
 * @param create_time Unix timestamp (second precision)
 * @return Deterministic task ID (UUID format string), caller must free
 */
char* wm_task_manager_generate_task_id(
    const char *source_id,
    const char *agent_id,
    const char *task_type,
    time_t create_time
);

/**
 * Initialize task cache
 * Cache only stores "no pending tasks" states - actual tasks are never cached
 */
void wm_task_cache_init(void);

/**
 * Get tasks from cache
 * @param agent_id Agent identifier
 * @return Empty array if agent has no pending tasks (cached state), or NULL if cache miss
 */
cJSON* wm_task_cache_get(const char *agent_id);

/**
 * Set tasks in cache
 * Only caches empty task arrays (no pending tasks state)
 * @param agent_id Agent identifier
 * @param tasks Tasks array - only empty arrays are cached
 */
void wm_task_cache_set(const char *agent_id, cJSON *tasks);

/**
 * Invalidate cache entry for an agent
 * @param agent_id Agent identifier
 */
void wm_task_cache_invalidate(const char *agent_id);

/**
 * Destroy task cache and free all resources
 * Should be called at shutdown or in test cleanup
 */
void wm_task_cache_destroy(void);

#endif
