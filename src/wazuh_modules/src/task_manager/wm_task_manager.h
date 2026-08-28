/*
 * Wazuh Module for Task management.
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WM_TASK_MANAGER_H
#define WM_TASK_MANAGER_H

#define WM_TASK_MANAGER_LOGTAG ARGV0 ":" TASK_MANAGER_WM_NAME

/**
 * Enumeration of generic task types
 * */
typedef enum _wm_task_type {
    WM_TASK_TYPE_ACTIVE_RESPONSE = 0,
    WM_TASK_TYPE_REMOTE_UPGRADE,
    WM_TASK_TYPE_AGENT_RESTART,
    WM_TASK_TYPE_AGENT_RELOAD,
    WM_TASK_TYPE_COUNT  // Keep last - used for array bounds checking
} wm_task_type;

// Defaults
#define WM_TASK_DEFAULT_TTL 3600 // 1 hour
#define WM_TASK_DEFAULT_CLEANUP_INTERVAL 300 // 5 minutes
#define WM_TASK_DEFAULT_MAX_PAYLOAD_BYTES 1048576 // 1 MB
#define WM_TASK_DEFAULT_MAX_TASKS_PER_POLL 100 // Maximum tasks returned per poll

typedef struct _wm_task_manager {
    int enabled:1;
    int task_ttl;              // Time-to-live for all tasks (default: 1 hour)
    int cleanup_interval;      // Cleanup thread interval (default: 5 minutes)
    int max_payload_bytes;     // Maximum task payload size (default: 1 MB)
    int max_tasks_per_poll;    // Maximum tasks per get_pending_tasks call (default: 100)
} wm_task_manager;

typedef enum _error_code {
    WM_TASK_SUCCESS = 0,
    WM_TASK_DATABASE_ERROR,
    WM_TASK_DATABASE_PARSE_ERROR,
    WM_TASK_DATABASE_REQUEST_ERROR,
    WM_TASK_UNKNOWN_ERROR
} error_code;

/**
 * Task Manager action types
 */
typedef enum _wm_task_manager_action {
    WM_TASK_MANAGER_CREATE = 0,
    WM_TASK_MANAGER_GET_PENDING
} wm_task_manager_action;

/**
 * Create task parameters
 */
typedef struct _wm_task_create_params {
    char *agent_id;
    wm_task_type task_type;
    time_t create_time;
    char *source_id;
    char *payload_json;
} wm_task_create_params;

/**
 * Get pending tasks parameters
 */
typedef struct _wm_task_get_pending_params {
    char *agent_id;
} wm_task_get_pending_params;

extern const wm_context WM_TASK_MANAGER_CONTEXT;   // Context

// Parse XML configuration
int wm_task_manager_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

/**
 * Set tasks status to TIMEOUT after they are IN PROGRESS for a long period of time.
 * Delete entries older than a configurable period of time from the tasks DB.
 * @param arg Module configuration.
 * */
void* wm_task_manager_clean_tasks(void *arg) __attribute__((nonnull));

/**
 * Create a new generic task
 * @param agent_id Agent identifier
 * @param task_type Task type enum
 * @param payload_json Complete JSON payload as string
 * @param source_id Optional source ID (AR doc ID, API request ID, etc.)
 * @param create_time Task creation timestamp (from source document, e.g., AR @timestamp)
 * @param max_payload_bytes Maximum allowed payload size in bytes (0 = use default)
 * @return task_id on success, NULL on error (caller must free)
 */
char* wm_task_manager_create_task(
    const char *agent_id,
    wm_task_type task_type,
    const char *payload_json,
    const char *source_id,
    time_t create_time,
    int max_payload_bytes
) __attribute__((nonnull(1,3)));

/**
 * Get pending tasks for an agent (automatically marks them as delivered)
 * @param agent_id Agent identifier
 * @param max_tasks Maximum number of tasks to return (0 = use default)
 * @return JSON array of tasks, NULL on error (caller must free with cJSON_Delete)
 */
cJSON* wm_task_manager_get_pending_tasks(const char *agent_id, int max_tasks) __attribute__((nonnull(1)));

/**
 * Socket message dispatcher for generic task API
 * Handles JSON messages with actions: create_task, get_pending_tasks
 * @param msg JSON message string
 * @return JSON response string (caller must free)
 */
char* wm_task_manager_dispatch(const char *msg) __attribute__((nonnull));

#endif
