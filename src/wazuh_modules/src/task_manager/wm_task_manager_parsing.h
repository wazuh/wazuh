/*
 * Wazuh Module for Task Manager
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WM_TASK_MANAGER_PARSING_H
#define WM_TASK_MANAGER_PARSING_H

#include "wm_task_manager.h"

/**
 * Parse received task manager message and returns action type
 *
 * Supported actions:
 * - create_task
 * - get_pending_tasks
 *
 * Example create_task:
 * {
 *     "action": "create_task",
 *     "agent_id": "001",
 *     "task_type": "active_response",
 *     "create_time": 1234567890,
 *     "source_id": "ar-doc-id-123",
 *     "payload": {
 *         "command": "firewall-drop",
 *         "arguments": ["192.168.1.100"]
 *     }
 * }
 *
 * Example get_pending_tasks:
 * {
 *     "action": "get_pending_tasks",
 *     "agent_id": "001"
 * }
 *
 * @param buffer message to be parsed
 * @param params on success command params will be stored here (caller must free)
 * @param error on error, error message will be stored here (caller must free)
 * @return action type
 * @retval OS_INVALID on errors
 * @retval WM_TASK_MANAGER_CREATE for create_task action
 * @retval WM_TASK_MANAGER_GET_PENDING for get_pending_tasks action
 */
int wm_task_manager_parse_message(const char* buffer, void** params, char** error);

/**
 * Create error response JSON
 *
 * Example:
 * {
 *     "error": "invalid_json",
 *     "message": "Failed to parse JSON request"
 * }
 *
 * @param error error code
 * @param message error message (optional)
 * @return response JSON string (caller must free)
 */
char* wm_task_manager_parse_error_response(const char *error, const char *message);

/**
 * Create success response JSON for create_task
 *
 * Example:
 * {
 *     "status": "ok",
 *     "task_id": "12345678-1234-5678-1234-567812345678"
 * }
 *
 * @param task_id task identifier
 * @return response JSON string (caller must free)
 */
char* wm_task_manager_parse_create_response(const char *task_id);

/**
 * Create success response JSON for get_pending_tasks
 *
 * Example:
 * {
 *     "status": "ok",
 *     "tasks": [...]
 * }
 *
 * @param tasks tasks array (will be added to response)
 * @return response JSON string (caller must free)
 */
char* wm_task_manager_parse_get_pending_response(cJSON *tasks);

#endif
