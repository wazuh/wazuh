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

#include "wm_task_general.h"

const char *task_manager_json_keys[] = {
    // Request
    [WM_TASK_ORIGIN] = "origin",
    [WM_TASK_NAME] = "name",
    [WM_TASK_MODULE] = "module",
    [WM_TASK_COMMAND] = "command",
    [WM_TASK_PARAMETERS] = "parameters",
    [WM_TASK_AGENTS] = "agents",
    // Response
    [WM_TASK_ERROR] = "error",
    [WM_TASK_DATA] = "data",
    [WM_TASK_ERROR_MESSAGE] = "message",
    [WM_TASK_AGENT_ID] = "agent",
    [WM_TASK_TASK_ID] = "task_id",
    [WM_TASK_NODE] = "node",
    [WM_TASK_STATUS] = "status",
    [WM_TASK_ERROR_MSG] = "error_msg",
    [WM_TASK_CREATE_TIME] = "create_time",
    [WM_TASK_LAST_UPDATE_TIME] = "update_time",
    // Clean tasks request
    [WM_TASK_NOW] = "now",
    [WM_TASK_INTERVAL] = "interval",
    [WM_TASK_TIMESTAMP] = "timestamp"
};

const char *task_manager_commands_list[] = {
    [WM_TASK_UPGRADE] = "upgrade",
    [WM_TASK_UPGRADE_CUSTOM] = "upgrade_custom",
    [WM_TASK_UPGRADE_GET_STATUS] = "upgrade_get_status",
    [WM_TASK_UPGRADE_UPDATE_STATUS] = "upgrade_update_status",
    [WM_TASK_UPGRADE_RESULT] = "upgrade_result",
    [WM_TASK_UPGRADE_CANCEL_TASKS] = "upgrade_cancel_tasks",
    [WM_TASK_SET_TIMEOUT] = "set_timeout",
    [WM_TASK_DELETE_OLD] = "delete_old"
};

const char *task_manager_modules_list[] = {
    [WM_TASK_UPGRADE_MODULE] = "upgrade_module",
    [WM_TASK_API_MODULE] = "api"
};

const char *task_statuses[] = {
    [WM_TASK_PENDING] = WM_TASK_STATUS_PENDING,
    [WM_TASK_IN_PROGRESS] = WM_TASK_STATUS_IN_PROGRESS,
    [WM_TASK_DONE] = WM_TASK_STATUS_DONE,
    [WM_TASK_FAILED] = WM_TASK_STATUS_FAILED,
    [WM_TASK_CANCELLED] = WM_TASK_STATUS_CANCELLED,
    [WM_TASK_TIMEOUT] = WM_TASK_STATUS_TIMEOUT,
    [WM_TASK_LEGACY] = WM_TASK_STATUS_LEGACY
};
