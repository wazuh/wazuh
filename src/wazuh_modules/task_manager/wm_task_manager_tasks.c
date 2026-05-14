/*
 * Wazuh Module for Agent Upgrading
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

#include "wazuh_modules/wmodules.h"
#include "wm_task_manager_tasks.h"

wm_task_manager_upgrade* wm_task_manager_init_upgrade_parameters() {
    wm_task_manager_upgrade *parameters;
    os_calloc(1, sizeof(wm_task_manager_upgrade), parameters);
    return parameters;
}

wm_task_manager_upgrade_get_status* wm_task_manager_init_upgrade_get_status_parameters() {
    wm_task_manager_upgrade_get_status *parameters;
    os_calloc(1, sizeof(wm_task_manager_upgrade_get_status), parameters);
    return parameters;
}

wm_task_manager_upgrade_update_status* wm_task_manager_init_upgrade_update_status_parameters() {
    wm_task_manager_upgrade_update_status *parameters;
    os_calloc(1, sizeof(wm_task_manager_upgrade_update_status), parameters);
    return parameters;
}

wm_task_manager_upgrade_result* wm_task_manager_init_upgrade_result_parameters() {
    wm_task_manager_upgrade_result *parameters;
    os_calloc(1, sizeof(wm_task_manager_upgrade_result), parameters);
    return parameters;
}

wm_task_manager_upgrade_cancel_tasks* wm_task_manager_init_upgrade_cancel_tasks_parameters() {
    wm_task_manager_upgrade_cancel_tasks *parameters;
    os_calloc(1, sizeof(wm_task_manager_upgrade_cancel_tasks), parameters);
    return parameters;
}

wm_task_manager_task* wm_task_manager_init_task() {
    wm_task_manager_task *task;
    os_calloc(1, sizeof(wm_task_manager_task), task);
    return task;
}

void wm_task_manager_free_upgrade_parameters(wm_task_manager_upgrade* parameters) {
    if (parameters) {
        os_free(parameters->node);
        os_free(parameters->module);
        os_free(parameters->agent_ids);
        os_free(parameters);
    }
}

void wm_task_manager_free_upgrade_get_status_parameters(wm_task_manager_upgrade_get_status* parameters) {
    if (parameters) {
        os_free(parameters->node);
        os_free(parameters->agent_ids);
        os_free(parameters);
    }
}

void wm_task_manager_free_upgrade_update_status_parameters(wm_task_manager_upgrade_update_status* parameters) {
    if (parameters) {
        os_free(parameters->node);
        os_free(parameters->agent_ids);
        os_free(parameters->status);
        os_free(parameters->error_msg);
        os_free(parameters);
    }
}

void wm_task_manager_free_upgrade_result_parameters(wm_task_manager_upgrade_result* parameters) {
    if (parameters) {
        os_free(parameters->agent_ids);
        os_free(parameters);
    }
}

void wm_task_manager_free_upgrade_cancel_tasks_parameters(wm_task_manager_upgrade_cancel_tasks* parameters) {
    if (parameters) {
        os_free(parameters->node);
        os_free(parameters);
    }
}

void wm_task_manager_free_task(wm_task_manager_task* task) {
    if (task) {
        if (task->parameters) {
            if ((WM_TASK_UPGRADE == task->command) || (WM_TASK_UPGRADE_CUSTOM == task->command)) {
                wm_task_manager_free_upgrade_parameters((wm_task_manager_upgrade*)task->parameters);
            } else if (WM_TASK_UPGRADE_GET_STATUS == task->command) {
                wm_task_manager_free_upgrade_get_status_parameters((wm_task_manager_upgrade_get_status*)task->parameters);
            } else if (WM_TASK_UPGRADE_UPDATE_STATUS == task->command) {
                wm_task_manager_free_upgrade_update_status_parameters((wm_task_manager_upgrade_update_status*)task->parameters);
            } else if (WM_TASK_UPGRADE_RESULT == task->command) {
                wm_task_manager_free_upgrade_result_parameters((wm_task_manager_upgrade_result*)task->parameters);
            } else if (WM_TASK_UPGRADE_CANCEL_TASKS == task->command) {
                wm_task_manager_free_upgrade_cancel_tasks_parameters((wm_task_manager_upgrade_cancel_tasks*)task->parameters);
            }
        }
        os_free(task);
    }
}
