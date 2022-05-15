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

wm_task_manager_generic* wm_task_manager_init_generic_parameters() {
    wm_task_manager_generic *parameters;
    os_calloc(1, sizeof(wm_task_manager_generic), parameters);
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

wm_task_manager_result* wm_task_manager_init_result_parameters() {
    wm_task_manager_result *parameters;
    os_calloc(1, sizeof(wm_task_manager_result), parameters);
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

wm_task_manager_syscollector* wm_task_manager_init_syscollector_parameters() {
    wm_task_manager_syscollector *parameters;
    os_calloc(1, sizeof(wm_task_manager_syscollector), parameters);
    return parameters;
}

wm_task_manager_status* wm_task_manager_init_status_parameters() {
    wm_task_manager_status *parameters;
    os_calloc(1, sizeof(wm_task_manager_status), parameters);
    return parameters;
}

void wm_task_manager_free_generic_task_parameters(wm_task_manager_generic *parameters) {
    if (parameters) {
        os_free(parameters->agent_ids);
        os_free(parameters->error_msg);
        os_free(parameters->module);
        os_free(parameters->node);
        os_free(parameters->status);
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

void wm_task_manager_free_result_parameters(wm_task_manager_result* parameters) {
    if (parameters) {
        os_free(parameters->agent_ids);
        os_free(parameters->module);
        os_free(parameters);
    }
}

void wm_task_manager_free_upgrade_cancel_tasks_parameters(wm_task_manager_upgrade_cancel_tasks* parameters) {
    if (parameters) {
        os_free(parameters->node);
        os_free(parameters);
    }
}

void wm_task_manager_free_syscollector_tasks_parameters(wm_task_manager_syscollector *parameters) {
    if (parameters) {
        os_free(parameters->agent_ids);
        os_free(parameters->error_msg);
        os_free(parameters->module);
        os_free(parameters->node);
        os_free(parameters->status);
        os_free(parameters);
    }
}

void wm_task_manager_free_status_tasks_parameters(wm_task_manager_status *parameters) {
    if (parameters) {
        os_free(parameters->error_msg);
        os_free(parameters->status);
        os_free(parameters);
    }
}

void wm_task_manager_free_task(wm_task_manager_task* task) {
    if (task) {
        if (task->parameters) {
            switch (task->command)
            {
                case WM_TASK_UPGRADE:
                case WM_TASK_UPGRADE_CUSTOM:
                case WM_TASK_SYSCOLLECTOR_SCAN:
                    wm_task_manager_free_generic_task_parameters((wm_task_manager_generic*)task->parameters);
                    break;
                case WM_TASK_UPGRADE_GET_STATUS:
                    wm_task_manager_free_upgrade_get_status_parameters((wm_task_manager_upgrade_get_status*)task->parameters);
                    break;
                case WM_TASK_UPGRADE_UPDATE_STATUS:
                    wm_task_manager_free_upgrade_update_status_parameters((wm_task_manager_upgrade_update_status*)task->parameters);
                    break;
                case WM_TASK_UPGRADE_RESULT:
                case WM_TASK_SYSCOLLECTOR_RESULT:
                    wm_task_manager_free_result_parameters((wm_task_manager_result*)task->parameters);
                    break;
                case WM_TASK_UPGRADE_CANCEL_TASKS:
                    wm_task_manager_free_upgrade_cancel_tasks_parameters((wm_task_manager_upgrade_cancel_tasks*)task->parameters);
                    break;
                case WM_TASK_SYSCOLLECTOR_GET_STATUS:
                case WM_TASK_SYSCOLLECTOR_UPDATE_STATUS:
                    wm_task_manager_free_syscollector_tasks_parameters((wm_task_manager_syscollector*)task->parameters);
                    break;
                case WM_TASK_GET_STATUS:
                case WM_TASK_UPDATE_STATUS:
                    wm_task_manager_free_status_tasks_parameters((wm_task_manager_status*)task->parameters);
                    break;
                default:
                    break;
            }
        }
        os_free(task);
    }
}
