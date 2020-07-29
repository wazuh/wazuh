/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_tasks.h"
#include "wm_agent_upgrade_parsing.h"
#include "os_net/os_net.h"
#include "shared.h"

/* Hash table of current tasks based on agent_id */
static OSHash *task_table_by_agent_id;

wm_upgrade_task* wm_agent_upgrade_init_upgrade_task() {
    wm_upgrade_task *task;
    os_calloc(1, sizeof(wm_upgrade_task), task);
    task->custom_version = NULL;
    task->wpk_repository = NULL;
    task->force_upgrade = false;
    task->use_http = false;
    return task;
}

wm_upgrade_custom_task* wm_agent_upgrade_init_upgrade_custom_task() {
    wm_upgrade_custom_task *task;
    os_calloc(1, sizeof(wm_upgrade_custom_task), task);
    task->custom_file_path = NULL;
    task->custom_installer = NULL;
    return task;
}

wm_task_info* wm_agent_upgrade_init_task_info() {
    wm_task_info *task_info = NULL;
    os_calloc(1, sizeof(wm_task_info), task_info);
    task_info->task = NULL;
    return task_info;
}

wm_agent_info* wm_agent_upgrade_init_agent_info() {
    wm_agent_info *agent_info = NULL;
    os_calloc(1, sizeof(wm_agent_info), agent_info);
    agent_info->platform = NULL;
    agent_info->major_version = NULL;
    agent_info->minor_version = NULL;
    agent_info->architecture = NULL;
    agent_info->wazuh_version = NULL;
    return agent_info;
}

wm_agent_task* wm_agent_upgrade_init_agent_task() {
    wm_agent_task *agent_task = NULL;
    os_calloc(1, sizeof(wm_agent_task), agent_task);
    agent_task->agent_info = NULL;
    agent_task->task_info = NULL;
    return agent_task;
}

void wm_agent_upgrade_free_upgrade_task(wm_upgrade_task* upgrade_task) {
    if (upgrade_task) {
        os_free(upgrade_task->custom_version);
        os_free(upgrade_task->wpk_repository);
        os_free(upgrade_task);
    }
    upgrade_task = NULL;
}

void wm_agent_upgrade_free_upgrade_custom_task(wm_upgrade_custom_task* upgrade_custom_task) {
    if (upgrade_custom_task) {
        os_free(upgrade_custom_task->custom_file_path);
        os_free(upgrade_custom_task->custom_installer);
        os_free(upgrade_custom_task);
    }
    upgrade_custom_task = NULL;
}

void wm_agent_upgrade_free_task_info(wm_task_info* task_info) {
    if (task_info) {
        if (task_info->task) {
            if (WM_UPGRADE_UPGRADE == task_info->command) {
                wm_agent_upgrade_free_upgrade_task((wm_upgrade_task*)task_info->task);
            } else if (WM_UPGRADE_UPGRADE_CUSTOM == task_info->command) {
                wm_agent_upgrade_free_upgrade_custom_task((wm_upgrade_custom_task*)task_info->task);
            }
        }
        os_free(task_info);
    }
    task_info = NULL;
}

void wm_agent_upgrade_free_agent_info(wm_agent_info* agent_info) {
    if (agent_info) {
        os_free(agent_info->platform);
        os_free(agent_info->major_version);
        os_free(agent_info->minor_version);
        os_free(agent_info->architecture);
        os_free(agent_info->wazuh_version);
        os_free(agent_info);
    }
    agent_info = NULL;
}

void wm_agent_upgrade_free_agent_task(wm_agent_task* agent_task) {
    if (agent_task->agent_info) {
        wm_agent_upgrade_free_agent_info(agent_task->agent_info);
    }
    if (agent_task->task_info) {
        wm_agent_upgrade_free_task_info(agent_task->task_info);
    }
    os_free(agent_task);
    agent_task = NULL;
}

void wm_agent_upgrade_init_task_map() {
    task_table_by_agent_id = OSHash_Create();
}

void wm_agent_upgrade_destroy_task_map() {
    OSHash_Free(task_table_by_agent_id);
}

int wm_agent_upgrade_create_task_entry(int agent_id, wm_agent_task* agent_task) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    return OSHash_Add_ex(task_table_by_agent_id, agent_id_string, agent_task);
}

void wm_agent_upgrade_insert_task_id(int agent_id, int task_id) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    wm_agent_task *agent_task = (wm_agent_task *)OSHash_Get_ex(task_table_by_agent_id, agent_id_string);
    if (agent_task) {
        agent_task->task_info->task_id = task_id;
        OSHash_Update_ex(task_table_by_agent_id, agent_id_string, agent_task);
    }
}

void wm_agent_upgrade_remove_entry(int agent_id) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    wm_agent_task *agent_task = (wm_agent_task *)OSHash_Delete_ex(task_table_by_agent_id, agent_id_string);
    if (agent_task) {
        wm_agent_upgrade_free_agent_task(agent_task);
    }
}

cJSON* wm_agent_upgrade_send_tasks_information(const cJSON *message_object) {
    cJSON* response = NULL;

    int sock = OS_ConnectUnixDomain(WM_TASK_MODULE_SOCK_PATH, SOCK_STREAM, OS_MAXSTR);

    if (sock == OS_SOCKTERR) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNREACHEABLE_TASK_MANAGER, WM_TASK_MODULE_SOCK_PATH);
    } else {
        char *buffer = NULL;
        int length;
        char *message = cJSON_PrintUnformatted(message_object);
        mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TASK_SEND_MESSAGE, message);

        OS_SendSecureTCP(sock, strlen(message), message);
        os_free(message);
        os_calloc(OS_MAXSTR, sizeof(char), buffer);

        switch (length = OS_RecvSecureTCP(sock, buffer, OS_MAXSTR), length) {
            case OS_SOCKTERR:
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SOCKTERR_ERROR);
                break;
            case -1:
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RECV_ERROR, strerror(errno));
                break;
            case 0:
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TASK_EMPTY_MESSAGE);
                break;
            default:
                response = cJSON_Parse(buffer);
                if (!response) {
                    mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_TASK_MAN_JSON);
                } else {
                    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TASK_RECEIVE_MESSAGE, buffer);
                }
                break;
        }
        os_free(buffer);
    }

    return response;
}
