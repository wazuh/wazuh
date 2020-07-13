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
#include "wm_agent_upgrade.h"
#include "os_net/os_net.h"
#include "shared.h"

/* Hash table of current tasks based on agent_id */
static OSHash *task_table_by_agent_id;


wm_upgrade_task* wm_agent_init_upgrade_task() {
    wm_upgrade_task *task;
    os_malloc(sizeof(wm_upgrade_task), task);
    task->custom_file_path = NULL;
    task->custom_installer = NULL;
    task->custom_version = NULL;
    task->wpk_repository = NULL;
    task->force_upgrade = false;
    task->use_http = false;
    task->state = NOT_STARTED;
    return task;
}

void wm_agent_free_upgrade_task(wm_upgrade_task* task) {
    os_free(task->custom_file_path);
    os_free(task->custom_installer);
    os_free(task->custom_version);
    os_free(task->wpk_repository);
    os_free(task);
}


void wm_agent_create_agent_tasks(cJSON *agents, void *task, const char* command, cJSON* response, cJSON* failures) {
    assert(agents != NULL);
    assert(task != NULL);
    assert(command != NULL);
    assert(response && (response->type == cJSON_Array));
    assert(failures && (failures->type == cJSON_Array));

    for(int i=0; i < cJSON_GetArraySize(agents); i++) {
        wm_agent_task *agent_task;
        os_malloc(sizeof(wm_agent_task), agent_task);
        os_strdup(command, agent_task->command);
        agent_task->task = task;
        cJSON* agent_id = cJSON_GetArrayItem(agents, i);
        agent_task->agent = agent_id->valueint;
        char agent_id_string[128];
        sprintf(agent_id_string, "%d", agent_id->valueint);
        int result = OSHash_Add(task_table_by_agent_id, agent_id_string, agent_task);
        if (result == 2 ) {
           cJSON *task_message = wm_agent_parse_task_module_message(agent_task->command, agent_task->agent);
           cJSON_AddItemToArray(response, task_message);
        } else if (result == 1) {
            cJSON *task_message = wm_agent_parse_response_mesage(1, "Upgrade procedure could not start. Agent already upgrading", agent_task->agent, NULL);
            cJSON_AddItemToArray(failures, task_message);
        } else {
            cJSON *task_message = wm_agent_parse_response_mesage(1, "Upgrade procedure could not start", agent_task->agent, NULL);
            cJSON_AddItemToArray(failures, task_message);
        }
    }
}

void wm_agent_init_task_table() {
    task_table_by_agent_id = OSHash_Create();
}


void wm_agent_destroy_task_table() {
    OSHash_Free(task_table_by_agent_id);
}

cJSON *wm_agent_send_task_information(cJSON *message) {
    cJSON* response = NULL;
    int sock = OS_ConnectUnixDomain(WM_TASK_MODULE_SOCK_PATH, SOCK_STREAM, OS_MAXSTR);
    if (sock == OS_SOCKTERR) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, "Cannot connect to: %s. Could not reach task manager module", WM_AGENT_UPGRADE_LOGTAG);
    } else {
        char *buffer = NULL;
        int length;
        OS_SendTCP(sock, cJSON_Print(message));
        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvTCPBuffer(sock, buffer, OS_MAXSTR), length) {
            case OS_SOCKTERR:
                mterror(WM_AGENT_UPGRADE_LOGTAG, "OS_RecvSecureTCP(): Too big message size received from task manager module.");
                break;
            case -1:
                mterror(WM_AGENT_UPGRADE_LOGTAG, "OS_RecvSecureTCP(): %s", strerror(errno));
                break;
            case 0:
                mterror(WM_AGENT_UPGRADE_LOGTAG, "Empty message from task manager module.");
                break;
            default:
                response = cJSON_Parse(buffer);
                if (!response) {
                    mterror(WM_AGENT_UPGRADE_LOGTAG, "Response from task manager does not have a valid JSON format");
                }
                break;
        }
        os_free(buffer);
    }
    return response;
}
