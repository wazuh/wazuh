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

/**
 * Inserts a task_id into an already existent agent entry
 * @param task_id id of the task
 * @param agent_id id of the agent
 * */
static void wm_agent_upgrade_insert_tasks_id(const int task_id, const int agent_id);

/**
 * Creates an new entry into the table with the agent_id and task
 * @param agent_id id of the agent
 * @param task pointer to the task
 * */
static int wm_agent_upgrade_create_task_entry(const int agent_id, wm_task_info* task);

/**
 * Remoes a entry based on the agent_id
 * @param agent_id id of the agent
 * */
static void wm_agent_upgrade_remove_entry(const int agent_id);

/**
 * Sends json with task information to the task module and parses the response
 * to give back to the api
 * @param json_response cJSON array where the task responses will be stored
 * @param json_task_module cJSON to be sent to the task module
 * */
static void wm_agent_upgrade_parse_create_tasks_information(cJSON *json_response, const cJSON* json_task_module);

/**
 * Sends the JSON information to the task module and retrieves the answer
 * @param message_object JSON to be sent. Example:
 *  [{
 *       "module" : "upgrade_module",
 *       "command": "upgrade",
 *       "agent" : 1
 *   }, {
 *       "module" : "upgrade_module",
 *       "command": "upgrade",
 *       "agent" : 2
 *  }]
 * @return json response
 * @retval NULL if connection problem or incorrect response format
 * @retval JSON with the task information. Example:
 *  [{
 *       "error": 0,
 *       "data": "Task created successfully",
 *       "agent": 1,
 *       "task_id": {{tid1}}
 *   }, {
 *       "error": 0,
 *       "data": "Task created successfully",
 *       "agent": 2,
 *       "task_id": {{tid2}}
 *  }]
 * */
static cJSON* wm_agent_upgrade_send_tasks_information(const cJSON *message_object);

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
    return agent_info;
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
        os_free(agent_info);
    }
    agent_info = NULL;
}

void wm_agent_upgrade_init_task_map() {
    task_table_by_agent_id = OSHash_Create();
}

void wm_agent_upgrade_destroy_task_map() {
    OSHash_Free(task_table_by_agent_id);
}

void wm_agent_upgrade_insert_tasks_id(const int task_id, const int agent_id) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    wm_task_info *task_info = (wm_task_info *)OSHash_Get_ex(task_table_by_agent_id, agent_id_string);
    assert(task_info);
    if (task_info) {
        task_info->task_id = task_id;
        OSHash_Update_ex(task_table_by_agent_id, agent_id_string, task_info);
    }
}

int wm_agent_upgrade_create_task_entry(const int agent_id, wm_task_info* task) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    return OSHash_Add_ex(task_table_by_agent_id, agent_id_string, task);
}

void wm_agent_upgrade_remove_entry(const int agent_id) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    OSHash_Delete_ex(task_table_by_agent_id, agent_id_string);
}

void wm_agent_upgrade_create_agents_tasks(cJSON* json_response, const int* agent_ids, int command, void *task) {
    cJSON *json_task_module = cJSON_CreateArray();
    int agent = 0;
    int agent_id = 0;

    while (agent_id = agent_ids[agent++], agent_id) {
        cJSON *task_message = NULL;
        wm_task_info *task_info = wm_agent_upgrade_init_task_info();

        task_info->command = command;
        task_info->task = task;

        // Save task entry for agent
        int result = wm_agent_upgrade_create_task_entry(agent_id, task_info);

        if (result == OSHASH_SUCCESS) {
            task_message = wm_agent_upgrade_parse_task_module_message(task_info->command, agent_id);
            cJSON_AddItemToArray(json_task_module, task_message);
        } else if (result == OSHASH_DUPLICATED) {
            task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_UPGRADE_ALREADY_ON_PROGRESS, upgrade_error_codes[WM_UPGRADE_UPGRADE_ALREADY_ON_PROGRESS], &(agent_id), NULL, NULL);
            cJSON_AddItemToArray(json_response, task_message);
        } else {
            task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_UNKNOWN_ERROR, upgrade_error_codes[WM_UPGRADE_UNKNOWN_ERROR], &(agent_id), NULL, NULL);
            cJSON_AddItemToArray(json_response, task_message);
        }
    }

    // Update tasks with task module infomation
    if (cJSON_GetArraySize(json_task_module)) {
        wm_agent_upgrade_parse_create_tasks_information(json_response, json_task_module);
    }

    cJSON_Delete(json_task_module);
}

void wm_agent_upgrade_parse_create_tasks_information(cJSON *json_response, const cJSON* json_task_module) {
    // Create task for agent in task module
    cJSON *task_module_response = wm_agent_upgrade_send_tasks_information(json_task_module);

    if (task_module_response && (task_module_response->type == cJSON_Array)) {
        // Parse task module responses into API
        while(cJSON_GetArraySize(task_module_response)) {
            cJSON *task_response = cJSON_DetachItemFromArray(task_module_response, 0);
            int agent_id = cJSON_GetObjectItem(task_response, "agent")->valueint;

            if (cJSON_HasObjectItem(task_response, "task_id")) {
                // Store task_id
                int task_id = cJSON_GetObjectItem(task_response, "task_id")->valueint;
                wm_agent_upgrade_insert_tasks_id(task_id, agent_id);
                cJSON_AddItemToArray(json_response, task_response);
            } else {
                // Remove from table since upgrade will not be started
                wm_agent_upgrade_remove_entry(agent_id);
                cJSON *json_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_TASK_MANAGER_FAILURE, cJSON_GetObjectItem(task_response, "data")->valuestring, &agent_id, NULL, NULL);
                cJSON_AddItemToArray(json_response, json_message);
                cJSON_Delete(task_response);
            }
        }
    } else {
        for(int i=0; i < cJSON_GetArraySize(json_task_module); i++) {
            int agent_id = cJSON_GetObjectItem(cJSON_GetArrayItem(json_task_module, i), "agent")->valueint;
            // Remove from table since upgrade will not be started
            wm_agent_upgrade_remove_entry(agent_id);
            cJSON *json_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_TASK_MANAGER_COMMUNICATION, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION], &agent_id, NULL, NULL);
            cJSON_AddItemToArray(json_response, json_message);
        }
    }

    cJSON_Delete(task_module_response);
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
