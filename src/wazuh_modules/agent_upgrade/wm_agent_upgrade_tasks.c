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
 * @param agent_task pointer to the task
 * */
static int wm_agent_upgrade_create_task_entry(const int agent_id, wm_task*  agent_task);

/**
 * Remoes a entry based on the agent_id
 * @param agent_id id of the agent
 * */
static void wm_agent_upgrade_remove_entry(const int agent_id);

/**
 * Sends json with task information to the task module and parses the response
 * to give back to the api
 * @param json_api cJSON array where the task response will be stored
 * @param json_task_module cJSON to be sent to the task module
 * */
static void wm_agent_upgrade_parse_create_tasks_information(cJSON *json_api, const cJSON* json_task_module);

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
static cJSON *wm_agent_upgrade_send_tasks_information(const cJSON *message_object);

/* Hash table of current tasks based on agent_id */
static OSHash *task_table_by_agent_id;

wm_upgrade_task* wm_agent_upgrade_init_upgrade_task() {
    wm_upgrade_task *task;
    os_malloc(sizeof(wm_upgrade_task), task);
    task->custom_version = NULL;
    task->wpk_repository = NULL;
    task->force_upgrade = false;
    task->use_http = false;
    return task;
}

wm_upgrade_custom_task* wm_agent_upgrade_init_upgrade_custom_task() {
    wm_upgrade_custom_task *task;
    os_malloc(sizeof(wm_upgrade_custom_task), task);
    task->custom_file_path = NULL;
    task->custom_installer = NULL;
    return task;
}

void wm_agent_upgrade_free_upgrade_task(wm_upgrade_task* task) {
    os_free(task->custom_version);
    os_free(task->wpk_repository);
    os_free(task);
}

void wm_agent_upgrade_free_upgrade_custom_task(wm_upgrade_custom_task* task) {
    os_free(task->custom_file_path);
    os_free(task->custom_installer);
    os_free(task);
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
    wm_task *agent_task = (wm_task *)OSHash_Get_ex(task_table_by_agent_id, agent_id_string);
    assert(agent_task);
    if (agent_task) {
        agent_task->task_id = task_id;
        OSHash_Update_ex(task_table_by_agent_id, agent_id_string, agent_task);
    }
}

int wm_agent_upgrade_create_task_entry(const int agent_id, wm_task* agent_task) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    return OSHash_Add_ex(task_table_by_agent_id, agent_id_string, agent_task);
}

void wm_agent_upgrade_remove_entry(const int agent_id) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    OSHash_Delete_ex(task_table_by_agent_id, agent_id_string);
}

cJSON* wm_agent_upgrade_create_agent_tasks(const cJSON *agents, void *task, wm_upgrade_command command) {
    assert(agents && (agents->type == cJSON_Array));
    assert(task != NULL);

    cJSON *json_api = cJSON_CreateArray();
    cJSON *json_task_module = cJSON_CreateArray();

    for(int i=0; i < cJSON_GetArraySize(agents); i++) {
        cJSON* agent_id = cJSON_GetArrayItem(agents, i);
        wm_task *agent_task;

        os_malloc(sizeof(wm_task), agent_task);
        agent_task->state = WM_UPGRADE_NOT_STARTED;
        agent_task->command = command;
        agent_task->task = task;

        if (wm_agent_upgrade_validate_id(agent_id->valueint) < 0){
            cJSON *task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_NOT_AGENT_IN_DB, upgrade_error_codes[WM_UPGRADE_NOT_AGENT_IN_DB], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(json_api, task_message);
            continue;
        }
        
        int validate_ver_result = wm_agent_upgrade_validate_agent_version(agent_id->valueint, task, command);
        if ( validate_ver_result == WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED){
            cJSON *task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED, upgrade_error_codes[WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(json_api, task_message);
            continue;
        }else if ( validate_ver_result == WM_UPGRADE_NEW_VERSION_GREATER_MASTER){
            cJSON *task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_NEW_VERSION_GREATER_MASTER, upgrade_error_codes[WM_UPGRADE_NEW_VERSION_GREATER_MASTER], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(json_api, task_message);
            continue;
        }else if ( validate_ver_result == WM_UPGRADE_VERSION_SAME_MANAGER){
            cJSON *task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_VERSION_SAME_MANAGER, upgrade_error_codes[WM_UPGRADE_VERSION_SAME_MANAGER], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(json_api, task_message);
            continue;
        }else if ( validate_ver_result == WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT){
            cJSON *task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT, upgrade_error_codes[WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(json_api, task_message);
            continue;
        }
        
        

        // Save task entry for agent
        int result = wm_agent_upgrade_create_task_entry(agent_id->valueint, agent_task);

        if (result == OSHASH_SUCCESS ) {
            cJSON *task_message = wm_agent_upgrade_parse_task_module_message(agent_task->command, agent_id->valueint);
            cJSON_AddItemToArray(json_task_module, task_message);
        } else if (result == OSHASH_DUPLICATED) {
            cJSON *task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_UPGRADE_ALREADY_ON_PROGRESS, upgrade_error_codes[WM_UPGRADE_UPGRADE_ALREADY_ON_PROGRESS], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(json_api, task_message);
            os_free(agent_task);
        } else {
            cJSON *task_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_UNKNOWN_ERROR, upgrade_error_codes[WM_UPGRADE_UNKNOWN_ERROR], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(json_api, task_message);
            os_free(agent_task);
        }
    }

    // Update tasks with task module infomation
    if (cJSON_GetArraySize(json_task_module)) {
        wm_agent_upgrade_parse_create_tasks_information(json_api, json_task_module);
    } else if (WM_UPGRADE_UPGRADE == command) {
        wm_agent_upgrade_free_upgrade_task((wm_upgrade_task *)task);
    } else if (WM_UPGRADE_UPGRADE_CUSTOM == command) {
        wm_agent_upgrade_free_upgrade_custom_task((wm_upgrade_custom_task *)task);
    }

    cJSON_Delete(json_task_module);

    return json_api;
}

void wm_agent_upgrade_parse_create_tasks_information(cJSON *json_api, const cJSON* json_task_module) {
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
                cJSON_AddItemToArray(json_api, task_response);
            } else {
                // Remove from table since upgrade will not be started
                wm_agent_upgrade_remove_entry(agent_id);
                cJSON *json_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_TASK_MANAGER_FAILURE, cJSON_GetObjectItem(task_response, "data")->valuestring, &agent_id, NULL, NULL);
                cJSON_AddItemToArray(json_api, json_message);
                cJSON_Delete(task_response);
            }
        }
    } else {
        for(int i=0; i < cJSON_GetArraySize(json_task_module); i++) {
            int agent_id = cJSON_GetObjectItem(cJSON_GetArrayItem(json_task_module, i), "agent")->valueint;
            // Remove from table since upgrade will not be started
            wm_agent_upgrade_remove_entry(agent_id);
            cJSON *json_message = wm_agent_upgrade_parse_response_message(WM_UPGRADE_TASK_MANAGER_COMMUNICATION, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION], &agent_id, NULL, NULL);
            cJSON_AddItemToArray(json_api, json_message);
        }
    }

    cJSON_Delete(task_module_response);
}

cJSON *wm_agent_upgrade_send_tasks_information(const cJSON *message_object) {
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
