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
#include "wm_agent_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "os_net/os_net.h"

static void wm_agent_create_upgrade_tasks(const cJSON *agents, wm_upgrade_task *task, const char* command, cJSON* response, cJSON* failures);
static void wm_agent_parse_task_information(cJSON *json_api, const cJSON* json_task_module);
static cJSON *wm_agent_send_task_information(const cJSON *message);

cJSON *wm_agent_process_upgrade_command(const cJSON* params, const cJSON* agents) {
    cJSON *json_api = NULL;
    char *output = NULL;
    wm_upgrade_task *task = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), output);
    task = wm_agent_parse_upgrade_command(params, output);
    if (!task) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, output);
        json_api = wm_agent_parse_response_mesage(TASK_CONFIGURATIONS, output, NULL, NULL, NULL);
    } else {
        json_api = cJSON_CreateArray();
        cJSON *json_task_module = cJSON_CreateArray();
        wm_agent_create_upgrade_tasks(agents, task, WM_AGENT_UPGRADE_COMMAND_NAME, json_task_module, json_api);
        wm_agent_parse_task_information(json_api, json_task_module);
        cJSON_Delete(json_task_module);
    }
    os_free(output);
    return json_api;
}

/**
 * Receives the cJSON with the agents_id and creates the tasks structure for each agent
 * Will modify two jsons (response, failures), one with the successfull operation to be sent to the request module
 * And another one with the failed operation (In case there is already an upgrade in place)
 * @param agents cJSON array with the agents_id
 * @param task pointer to a task structure
 * @param command command corresponding to the task
 * @param response list of request to be sent to the task module. Expects cJSON array as input 
 * @param failures list of request that failed to be added as tasks. Expects cJSON array as input 
 * */
static void wm_agent_create_upgrade_tasks(const cJSON *agents, wm_upgrade_task *task, const char* command, cJSON* response, cJSON* failures) {
    assert(agents != NULL);
    assert(task != NULL);
    assert(command != NULL);
    assert(response && (response->type == cJSON_Array));
    assert(failures && (failures->type == cJSON_Array));

    for(int i=0; i < cJSON_GetArraySize(agents); i++) {
        wm_task *agent_task;
        os_malloc(sizeof(wm_task), agent_task);
        os_strdup(command, agent_task->command);
        agent_task->task = task;
        cJSON* agent_id = cJSON_GetArrayItem(agents, i);
        int result = wm_agent_create_task_entry(agent_id->valueint, (void *)task);
        if (result == OSHASH_SUCCESS ) {
           cJSON *task_message = wm_agent_parse_task_module_message(agent_task->command, agent_id->valueint);
           cJSON_AddItemToArray(response, task_message);
        } else if (result == OSHASH_DUPLICATED) {
            cJSON *task_message = wm_agent_parse_response_mesage(UPGRADE_ALREADY_ON_PROGRESS, upgrade_error_codes[UPGRADE_ALREADY_ON_PROGRESS], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(failures, task_message);
        } else {
            cJSON *task_message = wm_agent_parse_response_mesage(UNKNOWN_ERROR, upgrade_error_codes[UNKNOWN_ERROR], &(agent_id->valueint), NULL, NULL);
            cJSON_AddItemToArray(failures, task_message);
        }
    }
}

/**
 * Sends json with task information to the task module and parses the response
 * to give back to the api
 * @param json_api cJSON array where the task response will be stored
 * @param json_task_module cJSON to be sent to the task module 
 * */
static void wm_agent_parse_task_information(cJSON *json_api, const cJSON* json_task_module) {
    cJSON *task_module_response = wm_agent_send_task_information(json_task_module);
    if (task_module_response && (task_module_response->type == cJSON_Array)) {
        // Parse task module responses into API
        for(int i=0; i < cJSON_GetArraySize(task_module_response); i++) {
            cJSON *task_response = cJSON_GetArrayItem(task_module_response, i);
            int agent_id = cJSON_GetObjectItem(task_response, "agent")->valueint;
            if (cJSON_HasObjectItem(task_response, "task_id")) {
                // Store task_id
                int task_id = cJSON_GetObjectItem(task_response, "task_id")->valueint;
                wm_agent_insert_tasks_id(task_id, agent_id);
                cJSON_AddItemReferenceToArray(json_api, task_response);
            } else {
                // Remove from table since upgrade will not be started
                wm_agent_remove_entry(agent_id);
                cJSON *json_message = wm_agent_parse_response_mesage(TASK_MANAGER_FAILURE, cJSON_GetObjectItem(task_response, "data")->valuestring, &agent_id, NULL, NULL);
                cJSON_AddItemToArray(json_api, json_message);
                
            }
        }
    } else {
        for(int i=0; i < cJSON_GetArraySize(json_task_module); i++) {
            int agent_id = cJSON_GetObjectItem(cJSON_GetArrayItem(json_task_module, i), "agent")->valueint;
            // Remove from table since upgrade will not be started
            wm_agent_remove_entry(agent_id);
            cJSON_AddItemReferenceToArray(json_api, wm_agent_parse_response_mesage(TASK_MANAGER_COMMUNICATION, upgrade_error_codes[TASK_MANAGER_COMMUNICATION], &agent_id, NULL, NULL));
        }
    }
}

/**
 * Sends the JSON information to the task module and retrieves the answer
 * @param message JSON to be sent. Ezample:
 *  [{
 *      "module" : "upgrade_module",
 *      "command": "upgrade",
 *      "agent" : 1
 *  }, {
 *      "module" : "upgrade_module",
 *      "command": "upgrade",
 *      "agent" : 2
 *  }]
 * @return json response
 * @retval NULL if connection problem or incorrect repsonse format
 * @retval JSON with the task information. Example:
 * [{
 *      "error": 0,
 *      "data": "Task created successfully",
 *      "agent": 1,
 *      "task_id": {{tid1}}
 *  }, {
 *      "error": 0,
 *      "data": "Task created successfully",
 *      "agent": 2,
 *      "task_id": {{tid2}}
 *  }]
 * */
static cJSON *wm_agent_send_task_information(const cJSON *message) {
    cJSON* response = NULL;
    int sock = OS_ConnectUnixDomain(WM_TASK_MODULE_SOCK_PATH, SOCK_STREAM, OS_MAXSTR);
    if (sock == OS_SOCKTERR) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNREACHEABLE_TASK_MANAGER, WM_TASK_MODULE_SOCK_PATH);
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
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_EMPTY_MESSAGE);
                break;
            default:
                response = cJSON_Parse(buffer);
                if (!response) {
                    mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_TASK_MAN_JSON);
                }
                break;
        }
        os_free(buffer);
    }
    return response;
}
