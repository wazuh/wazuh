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
#include "wm_agent_upgrade_manager.h"
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "wazuh_db/wdb.h"
#include "os_net/os_net.h"

/**
 * Analyze agent information and returns a JSON to be sent to the task manager
 * @param agent_id id of the agent
 * @param agent_task structure where the information of the agent will be stored
 * @param error_code variable to modify in case of failure
 * @return JSON task if success, NULL otherwise
 * */
static cJSON* wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task, wm_upgrade_error_code *error_code);

/**
 * Validate the information of the agent and the task
 * @param agent_task structure with the information to be validated
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_VERSION_SAME_MANAGER
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER)
 * @retval WM_UPGRADE_AGENT_IS_NOT_ACTIVE
 * @retval WM_UPGRADE_INVALID_ACTION_FOR_MANAGER
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * */
static int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task);

/**
 * Start the upgrade procedure for the agents
 * @param json_response cJSON array where the responses for each agent will be stored
 * @param task_module_request cJSON array with the agents to be upgraded
 * */
static void wm_agent_upgrade_start_upgrades(cJSON *json_response, const cJSON* task_module_request);

/**
 * Send WPK file to agent and verify SHA1
 * @param agent_task structure with the information of the agent and the WPK
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_WPK_SENDING_ERROR
 * @retval WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH
 * */
static int wm_agent_upgrade_send_wpk_to_agent(const wm_agent_task *agent_task);

/**
 * Send a command to the agent and return the response
 * @param command request command to agent
 * @param command_size size of the command
 * @return response from agent
 * */
static char* wm_agent_upgrade_send_command_to_agent(const char *command, const size_t command_size);

char* wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task) {
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON* json_response = cJSON_CreateArray();
    cJSON *json_task_module_request = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
        cJSON *task_request = NULL;
        wm_agent_task *agent_task = NULL;
        wm_upgrade_task *upgrade_task = NULL;

        agent_task = wm_agent_upgrade_init_agent_task();

        // Task information
        upgrade_task = wm_agent_upgrade_init_upgrade_task();
        w_strdup(task->wpk_repository, upgrade_task->wpk_repository);
        w_strdup(task->custom_version, upgrade_task->custom_version);
        upgrade_task->use_http = task->use_http;
        upgrade_task->force_upgrade = task->force_upgrade;

        agent_task->task_info = wm_agent_upgrade_init_task_info();
        agent_task->task_info->command = WM_UPGRADE_UPGRADE;
        agent_task->task_info->task = upgrade_task;

        if (task_request = wm_agent_upgrade_analyze_agent(agent_id, agent_task, &error_code), task_request) {
            cJSON_AddItemToArray(json_task_module_request, task_request);
        } else {
            cJSON *error_message = wm_agent_upgrade_parse_response_message(error_code, upgrade_error_codes[error_code], &agent_id, NULL, NULL);
            cJSON_AddItemToArray(json_response, error_message);
            wm_agent_upgrade_free_agent_task(agent_task);
        }
    }

    wm_agent_upgrade_start_upgrades(json_response, json_task_module_request);

    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_task_module_request);
    cJSON_Delete(json_response);

    return response;
}

char* wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task) {
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON* json_response = cJSON_CreateArray();
    cJSON *json_task_module_request = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
        cJSON *task_request = NULL;
        wm_agent_task *agent_task = NULL;
        wm_upgrade_custom_task *upgrade_custom_task = NULL;

        agent_task = wm_agent_upgrade_init_agent_task();

        // Task information
        upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
        w_strdup(task->custom_file_path, upgrade_custom_task->custom_file_path);
        w_strdup(task->custom_installer, upgrade_custom_task->custom_installer);

        agent_task->task_info = wm_agent_upgrade_init_task_info();
        agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
        agent_task->task_info->task = upgrade_custom_task;

        if (task_request = wm_agent_upgrade_analyze_agent(agent_id, agent_task, &error_code), task_request) {
            cJSON_AddItemToArray(json_task_module_request, task_request);
        } else {
            cJSON *error_message = wm_agent_upgrade_parse_response_message(error_code, upgrade_error_codes[error_code], &agent_id, NULL, NULL);
            cJSON_AddItemToArray(json_response, error_message);
            wm_agent_upgrade_free_agent_task(agent_task);
        }
    }

    wm_agent_upgrade_start_upgrades(json_response, json_task_module_request);

    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_task_module_request);
    cJSON_Delete(json_response);

    return response;
}

static cJSON* wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task, wm_upgrade_error_code *error_code) {
    cJSON *task_request = NULL;

    // Agent information
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->agent_info->agent_id = agent_id;

    if (!wdb_agent_info(agent_id,
                        &agent_task->agent_info->platform,
                        &agent_task->agent_info->major_version,
                        &agent_task->agent_info->minor_version,
                        &agent_task->agent_info->architecture,
                        &agent_task->agent_info->wazuh_version,
                        &agent_task->agent_info->last_keep_alive)) {

        // Validate agent and task information
        *error_code = wm_agent_upgrade_validate_agent_task(agent_task);

        if (*error_code == WM_UPGRADE_SUCCESS) {
            // Save task entry for agent
            int result = wm_agent_upgrade_create_task_entry(agent_id, agent_task);

            if (result == OSHASH_SUCCESS) {
                task_request = wm_agent_upgrade_parse_task_module_request(agent_task->task_info->command, agent_id);
            } else if (result == OSHASH_DUPLICATED) {
                *error_code = WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS;
            } else {
                *error_code = WM_UPGRADE_UNKNOWN_ERROR;
            }
        }
    } else {
        *error_code = WM_UPGRADE_GLOBAL_DB_FAILURE;
    }

    return task_request;
}

static int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task) {
    int validate_result = WM_UPGRADE_SUCCESS;

    // Validate agent id
    validate_result = wm_agent_upgrade_validate_id(agent_task->agent_info->agent_id);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate agent status
    validate_result = wm_agent_upgrade_validate_status(agent_task->agent_info->last_keep_alive);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }


    // TODO: Check if there isn't already a task for this agent with status UPDATING


    // Validate Wazuh version to upgrade
    validate_result = wm_agent_upgrade_validate_version(agent_task->agent_info, agent_task->task_info->task, agent_task->task_info->command);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate WPK file
    if (WM_UPGRADE_UPGRADE == agent_task->task_info->command) {
        validate_result = wm_agent_upgrade_validate_wpk((wm_upgrade_task *)agent_task->task_info->task);
    } else {
        validate_result = wm_agent_upgrade_validate_wpk_custom((wm_upgrade_custom_task *)agent_task->task_info->task);
    }

    return validate_result;
}

static void wm_agent_upgrade_start_upgrades(cJSON *json_response, const cJSON* task_module_request) {
    unsigned int index = 0;
    OSHashNode *node = NULL;
    char *agent_key = NULL;
    wm_agent_task *agent_task = NULL;

    // Send request to task module and store task ids
    if (!wm_agent_upgrade_parse_task_module_task_ids(json_response, task_module_request)) {
        node = wm_agent_upgrade_get_first_node(&index);

        while (node) {
            agent_key = node->key;
            agent_task = (wm_agent_task *)node->data;
            node = wm_agent_upgrade_get_next_node(&index, node);

            if (WM_UPGRADE_SUCCESS == wm_agent_upgrade_send_wpk_to_agent(agent_task)) {


                // TODO: Send update command to agent and update task to UPDATING


            } else {


                // TODO: Update task to UPDATING/ERROR


            }

            wm_agent_upgrade_remove_entry(atoi(agent_key));
        }
    } else {
        mtwarn(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_NO_AGENTS_TO_UPGRADE);
    }
}

static int wm_agent_upgrade_send_wpk_to_agent(const wm_agent_task *agent_task) {
    int result = WM_UPGRADE_WPK_SENDING_ERROR;
    wm_upgrade_task *upgrade_task = NULL;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;
    char *file_path = NULL;
    char *file_sha1 = NULL;
    char *wpk_path = NULL;
    char *command = NULL;
    char *response = NULL;
    char *data = NULL;
    char *error = NULL;

    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SENDING_WPK_TO_AGENT, agent_task->agent_info->agent_id);

    if (WM_UPGRADE_UPGRADE == agent_task->task_info->command) {
        upgrade_task = agent_task->task_info->task;
        // WPK file path
        os_calloc(OS_SIZE_4096, sizeof(char), file_path);
        snprintf(file_path, OS_SIZE_4096, "%s%s", WM_UPGRADE_WPK_DEFAULT_PATH, upgrade_task->wpk_file);
        // WPK file sha1
        os_strdup(upgrade_task->wpk_sha1, file_sha1);
    } else {
        upgrade_custom_task = agent_task->task_info->task;
        // WPK custom file path
        os_strdup(upgrade_custom_task->custom_file_path, file_path);
        // WPK custom file sha1
        os_calloc(41, sizeof(char), file_sha1);
        OS_SHA1_File(file_path, file_sha1, OS_BINARY);
    }

    wpk_path = basename_ex(file_path);
    os_calloc(OS_MAXSTR, sizeof(char), command);

    // lock_restart
    snprintf(command, OS_MAXSTR, "%.3d com lock_restart -1", agent_task->agent_info->agent_id);
    response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));
    if (!wm_agent_upgrade_parse_agent_response(response, &data, &error)) {
        int open_retries = 0;

        // open wb
        snprintf(command, OS_MAXSTR, "%.3d com open wb %s", agent_task->agent_info->agent_id, wpk_path);
        for (open_retries = 0; open_retries < WM_UPGRADE_WPK_OPEN_ATTEMPTS; ++open_retries) {
            os_free(response);
            response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));
            if (!wm_agent_upgrade_parse_agent_response(response, &data, &error)) {
                break;
            }
        }

        if (open_retries < WM_UPGRADE_WPK_OPEN_ATTEMPTS) {
            FILE *file = NULL;
            unsigned char buffer[WM_UPGRADE_WPK_CHUNK_SIZE];
            size_t bytes = 0;
            size_t command_size = 0;
            size_t byte = 0;

            // write
            if (file = fopen(file_path, "rb"), file) {
                while (bytes = fread(buffer, 1, sizeof(buffer), file), bytes) {
                    snprintf(command, OS_MAXSTR, "%.3d com write %ld %s ", agent_task->agent_info->agent_id, bytes, wpk_path);
                    command_size = strlen(command);
                    for (byte = 0; byte < bytes; ++byte) {
                        sprintf(&command[command_size++], "%c", buffer[byte]);
                    }
                    os_free(response);
                    response = wm_agent_upgrade_send_command_to_agent(command, command_size);
                    if (wm_agent_upgrade_parse_agent_response(response, &data, &error) == OS_INVALID) {
                        break;
                    }
                }
                fclose(file);

                if (!bytes) {

                    // close
                    snprintf(command, OS_MAXSTR, "%.3d com close %s", agent_task->agent_info->agent_id, wpk_path);
                    os_free(response);
                    response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));
                    if (!wm_agent_upgrade_parse_agent_response(response, &data, &error)) {

                        // sha1
                        snprintf(command, OS_MAXSTR, "%.3d com sha1 %s", agent_task->agent_info->agent_id, wpk_path);
                        os_free(response);
                        response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));
                        if (!wm_agent_upgrade_parse_agent_response(response, &data, &error)) {

                            if (!strcmp(file_sha1, data)) {
                                result = WM_UPGRADE_SUCCESS;
                            } else {
                                result = WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH;
                            }
                        }
                    }
                }
            }
        }
    }

    if (WM_UPGRADE_WPK_SENDING_ERROR == result) {
        if (error) {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_AGENT_RESPONSE_MESSAGE_ERROR, error);
        } else {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_AGENT_RESPONSE_UNKNOWN_ERROR);
        }
    } else if (WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH == result) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_AGENT_RESPONSE_SHA1_ERROR);
    }

    os_free(command);
    os_free(response);
    os_free(file_path);
    os_free(file_sha1);

    return result;
}

static char* wm_agent_upgrade_send_command_to_agent(const char *command, const size_t command_size) {
    char *response = NULL;
    int length = 0;

    const char *path = isChroot() ? REMOTE_REQ_SOCK : DEFAULTDIR REMOTE_REQ_SOCK;

    int sock = OS_ConnectUnixDomain(path, SOCK_STREAM, OS_MAXSTR);

    if (sock == OS_SOCKTERR) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNREACHEABLE_REQUEST, path);
    } else {
        mtdebug2(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_REQUEST_SEND_MESSAGE, command);

        OS_SendSecureTCP(sock, command_size, command);
        os_calloc(OS_MAXSTR, sizeof(char), response);

        switch (length = OS_RecvSecureTCP(sock, response, OS_MAXSTR), length) {
            case OS_SOCKTERR:
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SOCKTERR_ERROR);
                break;
            case -1:
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RECV_ERROR, strerror(errno));
                break;
            default:
                if (!response) {
                    mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_EMPTY_AGENT_RESPONSE);
                } else {
                    mtdebug2(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_REQUEST_RECEIVE_MESSAGE, response);
                }
                break;
        }

        close(sock);
    }

    return response;
}
