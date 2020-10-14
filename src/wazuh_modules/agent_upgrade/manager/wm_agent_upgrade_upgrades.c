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

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_upgrades.h"
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "wm_agent_upgrade_validate.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_net/os_net.h"

/* Queue to store agents ready to be upgraded */
STATIC w_linked_queue_t *upgrade_queue;

/* Running threads semaphore */
sem_t upgrade_semaphore;

/* Definition of upgrade arguments structure */
typedef struct _wm_upgrade_args {
    wm_manager_configs *config;
    wm_agent_task *agent_task;
} wm_upgrade_args;

/**
 * Main function of upgrade threads
 * @param arg Upgrade arguments structure
 * */
STATIC void* wm_agent_upgrade_start_upgrade(void *arg);

/**
 * Send WPK file to agent and verify SHA1
 * @param agent_task structure with the information of the agent and the WPK
 * @param manager_configs manager configuration parameters
 * @return return_code
 * @retval WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST
 * @retval WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH
 * @retval WM_UPGRADE_SEND_LOCK_RESTART_ERROR
 * @retval WM_UPGRADE_SEND_OPEN_ERROR
 * @retval WM_UPGRADE_SEND_WRITE_ERROR
 * @retval WM_UPGRADE_SEND_CLOSE_ERROR
 * @retval WM_UPGRADE_SEND_SHA1_ERROR
 * @retval WM_UPGRADE_SEND_UPGRADE_ERROR
 * */
STATIC int wm_agent_upgrade_send_wpk_to_agent(const wm_agent_task *agent_task, const wm_manager_configs* manager_configs) __attribute__((nonnull));

/**
 * Send a lock_restart command to an agent
 * @param agent_id id of the agent
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * */
STATIC int wm_agent_upgrade_send_lock_restart(int agent_id);

/**
 * Send an open file command to an agent
 * @param agent_id id of the agent
 * @param wpk_file name of the file to open in the agent
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * */
STATIC int wm_agent_upgrade_send_open(int agent_id, const char *wpk_file) __attribute__((nonnull));

/**
 * Send a write file command to an agent
 * @param agent_id id of the agent
 * @param wpk_file name of the file to write in the agent
 * @param file_path name of the file to read in the manager
 * @param chunk_size size of block to send WPK file
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * */
STATIC int wm_agent_upgrade_send_write(int agent_id, const char *wpk_file, const char *file_path, int chunk_size) __attribute__((nonnull));

/**
 * Send a close file command to an agent
 * @param agent_id id of the agent
 * @param wpk_file name of the file to close in the agent
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * */
STATIC int wm_agent_upgrade_send_close(int agent_id, const char *wpk_file) __attribute__((nonnull));

/**
 * Send a sha1 command to an agent
 * @param agent_id id of the agent
 * @param wpk_file name of the file to calculate sha1 in the agent
 * @param file_sha1 sha1 of the file in the manager to compare
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * */
STATIC int wm_agent_upgrade_send_sha1(int agent_id, const char *wpk_file, const char *file_sha1) __attribute__((nonnull));

/**
 * Send an upgrade command to an agent
 * @param agent_id id of the agent
 * @param wpk_file name of the file with the installation files in the agent
 * @param installer name of the installer to run in the agent
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * */
STATIC int wm_agent_upgrade_send_upgrade(int agent_id, const char *wpk_file, const char *installer) __attribute__((nonnull));

void wm_agent_upgrade_init_upgrade_queue() {
    upgrade_queue = linked_queue_init();
}

void wm_agent_upgrade_destroy_upgrade_queue() {
    linked_queue_free(upgrade_queue);
}

void wm_agent_upgrade_prepare_upgrades() {
    unsigned int index = 0;
    OSHashNode *node = NULL;

    node = wm_agent_upgrade_get_first_node(&index);

    while (node) {
        int agent_key = atoi(node->key);
        wm_agent_task *agent_task = (wm_agent_task *)node->data;

        node = wm_agent_upgrade_get_next_node(&index, node);

        linked_queue_push_ex(upgrade_queue, agent_task);
        wm_agent_upgrade_remove_entry(agent_key, 0);
    }
}

void* wm_agent_upgrade_dispatch_upgrades(void *arg) {
    wm_manager_configs *config = (wm_manager_configs *)arg;
    wm_upgrade_args *upgrade_config = NULL;

    sem_init(&upgrade_semaphore, 0, config->max_threads);

    while (1) {
        // Blocks until an available thread is ready
        sem_wait(&upgrade_semaphore);

        wm_agent_task *agent_task = linked_queue_pop_ex(upgrade_queue);

        os_calloc(1, sizeof(wm_upgrade_args), upgrade_config);
        upgrade_config->config = config;
        upgrade_config->agent_task = agent_task;

        // Thread that will launch the upgrade
        w_create_thread(wm_agent_upgrade_start_upgrade, (void *)upgrade_config);

    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }

    sem_destroy(&upgrade_semaphore);

    return NULL;
}

STATIC void* wm_agent_upgrade_start_upgrade(void *arg) {
    wm_upgrade_args *upgrade_config = (wm_upgrade_args *)arg;

    wm_manager_configs *config = upgrade_config->config;
    wm_agent_task *agent_task = upgrade_config->agent_task;

    cJSON *status_request = NULL;
    cJSON *status_response = NULL;
    int error_code = WM_UPGRADE_SUCCESS;

    // Update task to "In progress"
    status_response = cJSON_CreateArray();
    status_request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_UPDATE_STATUS,
                                                                cJSON_CreateIntArray(&agent_task->agent_info->agent_id, 1),
                                                                task_statuses[WM_TASK_IN_PROGRESS],
                                                                NULL);

    wm_agent_upgrade_task_module_callback(status_response, status_request, NULL, NULL);

    if (wm_agent_upgrade_validate_task_status_message(cJSON_GetArrayItem(status_response, 0), NULL, NULL)) {

        if (error_code = wm_agent_upgrade_send_wpk_to_agent(agent_task, config), error_code == WM_UPGRADE_SUCCESS) {

            if (WM_UPGRADE_UPGRADE == agent_task->task_info->command) {
                wm_upgrade_task *upgrade_task = agent_task->task_info->task;

                if (upgrade_task->custom_version && (wm_agent_upgrade_compare_versions(upgrade_task->custom_version, WM_UPGRADE_NEW_UPGRADE_MECHANISM) < 0)) {

                    cJSON_Delete(status_request);
                    cJSON_Delete(status_response);

                    // Update task to "Legacy". The agent won't report the result of the upgrade task
                    status_response = cJSON_CreateArray();
                    status_request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_UPDATE_STATUS,
                                                                                cJSON_CreateIntArray(&agent_task->agent_info->agent_id, 1),
                                                                                task_statuses[WM_TASK_LEGACY],
                                                                                NULL);

                    wm_agent_upgrade_task_module_callback(status_response, status_request, NULL, NULL);
                    wm_agent_upgrade_validate_task_status_message(cJSON_GetArrayItem(status_response, 0), NULL, NULL);
                }
            }
        } else {

            cJSON_Delete(status_request);
            cJSON_Delete(status_response);

            // Update task to "Failed"
            status_response = cJSON_CreateArray();
            status_request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_UPDATE_STATUS,
                                                                        cJSON_CreateIntArray(&agent_task->agent_info->agent_id, 1),
                                                                        task_statuses[WM_TASK_FAILED],
                                                                        upgrade_error_codes[error_code]);

            wm_agent_upgrade_task_module_callback(status_response, status_request, NULL, NULL);
            wm_agent_upgrade_validate_task_status_message(cJSON_GetArrayItem(status_response, 0), NULL, NULL);
        }
    }

    cJSON_Delete(status_request);
    cJSON_Delete(status_response);

    wm_agent_upgrade_free_agent_task(agent_task);

    os_free(upgrade_config);

    // Notify end of execution
    sem_post(&upgrade_semaphore);

#ifndef WAZUH_UNIT_TESTING
    pthread_exit(NULL);
#endif

    return NULL;
}

STATIC int wm_agent_upgrade_send_wpk_to_agent(const wm_agent_task *agent_task, const wm_manager_configs* manager_configs) {
    int result = WM_UPGRADE_SUCCESS;
    char *file_path = NULL;
    char *file_path_copy = NULL;
    char *file_sha1 = NULL;
    char *wpk_path = NULL;
    char *installer = NULL;

    // Validate WPK file
    if (WM_UPGRADE_UPGRADE == agent_task->task_info->command) {
        result = wm_agent_upgrade_validate_wpk((wm_upgrade_task *)agent_task->task_info->task);
    } else {
        result = wm_agent_upgrade_validate_wpk_custom((wm_upgrade_custom_task *)agent_task->task_info->task);
    }

    if (result != WM_UPGRADE_SUCCESS) {
        return result;
    }

    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SENDING_WPK_TO_AGENT, agent_task->agent_info->agent_id);

    if (WM_UPGRADE_UPGRADE == agent_task->task_info->command) {
        wm_upgrade_task *upgrade_task = NULL;
        upgrade_task = agent_task->task_info->task;
        // WPK file path
        os_calloc(OS_SIZE_4096, sizeof(char), file_path);
        snprintf(file_path, OS_SIZE_4096, "%s%s", WM_UPGRADE_WPK_DEFAULT_PATH, upgrade_task->wpk_file);
        // WPK file sha1
        os_strdup(upgrade_task->wpk_sha1, file_sha1);
    } else {
        wm_upgrade_custom_task *upgrade_custom_task = NULL;
        upgrade_custom_task = agent_task->task_info->task;
        // WPK custom file path
        os_strdup(upgrade_custom_task->custom_file_path, file_path);
        // WPK custom file sha1
        os_calloc(41, sizeof(char), file_sha1);
        OS_SHA1_File(file_path, file_sha1, OS_BINARY);
        // Installer
        if (upgrade_custom_task->custom_installer) {
            os_strdup(upgrade_custom_task->custom_installer, installer);
        }
    }

    if (!installer) {
        if (!strcmp(agent_task->agent_info->platform, "windows")) {
            os_strdup("upgrade.bat", installer);
        } else {
            os_strdup("upgrade.sh", installer);
        }
    }

    os_strdup(file_path, file_path_copy);

    wpk_path = basename_ex(file_path_copy);

    // lock_restart
    if (wm_agent_upgrade_send_lock_restart(agent_task->agent_info->agent_id)) {
        result = WM_UPGRADE_SEND_LOCK_RESTART_ERROR;
    }

    // open wb
    if ((result == WM_UPGRADE_SUCCESS) && wm_agent_upgrade_send_open(agent_task->agent_info->agent_id, wpk_path)) {
        result = WM_UPGRADE_SEND_OPEN_ERROR;
    }

    // write
    if ((result == WM_UPGRADE_SUCCESS) && wm_agent_upgrade_send_write(agent_task->agent_info->agent_id, wpk_path, file_path, manager_configs->chunk_size)) {
        result = WM_UPGRADE_SEND_WRITE_ERROR;
    }

    // close
    if ((result == WM_UPGRADE_SUCCESS) && wm_agent_upgrade_send_close(agent_task->agent_info->agent_id, wpk_path)) {
        result = WM_UPGRADE_SEND_CLOSE_ERROR;
    }

    // sha1
    if ((result == WM_UPGRADE_SUCCESS) && wm_agent_upgrade_send_sha1(agent_task->agent_info->agent_id, wpk_path, file_sha1)) {
        result = WM_UPGRADE_SEND_SHA1_ERROR;
    }

    // upgrade
    if ((result == WM_UPGRADE_SUCCESS) && wm_agent_upgrade_send_upgrade(agent_task->agent_info->agent_id, wpk_path, installer)) {
        result = WM_UPGRADE_SEND_UPGRADE_ERROR;
    }

    os_free(file_path);
    os_free(file_path_copy);
    os_free(file_sha1);
    os_free(installer);

    return result;
}

STATIC int wm_agent_upgrade_send_lock_restart(int agent_id) {
    int result = OS_INVALID;
    char *command = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), command);

    snprintf(command, OS_MAXSTR, "%.3d com lock_restart -1",agent_id);

    response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));

    result = wm_agent_upgrade_parse_agent_response(response, NULL);

    os_free(command);
    os_free(response);

    return result;
}

STATIC int wm_agent_upgrade_send_open(int agent_id, const char *wpk_file) {
    int result = OS_INVALID;
    char *command = NULL;
    char *response = NULL;
    int open_retries = 0;

    os_calloc(OS_MAXSTR, sizeof(char), command);

    snprintf(command, OS_MAXSTR, "%.3d com open wb %s", agent_id, wpk_file);

    for (open_retries = 0; open_retries < WM_UPGRADE_WPK_OPEN_ATTEMPTS; ++open_retries) {
        os_free(response);
        response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));
        if (result = wm_agent_upgrade_parse_agent_response(response, NULL), !result) {
            break;
        }
    }

    os_free(command);
    os_free(response);

    return result;
}

STATIC int wm_agent_upgrade_send_write(int agent_id, const char *wpk_file, const char *file_path, int chunk_size) {
    int result = OS_INVALID;
    char *command = NULL;
    char *response = NULL;
    unsigned char buffer[chunk_size];
    size_t bytes = 0;
    size_t command_size = 0;
    size_t byte = 0;

    os_calloc(OS_MAXSTR, sizeof(char), command);

    FILE *file = fopen(file_path, "rb");
    if (file) {
        while (bytes = fread(buffer, 1, sizeof(buffer), file), bytes) {
            snprintf(command, OS_MAXSTR, "%.3d com write %ld %s ", agent_id, bytes, wpk_file);
            command_size = strlen(command);
            for (byte = 0; byte < bytes; ++byte) {
                sprintf(&command[command_size++], "%c", buffer[byte]);
            }
            os_free(response);
            response = wm_agent_upgrade_send_command_to_agent(command, command_size);
            if (result = wm_agent_upgrade_parse_agent_response(response, NULL), result) {
                break;
            }
        }
        fclose(file);
    }

    os_free(command);
    os_free(response);

    return result;
}

STATIC int wm_agent_upgrade_send_close(int agent_id, const char *wpk_file) {
    int result = OS_INVALID;
    char *command = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), command);

    snprintf(command, OS_MAXSTR, "%.3d com close %s", agent_id, wpk_file);

    response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));

    result = wm_agent_upgrade_parse_agent_response(response, NULL);

    os_free(command);
    os_free(response);

    return result;
}

STATIC int wm_agent_upgrade_send_sha1(int agent_id, const char *wpk_file, const char *file_sha1) {
    int result = OS_INVALID;
    char *command = NULL;
    char *response = NULL;
    char *data = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), command);

    snprintf(command, OS_MAXSTR, "%.3d com sha1 %s", agent_id, wpk_file);

    response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));

    if (result = wm_agent_upgrade_parse_agent_response(response, &data), !result) {
        if (!data || strcmp(file_sha1, data)) {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_AGENT_RESPONSE_SHA1_ERROR);
            result = OS_INVALID;
        }
    }

    os_free(command);
    os_free(response);

    return result;
}

STATIC int wm_agent_upgrade_send_upgrade(int agent_id, const char *wpk_file, const char *installer) {
    int result = OS_INVALID;
    char *command = NULL;
    char *response = NULL;
    char *data = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), command);

    snprintf(command, OS_MAXSTR, "%.3d com upgrade %s %s", agent_id, wpk_file, installer);

    response = wm_agent_upgrade_send_command_to_agent(command, strlen(command));
    if (result = wm_agent_upgrade_parse_agent_response(response, &data), !result) {
        if (!data || strncmp("0", data, 1)) {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_AGENT_RESPONSE_SCRIPT_ERROR);
            result = OS_INVALID;
        }
    }

    os_free(command);
    os_free(response);

    return result;
}

char* wm_agent_upgrade_send_command_to_agent(const char *command, const size_t command_size) {
    char *response = NULL;
    int length = 0;

    const char *path = isChroot() ? REMOTE_REQ_SOCK : DEFAULTDIR REMOTE_REQ_SOCK;

    int sock = OS_ConnectUnixDomain(path, SOCK_STREAM, OS_MAXSTR);

    if (sock == OS_SOCKTERR) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNREACHEABLE_REQUEST, path);
    } else {
        mtdebug2(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_REQUEST_SEND_MESSAGE, command);

        OS_SendSecureTCP(sock, command_size ? command_size : strlen(command), command);
        os_calloc(OS_MAXSTR, sizeof(char), response);

        switch (length = OS_RecvSecureTCP(sock, response, OS_MAXSTR), length) {
            case OS_SOCKTERR:
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SOCKTERR_ERROR);
                break;
            case -1:
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RECV_ERROR, strerror(errno));
                break;
            default:
                mtdebug2(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_REQUEST_RECEIVE_MESSAGE, response);
                break;
        }

        close(sock);
    }

    return response;
}
