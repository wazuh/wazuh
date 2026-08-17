/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "wmodules.h"
#include "wm_agent_upgrade_manager.h"
#include "wm_agent_upgrade_parsing.h"
#include "os_net.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

/**
 * Start listening loop, exits only on error
 * @param manager_configs manager configuration parameters
 * @return only on errors, socket will be closed
 * */
STATIC void wm_agent_upgrade_listen_messages(const wm_manager_configs* manager_configs) __attribute__((nonnull));

const char* upgrade_error_codes[] = {
    [WM_UPGRADE_SUCCESS] = "Success",
    [WM_UPGRADE_PARSING_ERROR] = "Could not parse message JSON",
    [WM_UPGRADE_PARSING_REQUIRED_PARAMETER] = "Required parameters in json message where not found",
    [WM_UPGRADE_TASK_CONFIGURATIONS] = "JSON parameter not recognized",
    [WM_UPGRADE_TASK_MANAGER_COMMUNICATION] ="Task manager communication error",
    [WM_UPGRADE_TASK_MANAGER_FAILURE] = "", // Data string will be provided by task manager
    [WM_UPGRADE_GLOBAL_DB_FAILURE] = "Agent information not found in database",
    [WM_UPGRADE_SYSTEM_NOT_SUPPORTED] = "The WPK for this platform is not available",
    [WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED] = "Remote upgrade is not available for this agent version",
    [WM_UPGRADE_INTERMEDIATE_VERSION_REQUIRED] = "Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first",
    [WM_UPGRADE_NEW_VERSION_LESS_OR_EQUAL_THAN_CURRENT] = "Current agent version is greater or equal",
    [WM_UPGRADE_NEW_VERSION_GREATER_MASTER] = "Upgrading an agent to a version higher than the manager requires the force flag",
    [WM_UPGRADE_URL_NOT_FOUND] = "The repository is not reachable",
    [WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST] = "The version of the WPK does not exist in the repository",
    [WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST] = "The WPK file does not exist",
    [WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH] = "The WPK sha1 of the file is not valid",
    [WM_UPGRADE_HTTPS_VERIFICATION_MODE_UNSAFE] = "The manager's HTTPS verification_mode is not 'none'; a just-upgraded agent may be unable to reconnect. Use the force option to proceed anyway.",
    [WM_UPGRADE_UNKNOWN_ERROR] = "Upgrade procedure could not start"
};

wm_upgrade_task* wm_agent_upgrade_init_upgrade_task() {
    wm_upgrade_task *task;
    os_calloc(1, sizeof(wm_upgrade_task), task);
    return task;
}

wm_upgrade_custom_task* wm_agent_upgrade_init_upgrade_custom_task() {
    wm_upgrade_custom_task *task;
    os_calloc(1, sizeof(wm_upgrade_custom_task), task);
    return task;
}

wm_task_info* wm_agent_upgrade_init_task_info() {
    wm_task_info *task_info = NULL;
    os_calloc(1, sizeof(wm_task_info), task_info);
    return task_info;
}

wm_agent_info* wm_agent_upgrade_init_agent_info() {
    wm_agent_info *agent_info = NULL;
    os_calloc(1, sizeof(wm_agent_info), agent_info);
    return agent_info;
}

wm_agent_task* wm_agent_upgrade_init_agent_task() {
    wm_agent_task *agent_task = NULL;
    os_calloc(1, sizeof(wm_agent_task), agent_task);
    return agent_task;
}

void wm_agent_upgrade_free_upgrade_task(wm_upgrade_task* upgrade_task) {
    if (upgrade_task) {
        os_free(upgrade_task->custom_version);
        os_free(upgrade_task->wpk_repository);
        os_free(upgrade_task->wpk_version);
        os_free(upgrade_task->wpk_file);
        os_free(upgrade_task->wpk_sha1);
        os_free(upgrade_task->package_type);
        os_free(upgrade_task);
    }
}

void wm_agent_upgrade_free_upgrade_custom_task(wm_upgrade_custom_task* upgrade_custom_task) {
    if (upgrade_custom_task) {
        os_free(upgrade_custom_task->custom_file_path);
        os_free(upgrade_custom_task->custom_installer);
        os_free(upgrade_custom_task->wpk_sha1);
        os_free(upgrade_custom_task);
    }
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
}

void wm_agent_upgrade_free_agent_info(wm_agent_info* agent_info) {
    if (agent_info) {
        os_free(agent_info->platform);
        os_free(agent_info->major_version);
        os_free(agent_info->minor_version);
        os_free(agent_info->architecture);
        os_free(agent_info->wazuh_version);
        os_free(agent_info->package_type);
        os_free(agent_info);
    }
}

void wm_agent_upgrade_free_agent_task(wm_agent_task* agent_task) {
    if (agent_task) {
        if (agent_task->agent_info) {
            wm_agent_upgrade_free_agent_info(agent_task->agent_info);
        }
        if (agent_task->task_info) {
            wm_agent_upgrade_free_task_info(agent_task->task_info);
        }
        os_free(agent_task);
    }
}

cJSON* wm_agent_upgrade_send_tasks_information(const cJSON *message_object) {
    cJSON* response = NULL;

    int sock = OS_ConnectUnixDomain(WM_TASK_MODULE_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock == OS_SOCKTERR) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNREACHEABLE_TASK_MANAGER, WM_TASK_MODULE_SOCK);
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

        close(sock);
    }

    return response;
}

void wm_agent_upgrade_start_manager_module(const wm_manager_configs* manager_configs, const int enabled) {

    // Check if module is enabled
    if (!enabled) {
        mtinfo(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_MODULE_DISABLED);
        pthread_exit(NULL);
    }

    mtinfo(WM_AGENT_UPGRADE_LOGTAG, STARTUP_MSG, (int)getpid());

    // Start listener
    wm_agent_upgrade_listen_messages(manager_configs);
}

STATIC void wm_agent_upgrade_listen_messages(const wm_manager_configs* manager_configs) {

    // Initialize socket
    int sock = OS_BindUnixDomainWithPerms(WM_UPGRADE_SOCK, SOCK_STREAM, OS_MAXSTR, getuid(), wm_getGroupID(), 0660);
    if (sock < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_BIND_SOCK_ERROR, WM_UPGRADE_SOCK, strerror(errno));
        return;
    }

    // Wait a few seconds until the task manager starts
    wm_sleep_interruptible(WM_AGENT_UPGRADE_START_WAIT_TIME);
    if (wm_shutdown_requested) {
        close(sock);
        return;
    }

    while (!wm_shutdown_requested) {
        // listen - wait connection
        fd_set fdset;

        switch (wm_select_interruptible(sock, &fdset)) {
        case -1:
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SELECT_ERROR, strerror(errno));
            close(sock);
            return;
        case 0:
            continue;
        default:
            break;
        }

        //Accept
        int peer;
        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ACCEPT_ERROR, strerror(errno));
            }
            continue;
        }

        // Get request string
        char *buffer = NULL;

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        int length;
        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case OS_SOCKTERR:
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SOCKTERR_ERROR);
            break;
        case -1:
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RECV_ERROR, strerror(errno));
            break;
        case 0:
            mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_EMPTY_MESSAGE);
            break;
        default:
            /* Correctly received message */
            mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INCOMMING_MESSAGE, buffer);

            void* task = NULL;
            int* agent_ids = NULL;
            char* message = NULL;
            int parsing_retval;

            // Parse incoming message
            parsing_retval = wm_agent_upgrade_parse_message(&buffer[0], &task, &agent_ids, &message);

            switch (parsing_retval) {
            case WM_UPGRADE_UPGRADE:
                // Upgrade command
                if (task && agent_ids) {
                    message = wm_agent_upgrade_process_upgrade_command(agent_ids, (wm_upgrade_task *)task, manager_configs->wpk_repository);
                }
                wm_agent_upgrade_free_upgrade_task(task);
                break;
            case WM_UPGRADE_UPGRADE_CUSTOM:
                // Upgrade custom command
                if (task && agent_ids) {
                    message = wm_agent_upgrade_process_upgrade_custom_command(agent_ids, (wm_upgrade_custom_task *)task);
                }
                wm_agent_upgrade_free_upgrade_custom_task(task);
                break;
            default:
                // Parsing error
                if (!message) {
                    cJSON *error_json = wm_agent_upgrade_parse_data_response(WM_UPGRADE_UNKNOWN_ERROR, upgrade_error_codes[WM_UPGRADE_UNKNOWN_ERROR], NULL);
                    cJSON *response = wm_agent_upgrade_parse_response(WM_UPGRADE_UNKNOWN_ERROR, error_json);
                    message = cJSON_PrintUnformatted(response);
                    cJSON_Delete(response);
                }
                break;
            }

            mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RESPONSE_MESSAGE, message);
            OS_SendSecureTCP(peer, strlen(message), message);
            os_free(agent_ids);
            os_free(message);
            break;
        }

        os_free(buffer);
        close(peer);

    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }

    close(sock);
}
