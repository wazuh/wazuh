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
#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_manager.h"
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "wm_agent_upgrade_upgrades.h"
#include "os_net/os_net.h"
#include "router.h"
#include "sym_load.h"
#include "shared_modules/router/include/router.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

const char* upgrade_error_codes[] = {
    [WM_UPGRADE_SUCCESS] = "Success",
    [WM_UPGRADE_PARSING_ERROR] = "Could not parse message JSON",
    [WM_UPGRADE_PARSING_REQUIRED_PARAMETER] = "Required parameters in json message where not found",
    [WM_UPGRADE_TASK_CONFIGURATIONS] = "JSON parameter not recognized",
    [WM_UPGRADE_TASK_MANAGER_COMMUNICATION] ="Task manager communication error",
    [WM_UPGRADE_TASK_MANAGER_FAILURE] = "", // Data string will be provided by task manager
    [WM_UPGRADE_GLOBAL_DB_FAILURE] = "Agent information not found in database",
    [WM_UPGRADE_INVALID_ACTION_FOR_MANAGER] = "Action not available for Manager (agent 000)",
    [WM_UPGRADE_AGENT_IS_NOT_ACTIVE] = "Agent is not active",
    [WM_UPGRADE_SYSTEM_NOT_SUPPORTED] = "The WPK for this platform is not available",
    [WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS] = "Upgrade procedure could not start. Agent already upgrading",
    [WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED] = "Remote upgrade is not available for this agent version",
    [WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT] = "Current agent version is greater or equal",
    [WM_UPGRADE_NEW_VERSION_GREATER_MASTER] = "Upgrading an agent to a version higher than the manager requires the force flag",
    [WM_UPGRADE_URL_NOT_FOUND] = "The repository is not reachable",
    [WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST] = "The version of the WPK does not exist in the repository",
    [WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST] = "The WPK file does not exist",
    [WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH] = "The WPK sha1 of the file is not valid",
    [WM_UPGRADE_SEND_LOCK_RESTART_ERROR] = "Send lock restart error",
    [WM_UPGRADE_SEND_OPEN_ERROR] = "Send open file error",
    [WM_UPGRADE_SEND_WRITE_ERROR] = "Send write file error",
    [WM_UPGRADE_SEND_CLOSE_ERROR] = "Send close file error",
    [WM_UPGRADE_SEND_SHA1_ERROR] = "Send verify sha1 error",
    [WM_UPGRADE_SEND_UPGRADE_ERROR] = "Send upgrade command error",
    [WM_UPGRADE_UPGRADE_ERROR] = "Upgrade procedure exited with error code",
    [WM_UPGRADE_UPGRADE_ERROR_MISSING_PACKAGE] = "Upgrade procedure exited with error code, missing dependency in agent",
    [WM_UPGRADE_UNKNOWN_ERROR] = "Upgrade procedure could not start"
};

/**
 * Start listening loop, exits only on error
 * @param manager_configs manager configuration parameters
 * @return only on errors, socket will be closed
 * */
STATIC void wm_agent_upgrade_listen_messages(const wm_manager_configs* manager_configs) __attribute__((nonnull));

void* router_module_ptr = NULL;

router_subscriber_create_func router_subscriber_create_ptr = NULL;
router_subscriber_subscribe_func router_subscriber_subscribe_ptr = NULL;
router_subscriber_unsubscribe_func router_subscriber_unsubscribe_ptr = NULL;
router_subscriber_destroy_func router_subscriber_destroy_ptr = NULL;

/**
 * Router subscriber thread that listens for router signals and forwards them to upgrade socket
 * @return thread function
 * */
STATIC void* wm_agent_upgrade_router_subscriber_thread(void) __attribute__((nonnull));

/**
 * Callback function for router subscriber to handle incoming messages
 * @param message received message
 * */
STATIC void wm_agent_upgrade_router_callback(const char* message);

void wm_agent_upgrade_start_manager_module(const wm_manager_configs* manager_configs, const int enabled) {

    // Check if module is enabled
    if (!enabled) {
        mtinfo(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_MODULE_DISABLED);
        pthread_exit(NULL);
    }

    mtinfo(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_MODULE_STARTED);

    // Initialize task hashmap
    wm_agent_upgrade_init_task_map();

    // Initialize upgrade queue
    wm_agent_upgrade_init_upgrade_queue();

    // Start listener
    wm_agent_upgrade_listen_messages(manager_configs);

    // Destroy task hashmap
    wm_agent_upgrade_destroy_task_map();

    // Destroy upgrade queue
    wm_agent_upgrade_destroy_upgrade_queue();
}

STATIC void wm_agent_upgrade_listen_messages(const wm_manager_configs* manager_configs) {

    // Initialize socket
    int sock = OS_BindUnixDomainWithPerms(WM_UPGRADE_SOCK, SOCK_STREAM, OS_MAXSTR, getuid(), wm_getGroupID(), 0660);
    if (sock < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_BIND_SOCK_ERROR, WM_UPGRADE_SOCK, strerror(errno));
        return;
    }

    // Wait a few seconds until the task manager starts
    sleep(WM_AGENT_UPGRADE_START_WAIT_TIME);

    // Cancel pending upgrade tasks since they were lost
    wm_agent_upgrade_cancel_pending_upgrades();

    // Start dispatch upgrades thread
    w_create_thread(wm_agent_upgrade_dispatch_upgrades, (void *)manager_configs);

    // Start router subscriber thread
    w_create_thread(wm_agent_upgrade_router_subscriber_thread, NULL);

    while (1) {
        // listen - wait connection
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SELECT_ERROR, strerror(errno));
                close(sock);
                return;
            }
            continue;
        case 0:
            continue;
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
                    message = wm_agent_upgrade_process_upgrade_command(agent_ids, (wm_upgrade_task *)task);
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
            case WM_UPGRADE_AGENT_UPDATE_STATUS:
                if (task && agent_ids) {
                    message = wm_agent_upgrade_process_agent_result_command(agent_ids, (wm_upgrade_agent_status_task *)task);
                }
                wm_agent_upgrade_free_agent_status_task(task);
                break;
            case WM_UPGRADE_RESULT:
                if (agent_ids) {
                    message = wm_agent_upgrade_process_upgrade_result_command(agent_ids);
                }
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

STATIC void wm_agent_upgrade_router_callback(const char* message) {

    if (!message) {
        mtdebug1(WM_AGENT_UPGRADE_LOGTAG, "Empty router message received");
        return;
    }

    // Connect to upgrade socket
    int sock = OS_ConnectUnixDomain(WM_UPGRADE_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock == OS_SOCKTERR) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, "Could not connect to upgrade module socket at '%s'. Error: %s", WM_UPGRADE_SOCK, strerror(errno));
    } else {
        mtdebug1(WM_AGENT_UPGRADE_LOGTAG, "Sending router-triggered upgrade message: '%s'", message);

        OS_SendSecureTCP(sock, strlen(message), message);
        os_free(message);
        close(sock);
    }
}

STATIC bool initialize_router_functions(void) {

    if (router_module_ptr = so_get_module_handle("router"), router_module_ptr)
    {
        router_subscriber_create_ptr = so_get_function_sym(router_module_ptr, "router_subscriber_create");
        router_subscriber_subscribe_ptr = so_get_function_sym(router_module_ptr, "router_subscriber_subscribe");
        router_subscriber_unsubscribe_ptr = so_get_function_sym(router_module_ptr, "router_subscriber_unsubscribe");
        router_subscriber_destroy_ptr = so_get_function_sym(router_module_ptr, "router_subscriber_destroy");

    }
    else
    {
        mtwarn(WM_ROUTER_LOGTAG, "Unable to load router module.");
        return false;
    }
    return true;
}

STATIC void* wm_agent_upgrade_router_subscriber_thread(void) {
    mtinfo(WM_AGENT_UPGRADE_LOGTAG, "Starting router subscriber thread for upgrade notifications");

    if (!initialize_router_functions()) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, "Failed to initialize router functions");
        return NULL;
    }

    // Create router subscriber handle
    const char* topic_name = "upgrade_notifications";
    const char* subscriber_id = "ack_upgrade";
    bool is_local = false;

    ROUTER_SUBSCRIBER_HANDLE subscriber_handle = router_subscriber_create_ptr(topic_name, subscriber_id, is_local);

    if (!subscriber_handle) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, "Failed to create router subscriber for topic '%s'", topic_name);
        return NULL;
    }

    // Subscribe to messages with our callback
    if (router_subscriber_subscribe_ptr(subscriber_handle, wm_agent_upgrade_router_callback) != 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, "Failed to subscribe to router topic '%s'", topic_name);
        router_subscriber_destroy_ptr(subscriber_handle);
        return NULL;
    }

    mtinfo(WM_AGENT_UPGRADE_LOGTAG, "Successfully subscribed to router topic '%s'", topic_name);

    // Register cleanup handlers for thread cancellation/exit
    pthread_cleanup_push((void(*)(void*))router_subscriber_destroy_ptr, subscriber_handle);
    pthread_cleanup_push((void(*)(void*))router_subscriber_unsubscribe_ptr, subscriber_handle);

    while (FOREVER()) {
        sleep(1);
        pthread_testcancel();
    }

    // Cleanup
    // These will be called automatically via pthread_cleanup_push if thread is cancelled
    pthread_cleanup_pop(1); // calls router_subscriber_unsubscribe_ptr
    pthread_cleanup_pop(1); // calls router_subscriber_destroy_ptr

    mtinfo(WM_AGENT_UPGRADE_LOGTAG, "Router subscriber thread stopped");
    return NULL;
}
