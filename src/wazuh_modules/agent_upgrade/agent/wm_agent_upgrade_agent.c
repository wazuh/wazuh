/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_agent.h"

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#include "unit_tests/wrappers/windows/synchapi_wrappers.h"
#endif
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

const char* upgrade_values[] = {
    [WM_UPGRADE_SUCCESSFUL] = "0",
    [WM_UPGRADE_FAILED] = "2"
};

const char* upgrade_messages[] = {
    [WM_UPGRADE_SUCCESSFUL] = "Upgrade was successful",
    [WM_UPGRADE_FAILED]      = "Upgrade failed"
};

static const char *task_statuses_map[] = {
    [WM_UPGRADE_SUCCESSFUL] = WM_TASK_STATUS_DONE,
    [WM_UPGRADE_FAILED] = WM_TASK_STATUS_FAILED
};

/**
 * Reads the upgrade_result file if it is present and sends the upgrade result message to the manager.
 * Example message:
 * {
 *   "command": "agent_upgraded/agent_upgrade_failed",
 *   "params":  {
 *     "error": 0/{ERROR_CODE},
 *     "message": "Upgrade was successfull"
 *   }
 * }
 * @param queue_fd File descriptor of the upgrade queue
 * @param state upgrade result state
 * */
STATIC void wm_upgrade_agent_send_ack_message(int *queue_fd, wm_upgrade_agent_state state);

/**
 * Checks in the upgrade_results file for a code that determines the result
 * of the upgrade operation, then sends it to the current manager
 * @param queue_fd file descriptor of the queue where the notification will be sent
 * @return a flag indicating if any result was found
 * @retval true information was found on the upgrade_result file
 * @retval either the upgrade_result file does not exist or contains invalid information
 * */
STATIC bool wm_upgrade_agent_search_upgrade_result(int *queue_fd);

void wm_agent_upgrade_check_status(const wm_agent_configs* agent_config) {
    /**
     *  StartMQ will wait until agent connection which is when the pkg_install.sh will write 
     *  the upgrade result
    */
    int queue_fd = StartMQ(DEFAULTQPATH, WRITE, INFINITE_OPENQ_ATTEMPTS);

    // Wait until pkg_installer script verifies the agent was connected and writes the upgrade_result file
    sleep(WM_AGENT_UPGRADE_RESULT_WAIT_TIME);

    if (queue_fd < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_QUEUE_FD);
    } else {
        bool result_available = true;
        unsigned int wait_time = agent_config->upgrade_wait_start;
        /**
         * This loop will send the upgrade result notification to the manager
         * If the manager is able to update the upgrade status will notify the agent
         * erasing the result file and exiting this loop 
         * */
        while (result_available) {
            result_available = wm_upgrade_agent_search_upgrade_result(&queue_fd);

            if(result_available) {
                sleep(wait_time);

                wait_time *= agent_config->upgrade_wait_factor_increase;
                if (wait_time > agent_config->upgrade_wait_max) {
                    wait_time = agent_config->upgrade_wait_max;
                }
            }
        }
    #ifndef WIN32
        close(queue_fd);
    #endif
    }
}

STATIC void wm_upgrade_agent_send_ack_message(int *queue_fd, wm_upgrade_agent_state state) {
    int msg_delay = 1000000 / wm_max_eps;
    cJSON* root = cJSON_CreateObject();
    cJSON* parameters = cJSON_CreateObject();

    cJSON_AddStringToObject(root, task_manager_json_keys[WM_TASK_COMMAND], task_manager_commands_list[WM_TASK_UPGRADE_UPDATE_STATUS]);
    cJSON_AddNumberToObject(parameters, task_manager_json_keys[WM_TASK_ERROR], atoi(upgrade_values[state]));
    cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_ERROR_MESSAGE], upgrade_messages[state]);
    cJSON_AddStringToObject(parameters,  task_manager_json_keys[WM_TASK_STATUS], task_statuses_map[state]);
    cJSON_AddItemToObject(root, task_manager_json_keys[WM_TASK_PARAMETERS], parameters);

    char *msg_string = cJSON_PrintUnformatted(root);
    if (wm_sendmsg(msg_delay, *queue_fd, msg_string, task_manager_modules_list[WM_TASK_UPGRADE_MODULE], UPGRADE_MQ) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
        if(*queue_fd >= 0){
            close(*queue_fd);
        }
        *queue_fd = StartMQ(DEFAULTQPATH, WRITE, INFINITE_OPENQ_ATTEMPTS);
        if (*queue_fd < 0) {
            mterror_exit(WM_AGENT_UPGRADE_LOGTAG, QUEUE_FATAL, DEFAULTQUEUE);
        }
    }

    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ACK_MESSAGE, msg_string);
    os_free(msg_string);
    cJSON_Delete(root);
}

STATIC bool wm_upgrade_agent_search_upgrade_result(int *queue_fd) {
    char buffer[20];
    const char * PATH = WM_AGENT_UPGRADE_RESULT_FILE;

    FILE *result_file = fopen(PATH, "r");
    if (result_file) {
        fgets(buffer, 20, result_file);
        fclose(result_file);

        wm_upgrade_agent_state state;
        for (state = 0; state < WM_UPGRADE_MAX_STATE; state++) {
            // File can either be "0\n" or "2\n", so we are expecting a positive match
            if (strstr(buffer, upgrade_values[state]) != NULL) {
                // Matched value, send message
                wm_upgrade_agent_send_ack_message(queue_fd, state);
                return true;
            }
        }
    }
    return false;
}
