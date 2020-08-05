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

const char* upgrade_values[] = {
    [WM_UPGRADE_SUCCESSFULL] = "0",
    [WM_UPGRADE_FAILED] = "2"
};

const char* upgrade_messages[] = {
    [WM_UPGRADE_SUCCESSFULL] = "Upgrade was successful",
    [WM_UPGRADE_FAILED]      = "Upgrade failed"
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
static void wm_upgrade_agent_send_ack_message(int queue_fd, wm_upgrade_agent_state state);

void wm_agent_upgrade_check_status() {
    char buffer[20];
    FILE * result_file;
    const char * PATH = WM_AGENT_UPGRADE_RESULT_FILE;

    /**
     *  StartMQ will wait until agent connection which is when the pkg_install.sh will write 
     *  the upgrade result
    */
    int queue_fd = StartMQ(DEFAULTQPATH, WRITE, MAX_OPENQ_ATTEMPS);

    if (queue_fd < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_QUEUE_FD);
    } else {
        if (result_file = fopen(PATH, "r"), result_file) {
            fgets(buffer, 20, result_file);
            fclose(result_file);

            wm_upgrade_agent_state state;
            for(state = 0; state < WM_UPGRADE_MAX_STATE; state++) {
                // File can either be "0\n" or "2\n", so we are expecting a positive match
                if (strcmp(buffer, upgrade_values[state]) >= 0) {
                    // Matched value, send message
                    wm_upgrade_agent_send_ack_message(queue_fd, state);
                }
            }
        }
        close(queue_fd);
    }
}

static void wm_upgrade_agent_send_ack_message(int queue_fd, wm_upgrade_agent_state state) {
    int msg_delay = 1000000 / wm_max_eps;
    cJSON* root = cJSON_CreateObject();
    cJSON* params = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "command", WM_UPGRADE_AGENT_UPDATED_COMMAND);
    cJSON_AddNumberToObject(params, "error", atoi(upgrade_values[state]));
    cJSON_AddStringToObject(params, "message", upgrade_messages[state]);
    cJSON_AddItemToObject(root, "params", params);

    char *msg_string = cJSON_PrintUnformatted(root);
    if (wm_sendmsg(msg_delay, queue_fd, msg_string, WM_AGENT_UPGRADE_MODULE_NAME, UPGRADE_MQ) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
    }

    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ACK_MESSAGE, msg_string);
    os_free(msg_string);
    cJSON_Delete(root);
}
