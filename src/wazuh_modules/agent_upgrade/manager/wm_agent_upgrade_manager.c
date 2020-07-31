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
#include "wm_agent_upgrade_manager.h"
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "os_net/os_net.h"

const char* upgrade_error_codes[] = {
    [WM_UPGRADE_SUCCESS] = "Success",
    [WM_UPGRADE_PARSING_ERROR] = "Could not parse message JSON",
    [WM_UPGRADE_PARSING_REQUIRED_PARAMETER] = "Required parameters in json message where not found",
    [WM_UPGRADE_TASK_CONFIGURATIONS] = "Command not recognized",
    [WM_UPGRADE_TASK_MANAGER_COMMUNICATION] ="Could not create task id for upgrade task",
    [WM_UPGRADE_TASK_MANAGER_FAILURE] = "", // Data string will be provided by task manager
    [WM_UPGRADE_UPGRADE_ALREADY_ON_PROGRESS] = "Upgrade procedure could not start. Agent already upgrading",
    [WM_UPGRADE_UNKNOWN_ERROR] "Upgrade procedure could not start"
};

void wm_agent_upgrade_listen_messages(int sock, int timeout_sec) {
    struct timeval timeout = { timeout_sec, 0 };

    while(1) {
        // listen - wait connection
        fd_set fdset;    
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            if (errno != EINTR) {
                merror(WM_UPGRADE_SELECT_ERROR, strerror(errno));
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
                merror(WM_UPGRADE_ACCEPT_ERROR, strerror(errno));
            }
            continue;
        }
        
        // Get request string
        char *buffer = NULL;
        cJSON* json_response = NULL;
        cJSON* params = NULL;
        cJSON* agents = NULL;
        int parsing_retval;
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
            parsing_retval = wm_agent_upgrade_parse_command(&buffer[0], &json_response, &params, &agents);
            break;
        }

        if (json_response) {
            cJSON *command_response = NULL;
            char* message = NULL;
            switch (parsing_retval)
            {
                case WM_UPGRADE_UPGRADE:
                    command_response = wm_agent_upgrade_process_upgrade_command(params, agents);
                    message = cJSON_PrintUnformatted(command_response); 
                    cJSON_Delete(command_response);
                    break;
                case WM_UPGRADE_UPGRADE_CUSTOM:
                    command_response = wm_agent_upgrade_process_upgrade_custom_command(params, agents);
                    message = cJSON_PrintUnformatted(command_response);
                    cJSON_Delete(command_response);
                    break;
                case WM_UPGRADE_UPGRADE_RESULT:
                    command_response = wm_agent_upgrade_process_upgrade_result_command(agents);
                    message = cJSON_PrintUnformatted(command_response); 
                    cJSON_Delete(command_response);
                    break;
                case WM_UPGRADE_AGENT_UPGRADED:
                case WM_UPGRADE_AGENT_UPGRADE_FAILED:
                    command_response = wm_agent_upgrade_process_agent_result_command((wm_upgrade_command) parsing_retval, params, agents);
                    message = cJSON_PrintUnformatted(command_response); 
                    cJSON_Delete(command_response);
                    break;
                default:
                    message = cJSON_PrintUnformatted(json_response);
                    break;
            }
            mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RESPONSE_MESSAGE, message);
            OS_SendSecureTCP(peer, strlen(message), message);
            os_free(message);
            cJSON_Delete(json_response);
        }

        free(buffer);
        close(peer);
    }
}
