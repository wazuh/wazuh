/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <pthread.h>

#include "shared.h"
#include "remoted.h"
#include "os_net/os_net.h"
#include "wazuh_modules/wm_task_general.h"

cJSON* remoted_create_task_manager_payload(const char* status, const char* error);

cJSON *wm_agent_send_task_information_master(const cJSON *message_object) {
    cJSON* response = NULL;

    int sock = OS_ConnectUnixDomain(WM_TASK_MODULE_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock == OS_SOCKTERR) {
        mterror("TEST_LOGTAG", WM_UPGRADE_UNREACHEABLE_TASK_MANAGER, WM_TASK_MODULE_SOCK);
    } else {
        char *buffer = NULL;
        int length;
        char *message = cJSON_PrintUnformatted(message_object);
        mtdebug1("TEST_LOGTAG", WM_UPGRADE_TASK_SEND_MESSAGE, message);

        OS_SendSecureTCP(sock, strlen(message), message);
        os_free(message);
        os_calloc(OS_MAXSTR, sizeof(char), buffer);

        switch (length = OS_RecvSecureTCP(sock, buffer, OS_MAXSTR), length) {
            case OS_SOCKTERR:
                mterror("TEST_LOGTAG", WM_UPGRADE_SOCKTERR_ERROR);
                break;
            case -1:
                mterror("TEST_LOGTAG", WM_UPGRADE_RECV_ERROR, strerror(errno));
                break;
            default:
                response = cJSON_Parse(buffer);
                if (!response) {
                    mterror("TEST_LOGTAG", WM_UPGRADE_INVALID_TASK_MAN_JSON);
                } else {
                    mtdebug1("TEST_LOGTAG", WM_UPGRADE_TASK_RECEIVE_MESSAGE, buffer);
                }
                break;
        }
        os_free(buffer);

        close(sock);
    }

    return response;
}


/* Start of a new thread. Only returns on unrecoverable errors. */
void *AR_Forward(__attribute__((unused)) void *arg)
{
    int arq = 0;
    int ar_location = 0;
    const char * path = ARQUEUE;
    char *msg_to_send;
    os_calloc(OS_MAXSTR, sizeof(char), msg_to_send);
    char *msg;
    os_calloc(OS_MAXSTR, sizeof(char), msg);
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;

    /* Create the unix queue */
    if ((arq = StartMQ(path, READ, 0)) < 0) {
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    /* Daemon loop */
    while (1) {
        if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg)) {

            mdebug2("Active response request received: %s", msg);

            /* Always zero the location */
            ar_location = 0;

            /* Location */
            tmp_str = strchr(msg, ')');
            if (!tmp_str) {
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            tmp_str += 2;

            /* Source IP */
            tmp_str = strchr(tmp_str, ']');
            if (!tmp_str) {
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            tmp_str += 2;

            /* AR location */
            if (*tmp_str == ALL_AGENTS_C) {
                ar_location |= ALL_AGENTS;
            }
            tmp_str++;
            if (*tmp_str == REMOTE_AGENT_C) {
                ar_location |= REMOTE_AGENT;
            } else if (*tmp_str == NO_AR_C) {
                ar_location |= NO_AR_MSG;
            }
            tmp_str++;
            if (*tmp_str == SPECIFIC_AGENT_C) {
                ar_location |= SPECIFIC_AGENT;
            }
            tmp_str += 2;

            /* Extract the agent id */
            ar_agent_id = tmp_str;
            tmp_str = strchr(tmp_str, ' ');
            if (!tmp_str) {
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            *tmp_str = '\0';
            tmp_str++;

            /* Create the new message */
            if (ar_location & NO_AR_MSG) {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s",
                         CONTROL_HEADER,
                         tmp_str);
            } else {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s%s",
                         CONTROL_HEADER,
                         EXECD_HEADER,
                         tmp_str);
            }

            mdebug2("Active response sent: %s", msg_to_send);

            //Create task
            cJSON* task_payload = remoted_create_task_manager_payload("test_status", "error_message");

            cJSON* task_manager_response = wm_agent_send_task_information_master(task_payload);
            char* str_response = cJSON_PrintUnformatted(task_manager_response);

            mwarn("Task manager response: %s", str_response );

            cJSON_Delete(task_payload);
            cJSON_Delete(task_manager_response);
            //**************


            /* Send to ALL agents */
            if (ar_location & ALL_AGENTS) {
                char agent_id[KEYSIZE + 1] = "";

                /* Lock use of keys */
                key_lock_read();

                for (unsigned int i = 0; i < keys.keysize; i++) {
                    if (keys.keyentries[i]->rcvd >= (time(0) - logr.global.agents_disconnection_time)) {
                        strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                        key_unlock();
                        send_msg(agent_id, msg_to_send, -1);
                        key_lock_read();
                    }
                }

                key_unlock();
            }

            /* Send to the remote agent that generated the event or to a pre-defined agent */
            else if (ar_location & (REMOTE_AGENT | SPECIFIC_AGENT)) {
                send_msg(ar_agent_id, msg_to_send, -1);
            }
        }
    }
}


cJSON* remoted_create_task_manager_payload(const char* status, const char* error) {
    // Create ids array
     cJSON *agents_array = cJSON_CreateArray();
     cJSON_AddItemToArray(agents_array, cJSON_CreateNumber(1));

    //******************************************
    cJSON *request = cJSON_CreateObject();
    cJSON *origin = cJSON_CreateObject();
    cJSON *parameters = cJSON_CreateObject();

    cJSON_AddStringToObject(origin, task_manager_json_keys[WM_TASK_NAME], "test_node");
    cJSON_AddStringToObject(origin, task_manager_json_keys[WM_TASK_MODULE], task_manager_modules_list[WM_TASK_TEST_MODULE]);
    cJSON_AddItemToObject(request, task_manager_json_keys[WM_TASK_ORIGIN], origin);
    cJSON_AddStringToObject(request, task_manager_json_keys[WM_TASK_COMMAND], task_manager_commands_list[WM_TASK_TEST_TASK]);
    if (agents_array) {
        cJSON_AddItemToObject(parameters, task_manager_json_keys[WM_TASK_AGENTS], agents_array);
    }
    if (status) {
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_STATUS], status);
    }
    if (error) {
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_ERROR_MSG], error);
    }
    cJSON_AddItemToObject(request, task_manager_json_keys[WM_TASK_PARAMETERS], parameters);


    return request;

}