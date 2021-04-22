/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "sec.h"

/* Message parser for wazuh-modules health check. */
void wmodules_hc_parse_msg(cJSON *const messageJSON, int * execdqueue) {
    if (messageJSON) {
        cJSON *operation = cJSON_GetObjectItem(messageJSON, "operation");
        cJSON *wmodule = cJSON_GetObjectItem(messageJSON, "wmodule");
        if (operation && wmodule) {
            const char * wmodule_string = cJSON_GetStringValue(wmodule);
            const char * operation_string = cJSON_GetStringValue(operation);
            if (wmodule_string && operation_string) {
                if (strcmp(wmodule_string, "execd") == 0) {
                    if (strcmp(operation_string, "initialization") == 0) {
                        /* Connect to the execd queue */
                        if (*execdqueue == 0) {
                            if ((*execdqueue = StartMQ(EXECQUEUE, WRITE, 0)) < 0) {
                                minfo("Unable to connect to the active response "
                                    "queue (disabled).");
                                *execdqueue = -1;
                            } else {
                                minfo(CONN_TO, EXECQUEUE, "exec");
                            }
                        }
                    }
                }
            }
        }
    }
}

/* Receive a message locally from wazuh-modules to check health check and initialization */
int wmodules_hs_receivemsg(const int wmoduleshs, int * execdqueue) {
    int ret_val = 0;
    char msg[OS_MAXSTR + 1] = { 0 };
    ssize_t position = 0;
    int recv_ret = 0;

    while (1) {
        recv_ret = recv(wmoduleshs, msg+position, OS_MAXSTR, MSG_DONTWAIT);
        if (-1 == recv_ret) {
            if (errno == EAGAIN) {
                break;
            } else {
                ret_val = errno;
                position = 0;
                break;
            }
        } else {
            position += recv_ret;
        }
    }
    msg[position] = '\0';
    if (position > 0) {
        const char *jsonErrPtr;
        cJSON * messageJSON = cJSON_ParseWithOpts(msg, &jsonErrPtr, 0);
        if (!messageJSON) {
            mdebug2("Parse JSON error '%s' - '%s'", msg, jsonErrPtr);
        } else {
            wmodules_hc_parse_msg(messageJSON, execdqueue);
            cJSON_Delete(messageJSON);
        }
    }
    return ret_val;
}

