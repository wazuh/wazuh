/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"
#include "sec.h"

/* Message parser for wazuh-modules health check. */
void wmodules_hc_parse_msg(cJSON *const messageJSON) {
    if (messageJSON) {
        cJSON *operation = cJSON_GetObjectItem(messageJSON, "operation");
        cJSON *wmodule = cJSON_GetObjectItem(messageJSON, "wmodule");

        if (operation && wmodule) {
            const char * wmodule_string = cJSON_GetStringValue(wmodule);
            const char * operation_string = cJSON_GetStringValue(operation);
            if (wmodule_string && operation_string) {
                minfo("DWORD 1");
                if (strcmp(wmodule_string, "execd") == 0) {
                    minfo("DWORD 2");
                    if (strcmp(operation_string, "initialization") == 0) {
                        minfo("DWORD 3");
                        /* Connect to the execd queue */
                        if (agt->execdq == 0) {
                            minfo("DWORD 4");
                            if ((agt->execdq = StartMQ(EXECQUEUE, WRITE, 0)) < 0) {
                                minfo("Unable to connect to the active response "
                                    "queue (disabled).");
                                agt->execdq = -1;
                            } else {
                                mdebug2("Connect to the active response queue success.");
                            }
                        }
                    }
                }
            }
        }
    }
}

/* Receive a message locally from wazuh-modules to check health check and initialization */
int wmodules_hs_receivemsg() {
    ssize_t recv_b;
    int total_chunks_received = 0;
    char msg[OS_MAXSTR + 1];

    /* Initialize variables */
    msg[0] = '\0';
    msg[OS_MAXSTR] = '\0';

    while ((recv_b = recv(agt->wmoduleshs, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0) {
        msg[recv_b] = '\0';
        ++total_chunks_received;
        const char *jsonErrPtr;
        cJSON * messageJSON = cJSON_ParseWithOpts(msg, &jsonErrPtr, 0);
        if (!messageJSON) {
            mdebug2("Malformed JSON string '%s'", msg);
        } else {
            wmodules_hc_parse_msg(messageJSON);
            cJSON_Delete(messageJSON);
        }
    }
    return recv_b < 0 ? recv_b : total_chunks_received;
}

