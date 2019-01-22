/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <pthread.h>

#include "shared.h"
#include "remoted.h"
#include "os_net/os_net.h"


/* Start of a new thread. Only returns on unrecoverable errors. */
void *AR_Forward(__attribute__((unused)) void *arg)
{
    int arq = 0;
    int key_id = 0;
    int ar_location = 0;
    const char * path = isChroot() ? ARQUEUE : DEFAULTDIR ARQUEUE;

    char msg_to_send[OS_SIZE_1024 + 1];

    char msg[OS_SIZE_1024 + 1];
    char *location = NULL;
    char *ar_location_str = NULL;
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;
    char agent_id[KEYSIZE + 1] = "";

    /* Create the unix queue */
    if ((arq = StartMQ(path, READ)) < 0) {
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    memset(msg, '\0', OS_SIZE_1024 + 1);

    /* Daemon loop */
    while (1) {
        if (OS_RecvUnix(arq, OS_SIZE_1024, msg)) {

            mdebug2("Active response request received: %s", msg);

            /* Always zero the location */
            ar_location = 0;

            /* Get the location */
            location = msg;

            /* Location is going to be the agent name */
            tmp_str = strchr(msg, ')');
            if (!tmp_str) {
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            *tmp_str = '\0';

            /* Going after the ')' and space */
            tmp_str += 2;

            /* Extract the source IP */
            tmp_str = strchr(tmp_str, ' ');
            if (!tmp_str) {
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            tmp_str++;
            location++;

            /* Set ar_location */
            ar_location_str = tmp_str;
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

            /* Extract the active response location */
            tmp_str = strchr(ar_location_str, ' ');
            if (!tmp_str) {
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            *tmp_str = '\0';
            tmp_str++;

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
                snprintf(msg_to_send, OS_SIZE_1024, "%s%s",
                         CONTROL_HEADER,
                         tmp_str);
            } else {
                snprintf(msg_to_send, OS_SIZE_1024, "%s%s%s",
                         CONTROL_HEADER,
                         EXECD_HEADER,
                         tmp_str);
            }

            mdebug2("Active response sent: %s", msg_to_send);

            /* Send to ALL agents */
            if (ar_location & ALL_AGENTS) {
                unsigned int i;

                /* Lock use of keys */
                key_lock_read();

                for (i = 0; i < keys.keysize; i++) {
                    if (keys.keyentries[i]->rcvd >= (time(0) - DISCON_TIME)) {
                        strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                        key_unlock();
                        send_msg(agent_id, msg_to_send, -1);
                        key_lock_read();
                    }
                }

                key_unlock();
            }

            /* Send to the remote agent that generated the event */
            else if ((ar_location & REMOTE_AGENT) && (location != NULL)) {
                key_lock_read();
                key_id = OS_IsAllowedName(&keys, location);

                if (key_id < 0) {
                    key_unlock();
                    merror(AR_NOAGENT_ERROR, location);
                    continue;
                }

                strncpy(agent_id, keys.keyentries[key_id]->id, KEYSIZE);
                key_unlock();
                send_msg(agent_id, msg_to_send, -1);
            }

            /* Send to a pre-defined agent */
            else if (ar_location & SPECIFIC_AGENT) {
                ar_location++;
                send_msg(ar_agent_id, msg_to_send, -1);
            }
        }
    }
}
