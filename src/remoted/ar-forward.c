/* Copyright (C) 2009 Trend Micro Inc.
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
    int agent_id = 0;
    int ar_location = 0;

    char msg_to_send[OS_SIZE_1024 + 1];

    char msg[OS_SIZE_1024 + 1];
    char *location = NULL;
    char *ar_location_str = NULL;
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;

    /* Create the unix queue */
    if ((arq = StartMQ(ARQUEUE, READ)) < 0) {
        ErrorExit(QUEUE_ERROR, ARGV0, ARQUEUE, strerror(errno));
    }

    memset(msg, '\0', OS_SIZE_1024 + 1);

    /* Daemon loop */
    while (1) {
        if (OS_RecvUnix(arq, OS_SIZE_1024, msg)) {
            /* Always zero the location */
            ar_location = 0;

            /* Get the location */
            location = msg;

            /* Location is going to be the agent name */
            tmp_str = strchr(msg, ')');
            if (!tmp_str) {
                merror(EXECD_INV_MSG, ARGV0, msg);
                continue;
            }
            *tmp_str = '\0';

            /* Going after the ')' and space */
            tmp_str += 2;

            /* Extract the source IP */
            tmp_str = strchr(tmp_str, ' ');
            if (!tmp_str) {
                merror(EXECD_INV_MSG, ARGV0, msg);
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
                merror(EXECD_INV_MSG, ARGV0, msg);
                continue;
            }
            *tmp_str = '\0';
            tmp_str++;

            /* Extract the agent id */
            ar_agent_id = tmp_str;
            tmp_str = strchr(tmp_str, ' ');
            if (!tmp_str) {
                merror(EXECD_INV_MSG, ARGV0, msg);
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

            /* Lock use of keys */
            key_lock();

            /* Send to ALL agents */
            if (ar_location & ALL_AGENTS) {
                unsigned int i;
                for (i = 0; i < keys.keysize; i++) {
                    send_msg(i, msg_to_send);
                }
            }

            /* Send to the remote agent that generated the event */
            else if ((ar_location & REMOTE_AGENT) && (location != NULL)) {
                agent_id = OS_IsAllowedName(&keys, location);
                if (agent_id < 0) {
                    key_unlock();
                    merror(AR_NOAGENT_ERROR, ARGV0, location);
                    continue;
                }

                send_msg((unsigned)agent_id, msg_to_send);
            }

            /* Send to a pre-defined agent */
            else if (ar_location & SPECIFIC_AGENT) {
                ar_location++;

                agent_id = OS_IsAllowedID(&keys, ar_agent_id);

                if (agent_id < 0) {
                    key_unlock();
                    merror(AR_NOAGENT_ERROR, ARGV0, ar_agent_id);
                    continue;
                }

                send_msg((unsigned)agent_id, msg_to_send);
            }

            /* Lock use of keys */
            key_unlock();
        }
    }
}

