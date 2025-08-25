/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <pthread.h>

#include "defs.h"
#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"


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
    char *payload_size_offset = NULL;
    ssize_t payload_size = 0;
    ssize_t header_size = 0;
    char *module_name = NULL;

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
            } else if (*tmp_str == SPECIFIC_AGENT_SIZED_C) {
                ar_location |= SPECIFIC_AGENT_SIZED;
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

            /* Extract the payload size */
            if (ar_location & SPECIFIC_AGENT_SIZED) {
                payload_size_offset = tmp_str;
                tmp_str = strchr(tmp_str, ' ');
                if (!tmp_str) {
                    mwarn(EXECD_INV_MSG, msg);
                    continue;
                }
                *tmp_str = '\0';
                payload_size = strtoll(payload_size_offset, NULL, 10);
                
                /* Validate payload size */
                if (payload_size < 0 || payload_size >= OS_MAXSTR) {
                    mwarn("Invalid payload size: %ld. Must be between 0 and %d. Dropping message.", 
                          payload_size, OS_MAXSTR - 1);
                    continue;
                }
                tmp_str++;

                /* Extract the module name */
                module_name = tmp_str;
                tmp_str = strchr(tmp_str, ' ');
                if (!tmp_str) {
                    mwarn(EXECD_INV_MSG, msg);
                    continue;
                }
                *tmp_str = '\0';
                tmp_str+=2;

            }

            /* Create the new message */
            if (ar_location & NO_AR_MSG) {
                if (ar_location & SPECIFIC_AGENT_SIZED) {
                    header_size = snprintf(msg_to_send, OS_MAXSTR, "%s%s ",
                             CONTROL_HEADER,
                             module_name);
                                               
                    /* Validate payload size to prevent buffer overflow */
                    if ((size_t)(header_size + payload_size) >= OS_MAXSTR) {
                        mwarn("Message size (%ld + %ld) exceeds maximum allowed size (%d). Dropping message.", 
                              header_size, payload_size, OS_MAXSTR);
                        continue;
                    }
                    
                    /* Copy the payload to the message */
                    memcpy(msg_to_send + header_size, tmp_str, payload_size);
                } else {
                    snprintf(msg_to_send, OS_MAXSTR, "%s%s",
                            CONTROL_HEADER,
                            tmp_str);
                }
            } else {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s%s",
                         CONTROL_HEADER,
                         EXECD_HEADER,
                         tmp_str);
            }

            mdebug2("Active response sent: %s", msg_to_send);

            /* Send to ALL agents */
            if (ar_location & ALL_AGENTS) {
                char agent_id[KEYSIZE + 1] = "";

                /* Lock use of keys */
                key_lock_read();

                for (unsigned int i = 0; i < keys.keysize; i++) {
                    if (keys.keyentries[i]->rcvd >= (time(0) - logr.global.agents_disconnection_time)) {
                        strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                        key_unlock();
                        if (send_msg(agent_id, msg_to_send, -1) >= 0) {
                            rem_inc_send_ar(agent_id);
                        }
                        key_lock_read();
                    }
                }

                key_unlock();
            }

            /* Send to the remote agent that generated the event or to a pre-defined agent */
            else if (ar_location & (REMOTE_AGENT | SPECIFIC_AGENT)) {
                if (send_msg(ar_agent_id, msg_to_send, -1) >= 0) {
                    rem_inc_send_ar(ar_agent_id);
                }
            }
            else if (ar_location & SPECIFIC_AGENT_SIZED) {
                if (send_msg(ar_agent_id, msg_to_send, payload_size + header_size) >= 0) {
                    rem_inc_send_ar(ar_agent_id);
                }
            }
        }
    }
}
