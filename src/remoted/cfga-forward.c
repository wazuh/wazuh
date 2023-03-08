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

#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"


/* Start of a new thread. Only returns on unrecoverable errors. */
void *SCFGA_Forward(__attribute__((unused)) void *arg)
{
    int cfgarq = 0;
    char *agent_id;
    const char * path = CFGARQUEUE;

    char msg[OS_SIZE_4096 + 1];

    /* Create the unix queue */
    if ((cfgarq = StartMQ(path, READ, 0)) < 0) {
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    memset(msg, '\0', OS_SIZE_4096 + 1);

    /* Daemon loop */
    while (1) {
        if (OS_RecvUnix(cfgarq, OS_SIZE_4096, msg)) {

            agent_id = msg;

            char *msg_dump = strchr(msg,':');

            if(msg_dump) {
                *msg_dump++ = '\0';
            } else {
                continue;
            }

            if(strncmp(msg_dump,CFGA_DB_DUMP,strlen(CFGA_DB_DUMP)) == 0) {
                char final_msg[OS_SIZE_4096 + 1] = {0};

                snprintf(final_msg, OS_SIZE_4096, "%s%s", CONTROL_HEADER, msg_dump);
                if (send_msg(agent_id, final_msg, -1) >= 0) {
                    rem_inc_send_cfga(agent_id);
                }
            }
        }
    }
}
