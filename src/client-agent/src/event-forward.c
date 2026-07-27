/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "sendmsg.h"
#include "state.h"
#include "os_net.h"
#include "sec.h"
#include "https_client_bridge.h"


/* Receive a message locally on the agent and forward it to the manager */
void *EventForward()
{

    ssize_t recv_b;
    char msg[OS_MAXSTR + 1];

    /* Initialize variables */
    msg[0] = '\0';
    msg[OS_MAXSTR] = '\0';

    while ((recv_b = recv(agt->m_queue, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0) {
        if (msg[0] == 's') {
            /* Stateful sync frames keep the legacy path until #37836 wires
             * /stateful; only the stateless egress moves to HTTPS here (#37835). */
            if (agt->buffer) {
                if (buffer_append(msg, recv_b) < 0) {
                    break;
                }
            } else {
                w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);
                if (send_msg(msg, recv_b) < 0) {
                    break;
                }
            }
        } else {
            /* Stateless events -> HTTPS /stateless accumulator (#37835). The
             * accumulator owns buffering and back-pressure (drop-newest), so a
             * full accumulator drops this frame without breaking the intake loop. */
            w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);
            w_https_client_submit_event(msg, recv_b);
        }
    }

    return (NULL);
}
