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
        /* Everything on this queue is a stateless event: sync sessions go
         * straight to the module's STREAM intake (#37836), so there is no 's'
         * frame class left to route. The accumulator owns the back-pressure
         * (drop-newest), so a full one drops this frame and the loop goes on. */
        w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);

        /* SendMSGAction() (mq_op.c) writes these frames via OS_SendUnix(..., 0),
         * whose "size == 0 means C string" convention sends strlen(msg) + 1
         * bytes -- the NUL terminator rides along as part of the datagram.
         * w_https_client_submit_event() is strictly length-delimited, not
         * NUL-terminated, so left uncorrected that trailing NUL becomes a real
         * extra byte of event content on the wire. Trim exactly one, mirroring
         * what the legacy handshake path used to do (send_msg(msg, -1) ->
         * strlen()) before 6867e35baa ("route the agent's events to /stateless
         * only") collapsed both frame classes into this raw datagram length. */
        ssize_t content_len = recv_b;
        if (content_len > 0 && msg[content_len - 1] == '\0') {
            content_len--;
        }

        w_https_client_submit_event(msg, content_len);
    }

    return (NULL);
}
