/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"

/* Send a message to the server */
int send_msg(const char *msg, ssize_t msg_length)
{
    ssize_t msg_size;
    uint32_t length;
    char crypt_msg[OS_MAXSTR + 1];
    int recv_b;

    msg_size = CreateSecMSG(&keys, msg, msg_length < 0 ? strlen(msg) : (size_t)msg_length, crypt_msg, 0);
    if (msg_size == 0) {
        merror(SEC_ERROR);
        return (-1);
    }

    /* Send msg_size of crypt_msg */
    if (agt->server[agt->rip_id].protocol == UDP_PROTO) {
        recv_b = OS_SendUDPbySize(agt->sock, msg_size, crypt_msg);
    } else {
        length = wnet_order(msg_size);
        OS_SendTCPbySize(agt->sock, sizeof(length), (char *)&length);
        recv_b = OS_SendTCPbySize(agt->sock, msg_size, crypt_msg);
    }

    if (recv_b < 0) {
        merror(SEND_ERROR, "server", strerror(errno));
        sleep(1);
        return (-1);
    }

    agent_state.msg_sent++;
    return (0);
}
