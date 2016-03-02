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
int send_msg(int agentid, const char *msg)
{
    size_t msg_size;
    char crypt_msg[OS_MAXSTR + 1];

    msg_size = CreateSecMSG(&keys, msg, crypt_msg, agentid);
    if (msg_size == 0) {
        merror(SEC_ERROR, ARGV0);
        return (-1);
    }

    /* Send msg_size of crypt_msg */
    if (agt->protocol == UDP_PROTO) {
        if (OS_SendUDPbySize(agt->sock, msg_size, crypt_msg) < 0) {
            merror(SEND_ERROR, ARGV0, "server");
            sleep(1);
            return (-1);
        }
    } else {
        if (agt->sock_r >= 0) {
            close(agt->sock_r);
        }
        
        agt->sock_r = OS_ConnectTCP(agt->port, agt->rip[agt->rip_id], strchr(agt->rip[agt->rip_id], ':') != NULL);

        if (agt->sock_r < 0) {
            merror(CONNS_ERROR, ARGV0, agt->rip[agt->rip_id]);
            sleep(1);
            return -1;
        }

        if (OS_SendTCPbySize(agt->sock_r, msg_size, crypt_msg) < 0) {
            merror(SEND_ERROR, ARGV0, "server");
            sleep(1);
            return (-1);
        }
    }

    return (0);
}
