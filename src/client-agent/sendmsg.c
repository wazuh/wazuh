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
    if (OS_SendUDPbySize(agt->sock, msg_size, crypt_msg) < 0) {
        merror(SEND_ERROR, ARGV0, "server");
        sleep(1);
        return (-1);
    }

    return (0);
}

