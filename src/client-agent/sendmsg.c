/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"

static pthread_mutex_t send_mutex;

/* Initialize sender structure */
void sender_init() {
    w_mutex_init(&send_mutex, NULL);
}

/**
 * @brief Send a message to destination server using TCP or UDP protocol.
 * @param msg Payload to sent
 * @param msg_size Payload size
 * @retval true on message sent
 * @retval false on message not sent
 * */
int send_message(const char *msg, ssize_t msg_size)
{
    int retval;
    int error;

    if (agt->server[agt->rip_id].protocol == IPPROTO_UDP) {
        retval = OS_SendUDPbySize(agt->sock, msg_size, msg);
#ifndef WIN32
        error = errno;
#endif
    } else {
        w_mutex_lock(&send_mutex);
        retval = OS_SendSecureTCP(agt->sock, msg_size, msg);
#ifndef WIN32
        error = errno;
#endif
        w_mutex_unlock(&send_mutex);
    }

    if (!retval) {
        agent_state.msg_sent++;
    } else {
#ifdef WIN32
        error = WSAGetLastError();
        mwarn(SEND_ERROR, "server", win_strerror(error));
#else
        switch (error) {
        case EPIPE:
            mdebug2(TCP_EPIPE);
            break;
        case ECONNREFUSED:
            mdebug2(CONN_REF);
            break;
        default:
            mwarn(SEND_ERROR, "server", strerror(error));
            break;
        }

#endif
        sleep(1);
    }
    return retval;
}

/**
 * @brief Create an encrypted message and send the message to destination server.
 * @param msg Message
 * @param msg_size Message length
 * @retval true on message sent
 * @retval false on message not sent
 * */
int send_msg(const char *msg, ssize_t msg_length)
{
    ssize_t msg_size;
    char crypt_msg[OS_MAXSTR + 1];
    int retval;

    msg_size = CreateSecMSG(&keys, msg, msg_length < 0 ? strlen(msg) : (size_t)msg_length, crypt_msg, 0);
    if (msg_size <= 0) {
        merror(SEC_ERROR);
        return (-1);
    }

    retval = send_message(crypt_msg, msg_size);
    return retval;
}
