/* Copyright (C) 2015, Wazuh Inc.
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
#include "sendmsg.h"
#include "state.h"
#include "os_net.h"

static pthread_mutex_t send_mutex;

/* Initialize sender structure */
void sender_init() {
    w_mutex_init(&send_mutex, NULL);
}

/* Send a message to the server */
int send_msg(const char *msg, ssize_t msg_length)
{
    ssize_t msg_size;
    char crypt_msg[OS_MAXSTR + 1];
    int retval;
    int error;

    msg_size = CreateSecMSG(&keys, msg, msg_length < 0 ? strlen(msg) : (size_t)msg_length, crypt_msg, 0);
    if (msg_size <= 0) {
        merror(SEC_ERROR);
        return (-1);
    }

    w_mutex_lock(&send_mutex);
    if (agt->sock < 0) {
        /* Socket was already invalidated by another thread; skip the send
         * to avoid calling OS_SendSecureTCP(-1, ...) and reading a stale errno. */
        w_mutex_unlock(&send_mutex);
        return -1;
    }
    retval = OS_SendSecureTCP(agt->sock, msg_size, crypt_msg);
    /* OS_SendSecureTCP returns 0 on success or OS_SOCKTERR (-1) on any error,
     * including partial writes — it never returns a positive partial count,
     * so checking retval != 0 is sufficient to detect all failure modes. */
#ifndef WIN32
    error = errno;
    if (retval != 0) {
        bool socket_dead = true;
        switch (error) {
        case EPIPE:
            mdebug2(TCP_EPIPE);
            break;
        case ECONNRESET:
            mdebug2("Connection reset by manager.");
            break;
        case ETIMEDOUT:
        case EAGAIN:
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
        case EWOULDBLOCK:
#endif
            /* SO_SNDTIMEO expiry: kernel returns EAGAIN/EWOULDBLOCK on
             * blocking sockets, or ETIMEDOUT on retransmit exhaustion. */
            mdebug2(SEND_ERROR, "server", strerror(error));
            break;
        case ECONNREFUSED:
            /* The remote end refused the connection — socket is unusable. */
            mdebug2(CONN_REF);
            break;
        case ENOTCONN:
            /* Kernel already tore down the connection (e.g. after keepalive
             * exhaustion or a previous hard error). */
            mdebug2("Socket not connected.");
            break;
        default:
            mwarn(SEND_ERROR, "server", strerror(error));
            socket_dead = false;
            break;
        }
        if (socket_dead && agt->sock >= 0) {
            OS_CloseSocket(agt->sock);
            agt->sock = -1;
        }
    }
#endif
    w_mutex_unlock(&send_mutex);

    if (retval == 0) {
        w_agentd_state_update(INCREMENT_MSG_SEND, NULL);
    }
#ifdef WIN32
    else {
        error = WSAGetLastError();
        mwarn(SEND_ERROR, "server", win_strerror(error));
    }
#endif

    return retval;
}
