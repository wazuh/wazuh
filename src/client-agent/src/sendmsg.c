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
#ifndef WIN32
    error = errno;
    if (retval != 0) {
        bool socket_dead = false;
        switch (error) {
        case EPIPE:
            mdebug2(TCP_EPIPE);
            socket_dead = true;
            break;
        case ECONNRESET:
            mdebug2("Connection reset by manager.");
            socket_dead = true;
            break;
        case ETIMEDOUT:
        case EAGAIN:
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
        case EWOULDBLOCK:
#endif
            /* SO_SNDTIMEO expiry: kernel returns EAGAIN/EWOULDBLOCK on
             * blocking sockets, or ETIMEDOUT on retransmit exhaustion. */
            mwarn(SEND_ERROR, "server", strerror(error));
            socket_dead = true;
            break;
        case ECONNREFUSED:
            /* The remote end refused the connection — socket is unusable. */
            mdebug2(CONN_REF);
            socket_dead = true;
            break;
        case ENOTCONN:
            /* Kernel already tore down the connection (e.g. after keepalive
             * exhaustion or a previous hard error). */
            mdebug2("Socket not connected.");
            socket_dead = true;
            break;
        default:
            mwarn(SEND_ERROR, "server", strerror(error));
            break;
        }
        if (socket_dead && agt->sock >= 0) {
            OS_CloseSocket(agt->sock);
            agt->sock = -1;
        }
    }
#endif
    w_mutex_unlock(&send_mutex);

    if (!retval) {
        w_agentd_state_update(INCREMENT_MSG_SEND, NULL);
    } else {
#ifdef WIN32
        error = WSAGetLastError();
        mwarn(SEND_ERROR, "server", win_strerror(error));
#else
        /* TCP send errors are handled inside send_mutex above. */
#endif
    }

    return retval;
}
