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
#include "os_net/os_net.h"

static pthread_mutex_t send_mutex;

/* Initialize sender structure */
void sender_init() {
    w_mutex_init(&send_mutex, NULL);
}

void send_mutex_lock(void) {
    w_mutex_lock(&send_mutex);
}

void send_mutex_unlock(void) {
    w_mutex_unlock(&send_mutex);
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

    /* Send msg_size of crypt_msg */
    if (agt->server[agt->rip_id].protocol == IPPROTO_UDP) {
        retval = OS_SendUDPbySize(atomic_int_get(&agt->sock), msg_size, crypt_msg);
#ifdef WIN32
        error = WSAGetLastError();
#else
        error = errno;
#endif
    } else {
        w_mutex_lock(&send_mutex);
        /* Snapshot once: nothing else can change agt->sock while send_mutex is
         * held (every writer takes it first too), so reuse this value for the
         * rest of the critical section instead of re-reading the atomic. */
        int sock = atomic_int_get(&agt->sock);
        if (sock < 0) {
            /* Socket was already invalidated (e.g. by another sender thread
             * after a previous timed-out send). Skip the call to avoid
             * operating on -1 and reading a stale errno. The sleep(1) matches
             * every other failure path here: without it, a caller like
             * dispatch_buffer() would spin through its whole queue at
             * events_persec discarding messages silently instead of pausing
             * while the reconnect (already under way) completes. */
            w_mutex_unlock(&send_mutex);
            mdebug1("Connection is down, discarding message until it is restored.");
            sleep(1);
            return (-1);
        }
        retval = OS_SendSecureTCP(sock, msg_size, crypt_msg);
        if (retval) {
            bool socket_dead;
#ifdef WIN32
            error = WSAGetLastError();

            switch (error) {
            case WSAECONNRESET:
            case WSAECONNABORTED:
            case WSAENOTCONN:
            case WSAECONNREFUSED:
            case WSAENOTSOCK:
            case WSAETIMEDOUT:
            case WSAEWOULDBLOCK:
                /* Same reasoning as the POSIX branch below: a dead peer,
                 * an invalidated descriptor, or an SO_SNDTIMEO expiry. */
                socket_dead = true;
                break;
            case 0:
                /* WSASetLastError(0) before send() in OS_SendSecureTCP()
                 * wasn't overwritten: a short/partial write happened with
                 * no reported error. The length-prefixed framing for this
                 * connection is now corrupted; only a reconnect recovers. */
                socket_dead = true;
                break;
            default:
                socket_dead = false;
                break;
            }
#else
            error = errno;

            switch (error) {
            case EPIPE:
            case ECONNRESET:
            case ENOTCONN:
            case ECONNREFUSED:
            case EBADF:
                /* agt->sock points at a descriptor that is no longer open
                 * (e.g. closed by another thread without updating agt->sock).
                 * Without this, the agent would keep retrying send() on the
                 * same dead descriptor forever instead of reconnecting. */
                socket_dead = true;
                break;
            case ETIMEDOUT:
            case EAGAIN:
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
            case EWOULDBLOCK:
#endif
                /* SO_SNDTIMEO expired: the kernel send buffer never drained.
                 * Close and invalidate so the main loop reconnects instead of
                 * blocking again on the very next call. */
                socket_dead = true;
                break;
            case 0:
                /* errno = 0 right before send() in OS_SendSecureTCP() wasn't
                 * overwritten: a short/partial write happened with no error
                 * at all (SO_SNDTIMEO can expire after only part of a large
                 * message drained). The length-prefixed framing for this
                 * connection is now corrupted regardless of how many bytes
                 * got through; only a reconnect recovers. */
                socket_dead = true;
                break;
            default:
                socket_dead = false;
                break;
            }
#endif
            if (socket_dead) {
                OS_CloseSocket(sock);
                atomic_int_set(&agt->sock, -1);
            }
        }
        w_mutex_unlock(&send_mutex);
    }

    if (!retval) {
        w_agentd_state_update(INCREMENT_MSG_SEND, NULL);
    } else {
#ifdef WIN32
        /* `error` was already captured via WSAGetLastError() above, before
         * OS_CloseSocket() could have changed it — don't re-fetch here. */
        switch (error) {
        case WSAECONNRESET:
            mdebug2("Connection reset by manager.");
            break;
        case WSAECONNABORTED:
            mdebug2(TCP_EPIPE);
            break;
        case WSAENOTCONN:
            mdebug2("Socket not connected.");
            break;
        case WSAECONNREFUSED:
            mdebug2(CONN_REF);
            break;
        case WSAENOTSOCK:
            mdebug2("Socket descriptor no longer valid.");
            break;
        case 0:
            mwarn("Partial write to server: message framing may be corrupted, reconnecting.");
            break;
        case WSAETIMEDOUT:
        case WSAEWOULDBLOCK:
            mwarn(SEND_ERROR, "server", win_strerror(error));
            break;
        default:
            mwarn(SEND_ERROR, "server", win_strerror(error));
            break;
        }
#else
        switch (error) {
        case EPIPE:
            mdebug2(TCP_EPIPE);
            break;
        case ECONNREFUSED:
            mdebug2(CONN_REF);
            break;
        case ECONNRESET:
            mdebug2("Connection reset by manager.");
            break;
        case ENOTCONN:
            mdebug2("Socket not connected.");
            break;
        case EBADF:
            mdebug2("Socket descriptor no longer valid.");
            break;
        case 0:
            mwarn("Partial write to server: message framing may be corrupted, reconnecting.");
            break;
        case ETIMEDOUT:
        case EAGAIN:
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
        case EWOULDBLOCK:
#endif
            mwarn(SEND_ERROR, "server", strerror(error));
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
