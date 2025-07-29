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
#include <pthread.h>
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"

extern netbuffer_t netbuffer_send;

/* pthread key update mutex */
static rwlock_t keyupdate_rwlock;

void key_lock_init()
{
    rwlock_init(&keyupdate_rwlock);
}

void key_lock_read()
{
    rwlock_lock_read(&keyupdate_rwlock);
}

void key_lock_write()
{
    rwlock_lock_write(&keyupdate_rwlock);
}

void key_unlock()
{
    rwlock_unlock(&keyupdate_rwlock);
}

/* Check for key updates */
int check_keyupdate()
{
    /* Check key for updates */
    if (!OS_CheckUpdateKeys(&keys)) {
        return (0);
    }

    minfo(ENCFILE_CHANGED);
    key_lock_write();
    OS_UpdateKeys(&keys);
    key_unlock();
    return 1;
}

/* Send message to an agent
 * Returns -1 on error
 * Must not call key_lock() before this
 */
int send_msg(const char *agent_id, const char *msg, ssize_t msg_length)
{
    int key_id;
    ssize_t msg_size;
    ssize_t bytes_sent = 0;
    char crypt_msg[OS_MAXSTR + 1] = {0};
    int retval = OS_INVALID;
    int error = 0;

    key_lock_read();
    key_id = OS_IsAllowedID(&keys, agent_id);

    if (key_id < 0) {
        key_unlock();
        merror(AR_NOAGENT_ERROR, agent_id);
        return OS_INVALID;
    }

    /* If we don't have the agent id, ignore it */
    if (keys.keyentries[key_id]->rcvd < (time(0) - logr.global.agents_disconnection_time)) {
        key_unlock();
        mdebug1(SEND_DISCON, keys.keyentries[key_id]->id);
        return OS_INVALID;
    }

    msg_size = CreateSecMSG(&keys, msg, msg_length < 0 ? strlen(msg) : (size_t)msg_length, crypt_msg, key_id);

    if (msg_size <= 0) {
        key_unlock();
        merror(SEC_ERROR);
        return OS_INVALID;
    }

    crypt_msg[msg_size] = '\0';

    w_mutex_lock(&keys.keyentries[key_id]->mutex);

    /* Send initial message */
    if (keys.keyentries[key_id]->net_protocol == REMOTED_NET_PROTOCOL_UDP) {
        /* UDP mode, send the message */
        bytes_sent = sendto(logr.udp_sock, crypt_msg, msg_size, 0, (struct sockaddr *)&keys.keyentries[key_id]->peer_info, logr.peer_size);
        error = errno;
        retval = bytes_sent == msg_size ? OS_SUCCESS : OS_INVALID;
    } else if (keys.keyentries[key_id]->sock >= 0) {
        /* TCP mode, enqueue the message in the send buffer */
        retval = nb_queue(&netbuffer_send, keys.keyentries[key_id]->sock, crypt_msg, msg_size, keys.keyentries[key_id]->id);
        if (retval == -1) {
            mdebug1("Not enough buffer space... [buffer_size=%lu, used=%lu, msg_size=%lu]",
                netbuffer_send.buffers[keys.keyentries[key_id]->sock].bqueue->max_length,
                netbuffer_send.buffers[keys.keyentries[key_id]->sock].bqueue->length,
                msg_size);
        }
        int sock = keys.keyentries[key_id]->sock;
        w_mutex_unlock(&keys.keyentries[key_id]->mutex);
        if (retval == -1) {
            sleep(send_timeout_to_retry);
            w_mutex_lock(&keys.keyentries[key_id]->mutex);

            /* Check if the socket is still the same */
            if (sock == keys.keyentries[key_id]->sock) {
                retval = nb_queue(&netbuffer_send, keys.keyentries[key_id]->sock, crypt_msg, msg_size, keys.keyentries[key_id]->id);
                if (retval < 0) {
                    rem_inc_send_discarded(keys.keyentries[key_id]->id);
                    mwarn("Package dropped. Could not append data into buffer.");
                }
            } else {
                rem_inc_send_discarded(keys.keyentries[key_id]->id);
                mwarn("Package dropped. Could not append data into buffer.");
                mdebug1("Send operation cancelled due to closed socket.");
            }
            w_mutex_unlock(&keys.keyentries[key_id]->mutex);
        }
        key_unlock();
        return retval;
    } else {
        w_mutex_unlock(&keys.keyentries[key_id]->mutex);
        key_unlock();
        mdebug1("Send operation cancelled due to closed socket.");
        return OS_INVALID;
    }

    /* Check UDP send result */
    if (retval < 0) {
        switch (error) {
        case 0:
            mwarn(SEND_ERROR " [%d]", agent_id, "A message could not be delivered completely.", keys.keyentries[key_id]->sock);
            break;
        case EPIPE:
        case EBADF:
        case ECONNRESET:
            mdebug1(SEND_ERROR " [%d]", agent_id, "Agent may have disconnected.", keys.keyentries[key_id]->sock);
            break;
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            mwarn(SEND_ERROR " [%d]", agent_id, "Agent is not responding.", keys.keyentries[key_id]->sock);
            break;
        default:
            merror(SEND_ERROR " [%d]", agent_id, strerror(error), keys.keyentries[key_id]->sock);
        }
    } else {
        rem_add_send(bytes_sent);
    }

    w_mutex_unlock(&keys.keyentries[key_id]->mutex);
    key_unlock();
    return retval;
}
