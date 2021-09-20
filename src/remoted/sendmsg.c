/* Copyright (C) 2015-2021, Wazuh Inc.
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
#include "os_net/os_net.h"

extern netbuffer_t netbuffer_send;
extern wnotify_t * notify;

/* pthread key update mutex */
static pthread_rwlock_t keyupdate_rwlock;

void key_lock_init()
{
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);

#ifdef __linux__
    /* PTHREAD_RWLOCK_PREFER_WRITER_NP is ignored.
     * Do not use recursive locking.
     */
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

    w_rwlock_init(&keyupdate_rwlock, &attr);
    pthread_rwlockattr_destroy(&attr);
}

void key_lock_read()
{
    w_rwlock_rdlock(&keyupdate_rwlock);
}

void key_lock_write()
{
    w_rwlock_wrlock(&keyupdate_rwlock);
}

void key_unlock()
{
    w_rwlock_unlock(&keyupdate_rwlock);
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
    char crypt_msg[OS_MAXSTR + 1];
    int retval = 0;
    int error = 0;

    mdebug1("---> Send Msg: agent: %s, size[%ld]", agent_id, strlen(msg));

    key_lock_read();
    key_id = OS_IsAllowedID(&keys, agent_id);

    if (key_id < 0) {
        key_unlock();
        merror(AR_NOAGENT_ERROR, agent_id);
        return (-1);
    }
    const int socket = keys.keyentries[key_id]->sock;

    /* If we don't have the agent id, ignore it */
    if (keys.keyentries[key_id]->rcvd < (time(0) - logr.global.agents_disconnection_time)) {
        key_unlock();
        mdebug1(SEND_DISCON, keys.keyentries[key_id]->id);
        return (-1);
    }

    msg_size = CreateSecMSG(&keys, msg, msg_length < 0 ? strlen(msg) : (size_t)msg_length, crypt_msg, key_id);

    if (msg_size <= 0) {
        key_unlock();
        merror(SEC_ERROR);
        return (-1);
    }

    /* Send initial message */
    if (keys.keyentries[key_id]->net_protocol == REMOTED_NET_PROTOCOL_UDP) {
        retval = sendto(logr.udp_sock, crypt_msg, msg_size, 0, (struct sockaddr *)&keys.keyentries[key_id]->peer_info, logr.peer_size) == msg_size ? 0 : -1;
        error = errno;
    } else if (socket >= 0) {
        for (unsigned int retry; retry < 10; retry++) {
            w_mutex_lock(&keys.keyentries[key_id]->mutex);
            char * data = netbuffer_send.buffers[socket].data;
            const unsigned long current_data_size = netbuffer_send.buffers[socket].data_size;
            const unsigned long current_data_len = netbuffer_send.buffers[socket].data_len;
            // For sender buffer these must be always the same.
            assert(current_data_size == current_data_len);

            if (current_data_size + msg_size + sizeof(uint32_t) <= OS_MAXSTR) {
                os_realloc(data, current_data_len + msg_size + sizeof(uint32_t), data);
                netbuffer_send.buffers[socket].data = data;
                *(uint32_t *)data = wnet_order(msg_size);
                memcpy(data + current_data_len + sizeof(uint32_t), crypt_msg, msg_size);
                netbuffer_send.buffers[socket].data_size += msg_size + sizeof(uint32_t);
                netbuffer_send.buffers[socket].data_len += msg_size + sizeof(uint32_t);
                netbuffer_send.buffers[socket].mutex = &keys.keyentries[key_id]->mutex;
                wnotify_modify(notify, socket, WO_READ | WO_WRITE);
                retval = OS_SUCCESS;

                mdebug1("Msg added to buffer, buff.data_size: %ld", netbuffer_send.buffers[socket].data_size);
                w_mutex_unlock(&keys.keyentries[key_id]->mutex);
                break;
            }
            else
            {
                merror("Packet dropped for agent id [%s]. Could not append data into buffer because there is not enough space. [buffer_size=%lu, msg_size=%lu]", agent_id, current_data_size, msg_size);
                w_mutex_unlock(&keys.keyentries[key_id]->mutex);
                sleep(1);
                retval = OS_SIZELIM;
            }
        }
        // For sender buffer these must be always the same.
        assert(netbuffer_send.buffers[socket].data_size == netbuffer_send.buffers[socket].data_len);
    } else {
        key_unlock();
        mdebug1("Send operation cancelled due to closed socket.");
        return -1;
    }

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
        rem_inc_msg_sent();
    }

    key_unlock();
    return retval;
}
