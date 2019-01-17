/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include <pthread.h>
#include "remoted.h"
#include "os_net/os_net.h"

/* pthread key update mutex */
static pthread_rwlock_t keyupdate_rwlock = PTHREAD_RWLOCK_INITIALIZER;

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
    int error;

    key_lock_read();
    key_id = OS_IsAllowedID(&keys, agent_id);

    if (key_id < 0) {
        key_unlock();
        merror(AR_NOAGENT_ERROR, agent_id);
        return (-1);
    }

    /* If we don't have the agent id, ignore it */
    if (keys.keyentries[key_id]->rcvd < (time(0) - DISCON_TIME)) {
        mwarn(SEND_DISCON, keys.keyentries[key_id]->id);
        return (-1);
    }

    msg_size = CreateSecMSG(&keys, msg, msg_length < 0 ? strlen(msg) : (size_t)msg_length, crypt_msg, key_id);

    if (msg_size <= 0) {
        key_unlock();
        merror(SEC_ERROR);
        return (-1);
    }

    /* Send initial message */
    if (logr.proto[logr.position] == UDP_PROTO) {
        retval = sendto(logr.sock, crypt_msg, msg_size, 0, (struct sockaddr *)&keys.keyentries[key_id]->peer_info, logr.peer_size) == msg_size ? 0 : -1;
        error = errno;
    } else if (keys.keyentries[key_id]->sock >= 0) {
        w_mutex_lock(&keys.keyentries[key_id]->mutex);
        retval = OS_SendSecureTCP(keys.keyentries[key_id]->sock, msg_size, crypt_msg);
        error = errno;
        w_mutex_unlock(&keys.keyentries[key_id]->mutex);
    } else {
        key_unlock();
        mdebug1("Send operation cancelled due to closed socket.");
        return -1;
    }

    if (retval < 0) {
        switch (error) {
        case 0:
            mwarn(SEND_ERROR " [%d]", agent_id, "Unknown error.", keys.keyentries[key_id]->sock);
            break;
        case EPIPE:
        case EBADF:
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
