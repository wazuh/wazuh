/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <pthread.h>

#include "shared.h"
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
    keyentry * key;

    key_lock_read();
    key_id = OS_IsAllowedID(&keys, agent_id);

    if (key_id < 0) {
        key_unlock();
        merror(AR_NOAGENT_ERROR, agent_id);
        return (-1);
    }

    key = OS_DupKeyEntry(keys.keyentries[key_id]);

    /* If we don't have the agent id, ignore it */
    if (key->rcvd < (time(0) - DISCON_TIME)) {
        mwarn(SEND_DISCON, key->id);
        return (-1);
    }

    msg_size = CreateSecMSG(&keys, msg, msg_length < 0 ? strlen(msg) : (size_t)msg_length, crypt_msg, key_id);
    key_unlock();

    if (msg_size <= 0) {
        merror(SEC_ERROR);
        return (-1);
    }

    /* Send initial message */
    if (logr.proto[logr.position] == UDP_PROTO) {
        retval = sendto(logr.sock, crypt_msg, msg_size, 0, (struct sockaddr *)&key->peer_info, logr.peer_size) == msg_size ? 0 : -1;
        error = errno;
    } else if (key->sock >= 0) {
        w_mutex_lock(&key->mutex);
        retval = OS_SendSecureTCP(key->sock, msg_size, crypt_msg);
        error = errno;
        w_mutex_unlock(&key->mutex);
    } else {
        OS_FreeKey(key);
        mdebug1("Send operation cancelled due to closed socket.");
        return -1;
    }

    if (retval < 0) {
        switch (error) {
        case 0:
            mwarn(SEND_ERROR " [%d]", agent_id, "Unknown error.", key->sock);
            break;
        case EPIPE:
        case EBADF:
            mdebug1(SEND_ERROR " [%d]", agent_id, "Agent may have disconnected.", key->sock);
            break;
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            mwarn(SEND_ERROR " [%d]", agent_id, "Agent is not responding.", key->sock);
            break;
        default:
            merror(SEND_ERROR " [%d]", agent_id, strerror(error), key->sock);
        }
    } else {
        rem_inc_msg_sent();
    }

    OS_FreeKey(key);
    return retval;
}
