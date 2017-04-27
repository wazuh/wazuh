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
static pthread_mutex_t keyupdate_mutex;


/* Initializes mutex */
void keyupdate_init()
{
    /* Initialize mutex */
    pthread_mutex_init(&keyupdate_mutex, NULL);
}

void key_lock()
{
    if (pthread_mutex_lock(&keyupdate_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
    }
}

void key_unlock()
{
    if (pthread_mutex_unlock(&keyupdate_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
    }
}

/* Check for key updates */
int check_keyupdate()
{
    int retval = 0;

    /* Check key for updates */
    if (!OS_CheckUpdateKeys(&keys)) {
        return (0);
    }

    key_lock();

    if (OS_UpdateKeys(&keys)) {
        retval = 1;
    }

    key_unlock();
    return retval;
}

/* Send message to an agent
 * Returns -1 on error
 * Must not call key_lock() before this
 */
int send_msg(const char *agent_id, const char *msg)
{
    int key_id;
    int sock = -1;
    ssize_t msg_size, send_b;
    netsize_t length;
    char crypt_msg[OS_MAXSTR + 1];
    struct sockaddr_in peer_info;

    key_lock();
    key_id = OS_IsAllowedID(&keys, agent_id);

    if (key_id < 0) {
        key_unlock();
        merror(AR_NOAGENT_ERROR, ARGV0, agent_id);
        return (-1);
    }

    /* If we don't have the agent id, ignore it */
    if (keys.keyentries[key_id]->rcvd < (time(0) - (3 * NOTIFY_TIME))) {
        key_unlock();
        merror(SEND_DISCON, ARGV0, keys.keyentries[key_id]->id);
        return (-1);
    }

    msg_size = CreateSecMSG(&keys, msg, crypt_msg, key_id);

    if (logr.proto[logr.position] == UDP_PROTO) {
        memcpy(&peer_info, &keys.keyentries[key_id]->peer_info, sizeof(peer_info));
    } else {
        sock = keys.keyentries[key_id]->sock;
    }

    key_unlock();

    if (msg_size == 0) {
        merror(SEC_ERROR, ARGV0);
        return (-1);
    }

    /* Send initial message */
    if (logr.proto[logr.position] == UDP_PROTO) {
        send_b = sendto(logr.sock, crypt_msg, msg_size, 0,
               (struct sockaddr *)&peer_info,
               logr.peer_size);
    } else {
        length = msg_size;
        send(sock, (char*)&length, sizeof(length), 0);
        send_b = send(sock, crypt_msg, msg_size, 0);
    }

    if (send_b < 0) {
        merror(SEND_ERROR, ARGV0, agent_id);
    }

    return (0);
}
