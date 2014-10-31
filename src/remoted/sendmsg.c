/* @(#) $Id: ./src/remoted/sendmsg.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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


/* pthread send_msg mutex */
static pthread_mutex_t sendmsg_mutex;

/* pthread key update mutex */
static pthread_mutex_t keyupdate_mutex;


/* void keyupdate_init()
 * Initializes mutex.
 */
void keyupdate_init()
{
    /* Initializing mutex */
    pthread_mutex_init(&keyupdate_mutex, NULL);
}


/* void void key_lock()
 * void key_unlock()
 * Locks/unlocks the update mutex.
 */
void key_lock()
{
    if(pthread_mutex_lock(&keyupdate_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
    }
}
void key_unlock()
{
    if(pthread_mutex_unlock(&keyupdate_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
    }
}


/* check_keyupdate()
 * Check for key updates.
 */
int check_keyupdate()
{
    /* Checking key for updates. */
    if(!OS_CheckUpdateKeys(&keys))
    {
        return(0);
    }

    key_lock();

    /* Locking before using */
    if(pthread_mutex_lock(&sendmsg_mutex) != 0)
    {
        key_unlock();
        merror(MUTEX_ERROR, ARGV0);
        return(0);
    }

    if(OS_UpdateKeys(&keys))
    {
        if(pthread_mutex_unlock(&sendmsg_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
        }
        key_unlock();
        return(1);
    }

    if(pthread_mutex_unlock(&sendmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
    }
    key_unlock();

    return(0);
}


/* send_msg_init():
 * Initializes send_msg.
 */
void send_msg_init()
{
    /* Initializing mutex */
    pthread_mutex_init(&sendmsg_mutex, NULL);
}


/* send_msg()
 * Send message to an agent.
 * Returns -1 on error
 */
int send_msg(unsigned int agentid, const char *msg)
{
    size_t msg_size;
    char crypt_msg[OS_MAXSTR +1];


    /* If we don't have the agent id, ignore it */
    if(keys.keyentries[agentid]->rcvd < (time(0) - (2*NOTIFY_TIME)))
    {
        return(-1);
    }


    msg_size = CreateSecMSG(&keys, msg, crypt_msg, agentid);
    if(msg_size == 0)
    {
        merror(SEC_ERROR,ARGV0);
        return(-1);
    }


    /* Locking before using */
    if(pthread_mutex_lock(&sendmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
        return(-1);
    }


    /* Sending initial message */
    if(sendto(logr.sock, crypt_msg, msg_size, 0,
                       (struct sockaddr *)&keys.keyentries[agentid]->peer_info,
                       logr.peer_size) < 0)
    {
        merror(SEND_ERROR,ARGV0, keys.keyentries[agentid]->id);
    }


    /* Unlocking mutex */
    if(pthread_mutex_unlock(&sendmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
        return(-1);
    }


    return(0);
}



/* EOF */
