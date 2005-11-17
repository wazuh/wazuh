/*   $OSSEC, event-forward.c, v0.1, 2005/11/09, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include "agentd.h"

#include "os_net/os_net.h"

#include "shared.h"
#include "sec.h"



/* EventForward v0.1, 2005/11/09
 * Receives a message in the internal queue
 * and forward it to the analysis server.
 */
void *EventForward(void *none)
{
    int local_mutex;
    int recv_b;
    int _ssize;    
    char crypt_msg[OS_MAXSTR +2];
    char msg[OS_MAXSTR +2];
    

    /* Initializing variables */
    _ssize = 0;
    memset(crypt_msg, '\0', OS_MAXSTR +2);
    memset(msg, '\0', OS_MAXSTR +2);
    
    
    /* daemon loop */	
    while(1)
    {
        /* locking mutex */
        if(pthread_mutex_lock(&forwarder_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(NULL);
        }

        if(available_forwarder == 0)
        {
            pthread_cond_wait(&forwarder_cond, &forwarder_mutex);
            merror("reiceived forwarder");
        }

        /* Setting availables to 0 */
        local_mutex = available_forwarder;
        available_forwarder = 0;

        /* Unlocking mutex */
        if(pthread_mutex_unlock(&forwarder_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(NULL);
        }

        merror("receiving from unix");

        while((recv_b = recv(logr->m_queue, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0)
        {
            msg[recv_b] = '\0';
            
            _ssize = CreateSecMSG(&keys, msg, crypt_msg, 0);

            /* Returns NULL if can't create encrypted message */
            if(_ssize == 0)
            {
                merror(SEC_ERROR,ARGV0);
                continue;
            }

            /* Send _ssize of crypt_msg */
            if(OS_SendUDPbySize(logr->sock, _ssize, crypt_msg) < 0)
                merror(SEND_ERROR,ARGV0);

        }
    }
    
    return(NULL);
}



/* EOF */
