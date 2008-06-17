/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
 */


#include "shared.h"
#include "agentd.h"

#include "os_net/os_net.h"

#include "sec.h"



/* EventForward v0.1, 2005/11/09
 * Receives a message in the internal queue
 * and forward it to the analysis server.
 */
void *EventForward(void *none)
{
    int recv_b;
    char msg[OS_MAXSTR +2];
    

    /* Initializing variables */
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
        }


        /* Setting availables to 0 */
        available_forwarder = 0;


        /* Unlocking mutex */
        if(pthread_mutex_unlock(&forwarder_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(NULL);
        }


        while((recv_b = recv(logr->m_queue, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0)
        {
            msg[recv_b] = '\0';
            
            send_msg(0, msg);
            
            run_notify();
        }
    }
    
    return(NULL);
}



/* EOF */
