/*   $OSSEC, ar-forward.c, v0.1, 2005/11/05, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>
#include <signal.h>

#include "remoted.h"
#include "os_net/os_net.h"


/*** Prototypes ***/
int send_msg(int agentid, char *msg);


/** void *AR_Forward(void *arg) v0.1
 * Start of a new thread. Only returns
 * on unrecoverable errors.
 */
void *AR_Forward(void *arg)
{
    int i = 0;
    int arq = 0;
    int agent_id = 0;
    int ar_location = 0;
    
    char msg_to_send[OS_MAXSTR +1];
    
    char *msg = NULL;
    char *location = NULL;
    char *ar_location_str = NULL;
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;


    /* Creating the unix queue */
    if((arq = StartMQ(ARQUEUE, READ)) < 0)
    {
        ErrorExit(QUEUE_ERROR, ARGV0, ARQUEUE);
    }

    /* Daemon loop */
    while(1)
    {
        if((msg = OS_RecvUnix(arq, OS_MAXSTR)) != NULL)
        {

            /* Always zeroing the location */
            ar_location = 0;
            
            /* Getting the location */
            location = msg;
            
            tmp_str = index(msg, ' ');
            if(!tmp_str)
            {
                merror(EXECD_INV_MSG, ARGV0, msg);
                goto cleanup;
            }
            *tmp_str = '\0';
            tmp_str++;


            /* Setting ar_location */
            ar_location_str = tmp_str;
            if(*tmp_str == ALL_AGENTS_C)
            {
                ar_location|=ALL_AGENTS;
            }
            tmp_str++;
            if(*tmp_str == REMOTE_AGENT_C)
            {
                ar_location|=REMOTE_AGENT;
            }
            tmp_str++;
            if(*tmp_str == SPECIFIC_AGENT_C)
            {
                ar_location|=SPECIFIC_AGENT;
            }
            
            
            /***  Extracting the agent ip (NULL if local) ***/
            tmp_str = index(location, '>');
            if(!tmp_str)
            {
                /* It is a local message from
                 * the AS. Not generated externally.
                 */
                location = NULL;
            }
            else
            {
                tmp_str--;
                *tmp_str = '\0';
            }


            /*** Extracting the active response location ***/
            tmp_str = index(ar_location_str, ' ');
            if(!tmp_str)
            {
                merror(EXECD_INV_MSG, ARGV0, msg);
                goto cleanup;
            }
            *tmp_str = '\0';
            tmp_str++;


            /*** Extracting the agent id */
            ar_agent_id = tmp_str;
            tmp_str = index(tmp_str, ' ');
            if(!tmp_str)
            {
                merror(EXECD_INV_MSG, ARGV0, msg);
                goto cleanup;
            }
            *tmp_str = '\0';
            tmp_str++;
            
            
            /*** Creating the new message ***/
            snprintf(msg_to_send, OS_MAXSTR, "%s%s%s", 
                                             CONTROL_HEADER,
                                             EXECD_HEADER,
                                             tmp_str);

            
            /* Sending to ALL agents */
            if(ar_location & ALL_AGENTS)
            {
                for(i = 0;i< keys.keysize; i++)
                {
                    send_msg(i, msg_to_send);
                }
            }

            /* Send to the remote agent that generated the event */
            else if((ar_location & REMOTE_AGENT) && (location != NULL))
            {
                agent_id = IsAllowedIP(&keys, location);
                if(agent_id < 0)
                {
                    merror(AR_NOAGENT_ERROR, ARGV0, location);
                    goto cleanup;
                }
                
                send_msg(agent_id, msg_to_send);
            }

            /* Send to a pre-defined agent */
            else if(ar_location & SPECIFIC_AGENT)
            {
                ar_location++;

                agent_id = IsAllowedID(&keys, ar_agent_id);
                
                if(agent_id < 0)
                {
                    merror(AR_NOAGENT_ERROR, ARGV0, ar_agent_id);
                    goto cleanup;
                }

                send_msg(agent_id, msg_to_send);
            }

            cleanup:
            free(msg);
        }
    }
}

 

/* send_msg: 
 * Send message to an agent.
 * Returns -1 on error
 */
int send_msg(int agentid, char *msg)
{
    int msg_size;
    char crypt_msg[OS_MAXSTR +1];

    /* If we don't have the agent id, ignore it */
    if(!keys.rcvd[agentid])
    {
        return(-1);
    }

    
    msg_size = CreateSecMSG(&keys, msg, crypt_msg, agentid);
    if(msg_size == 0)
    {
        merror(SEC_ERROR,ARGV0);
        return(-1);
    }

    /* Sending initial message */
    if(sendto(logr.sock, crypt_msg, msg_size, 0,
                         (struct sockaddr *)&keys.peer_info[agentid],
                         logr.peer_size) < 0) 
    {
        merror(SEND_ERROR,ARGV0, keys.ids[agentid]);
        return(-1);
    }
    

    return(0);
}



/* EOF */
