/*   $OSSEC, secure.c, v0.3, 2005/02/09, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <time.h>

#include "os_net/os_net.h"


#include "remoted.h"


/** void HandleSecure(int position) v0.3
 * Handle the secure connections
 */
void HandleSecure(int position)
{
    int agentid;

    char buffer[OS_MAXSTR +1];
    char cleartext_msg[OS_MAXSTR +1]; 
    char srcip[IPSIZE +1];
    char *tmp_msg;


    int recv_b;

    struct sockaddr_in peer_info;
    socklen_t peer_size;



    /* Initializing manager */
    manager_init();


    /* Creating Ar forwarder thread */
    if(CreateThread(AR_Forward, (void *)NULL) != 0)
    {
        ErrorExit(THREAD_ERROR, ARGV0);
    }
    
    /* Creating wait_for_msgs thread */
    if(CreateThread(wait_for_msgs, (void *)NULL) != 0)
    {
        ErrorExit(THREAD_ERROR, ARGV0);
    }


    /* Reading authentication keys */
    ReadKeys(&keys);


    /* setting up peer size */
    peer_size = sizeof(peer_info);
    logr.peer_size = sizeof(peer_info);


    /* Initializing some variables */
    memset(buffer, '\0', OS_MAXSTR +1);
    memset(cleartext_msg, '\0', OS_MAXSTR +1);
    tmp_msg = NULL;

    
    
    /* loop in here */
    while(1)
    {
        /* Receiving message  */
        recv_b = recvfrom(logr.sock, buffer, OS_MAXSTR, 0, 
                (struct sockaddr *)&peer_info, &peer_size);


        /* Nothing received */
        if(recv_b <= 0)
            continue;


        /* Setting the source ip */
        strncpy(srcip, inet_ntoa(peer_info.sin_addr), IPSIZE);
        srcip[IPSIZE] = '\0';



        /* Getting a valid agentid */ 
        agentid = IsAllowedIP(&keys, srcip); 
        if(agentid < 0)
        {
            merror(DENYIP_ERROR,ARGV0,srcip);
            continue;
        }
        

        /* Decrypting the message */    
        tmp_msg = ReadSecMSG(&keys, buffer, cleartext_msg,
                agentid,recv_b -1);
        if(tmp_msg == NULL)
        {
            merror(MSG_ERROR,ARGV0,srcip);
            continue;
        }


        /* Check if it is a control message */ 
        if(IsValidHeader(tmp_msg))
        {

            /* We need to save the peerinfo if it is a control msg */
            memcpy(&keys.peer_info[agentid], &peer_info, peer_size);

            save_controlmsg(agentid, tmp_msg);
        }


        /* If we can't send the message, try to connect to the
         * socket again. If not exit.
         */
        else if(SendMSG(logr.m_queue, tmp_msg, srcip, NULL,
                    SECURE_MQ) < 0)
        {
            merror(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);

            if((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0)
            {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
            }
        }

    }
}



/* EOF */
