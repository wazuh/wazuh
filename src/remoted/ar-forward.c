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

#include "shared.h"


void *AR_Forward(void *arg)
{
    int arq = 0;
    char *msg = NULL;

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
            merror("msg: %s",msg);
            free(msg);
        }
    }
}

 

/* send_msg: Send message to the agent.
 * Returns -1 on error
 */
int send_msg(int agentid, char *msg)
{
    int msg_size;
    char crypt_msg[OS_MAXSTR +1];
    char buffer[OS_MAXSTR +1];


    /* Sending the file name first */
    snprintf(buffer, OS_MAXSTR, "#!execd %s\n", msg);

    msg_size = CreateSecMSG(&keys, buffer, crypt_msg, agentid);
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
        merror(SEND_ERROR,ARGV0);
        return(-1);
    }
    

    return(0);
}



/* EOF */
