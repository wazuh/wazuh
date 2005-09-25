/*   $OSSEC, manager.c, v0.1, 2005/09/23, Daniel B. Cid$   */

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

#include "remoted.h"

#include "os_net/os_net.h"
#include "headers/defs.h"
#include "headers/debug_op.h"
#include "error_messages/error_messages.h"


#define OIMSG   "Oi, estou vivo."
#define CHEGUEI "Cheguei."

/* handleagent: Handle new connections from agent. 
 * If message is just a "I'm alive" message, do not fork.
 * If message is a new one, fork and share configs
 */
void handleagent(int clientsocket, char *srcip)
{
    int n;
    int client_size = OS_MAXSTR -1;

    char buf[OS_MAXSTR +1];
    char client_msg[OS_MAXSTR +1];
    char *cleartext_msg;
    char *tmp_msg;

    /* Null terminating */
    client_msg[0] = '\0';
    client_msg[client_size +1] = '\0';

    /* IP not on the agents list */
    if(CheckAllowedIP(&keys, srcip, NULL) == -1)
    {
        merror(DENYIP_ERROR,ARGV0,srcip);
        close(clientsocket);
        return;
    }

    /* Reading from client */
    while((n = read(clientsocket, buf, OS_MAXSTR)) > 0)
    {
        buf[n] = '\0';
        strncat(client_msg, buf, client_size);
        client_size-= n;

        /* Error in here, message should not be that big */
        if(client_size <= 1)
        {
            merror("%s: Invalid message from client '%s'",ARGV0, srcip);
            close(clientsocket);
            return;
        }
    }

    if(n < 0)
    {
        merror(READ_ERROR,ARGV0);
        close(clientsocket);
        return;
    }

    
    /* Decrypting the message */
    cleartext_msg = ReadSecMSG(&keys, srcip, client_msg);
    if(cleartext_msg == NULL)
    {
        merror(MSG_ERROR,ARGV0,srcip);
        close(clientsocket);
        return;
    }

    /* Removing checksum and rand number */
    tmp_msg = cleartext_msg;
    
    tmp_msg++;
    
    /* Removing checksum */
    tmp_msg = index(tmp_msg, ':');
    if(!tmp_msg)
    {
        merror("%s: Invalid message from '%s'",ARGV0, srcip);
        close(clientsocket);
        free(cleartext_msg);
        return;
    }

    tmp_msg++;

    /* Removing randon */
    tmp_msg = index(tmp_msg, ':');
    if(!tmp_msg)
    {   
        merror("%s: Invalid message from '%s'",ARGV0, srcip);
        close(clientsocket);
        free(cleartext_msg);
        return;
    }   
    
    tmp_msg++;
                                                    
    /* tmp_msg is now the desired message */

    if(strncmp(tmp_msg, OIMSG, strlen(OIMSG)) == 0)
    {
        printf("oi message from %s. OK!\n", srcip);
        close(clientsocket);
        free(cleartext_msg);
        return;
    }
    
    printf("message is: %s, tmp:%s\n",cleartext_msg, tmp_msg);

    free(cleartext_msg);
    
    close(clientsocket);

    return; 
}


/* start_mgr: Start manager thread */
void *start_mgr(void *arg)
{
    int sock;
    int clientsock;
    int *port = (int *)arg;
    
    char srcip[16];
    
    printf("Starting manager thread on port %d..\n", *port);


    /* Bind manager port */
    if((sock = OS_Bindporttcp(*port,NULL)) < 0)
        ErrorExit(BIND_ERROR,ARGV0,port);

    
    printf("Bind port \n");

    /* Receiving connections from now on */
    while(1)
    {
        if((clientsock = OS_AcceptTCP(sock, srcip, 16)) < 0)
            ErrorExit(CONN_ERROR,ARGV0,port);

        handleagent(clientsock, srcip);    
    }

   printf("done? should't be here\n"); 
        
    
    return NULL;
}

/* EOF */
