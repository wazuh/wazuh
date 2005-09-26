/*   $OSSEC, manager.c, v0.1, 2005/09/24, Daniel B. Cid$   */

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


#include "os_net/os_net.h"
#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/file_op.h"
#include "error_messages/error_messages.h"

#include "agentd.h"


/* start_mgr: Start manager thread */
void *start_mgr(void *arg)
{
    int sock;
    int *port = (int *)arg;
    int msg_size;

    
    char tmp_msg[1024];
    char *crypt_msg;
    char *uname;
    
    printf("Starting manager thread on port %d..\n", *port);


    /* Connect to the server */
    if((sock =  OS_ConnectTCP(*port, logr->rip)) < 0)
    {
        merror(CONNS_ERROR, ARGV0, logr->rip);
        return(NULL);
    }
    
    /* Send the message.
     * Message is going to be the 
     * uname : file checksum : file checksum :
     */   
    
    /* Getting uname */
    uname = getuname();
    if(!uname)
    {
        uname = strdup("No system info available");
        if(!uname)
        {
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }
    }
    
    printf("connected \n");
    
    /* creating message */
    snprintf(tmp_msg, 1024, "%s:",uname);
    
    crypt_msg = CreateSecMSG(&keys, tmp_msg, 0, &msg_size);
    
    if(crypt_msg == NULL)
    {
        merror(SEC_ERROR,ARGV0);
        return(NULL);
    }
   
    /* sending message */
    if(write(sock, crypt_msg, msg_size) < msg_size)
    {
        merror("%s: Error sending message to server (write)",ARGV0);
    }
                                                                                     
    printf("message sent!\n");
    free(crypt_msg);
    return(NULL);
}

/* EOF */
