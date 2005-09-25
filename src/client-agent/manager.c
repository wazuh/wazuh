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
#include "error_messages/error_messages.h"



/* start_mgr: Start manager thread */
void *start_mgr(void *arg)
{
    int sock;
    int *port = (int *)arg;
    
    
    printf("Starting manager thread on port %d..\n", *port);


    /* Connect to the server */
    if((sock =  OS_ConnectTCP(port, serverip)) < 0)
    {
        merror(CONNS_ERROR, ARGV0, serverip);
        return(NULL);
    }
    
    
    printf("connected \n");

    
    return(NULL);
}

/* EOF */
