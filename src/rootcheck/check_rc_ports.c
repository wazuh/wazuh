/*   $OSSEC, check_rc_pids.c, v0.1, 2005/10/05, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include <stdio.h>       
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h> 
#include <netinet/in.h>


#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"

/** Prototypes **/
void test_ports(int proto)
{
    int i;
    int ossock;
    struct sockaddr_in server;

    for(i = 0; i<= 65535; i++)
    {
        if(proto == IPPROTO_UDP)
        {
            if((ossock = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
                continue;
        }
        else if(proto == IPPROTO_TCP)
        {
            if((ossock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
                continue;
        }

        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons( i );
        server.sin_addr.s_addr = htonl(INADDR_ANY);

        if(bind(ossock, (struct sockaddr *) &server, sizeof(server)) < 0)
            printf("proto %d port: %d\n",proto, i);
        
        close(ossock);    
    }
}

/*  check_rc_ports: v0.1
 *  Check all ports
 */
void check_rc_ports()
{
   
    /* Trsting TCP ports */ 
    test_ports(IPPROTO_TCP);

    /* Testing UDP ports */
    test_ports(IPPROTO_UDP);
        
    return;
}

/* EOF */
