/*   $OSSEC, check_open_ports.c, v0.1, 2006/01/11, Daniel B. Cid$   */

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
#include <arpa/inet.h>
#include <errno.h>

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"


int open_ports_size;
char open_ports_str[OS_MAXSTR + 1];

/* connect_to_port */
int connect_to_port(int proto, int port)
{
    int rc = 0;
    
    int ossock;
    struct sockaddr_in server;

    if(proto == IPPROTO_UDP)
    {
        if((ossock = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
            return(0);
    }
    else if(proto == IPPROTO_TCP)
    {
        if((ossock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
            return(0);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons( port );
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(connect(ossock, (struct sockaddr *)&server, sizeof(server)) == 0)
    {
        rc = 1;
    }
    
    close(ossock);  

    return(rc);  
}

/* try_to_access_ports */
void try_to_access_ports()
{
    int i;

    for(i = 0; i<= 65535; i++)
    {
        if(total_ports_tcp[i] && connect_to_port(IPPROTO_TCP, i))
        {
            char port_proto[64];

            snprintf(port_proto, 64, "%d (tcp),", i);
            strncat(open_ports_str, port_proto, open_ports_size);
            open_ports_size -= strlen(port_proto) +1;            
        }
        if(total_ports_udp[i] && connect_to_port(IPPROTO_UDP, i))
        {
            char port_proto[64];

            snprintf(port_proto, 64, "%d (udp),",i);
            strncat(open_ports_str, port_proto, open_ports_size);
            open_ports_size -= strlen(port_proto) +1;

        }
    }

}


/*  check_open_ports: v0.1
 *  Check all open ports
 */
void check_open_ports()
{
    memset(open_ports_str, '\0', OS_MAXSTR +1);
    open_ports_size = OS_MAXSTR - 1;
    
    #ifndef OSSECHIDS
    snprintf(open_ports_str, OS_MAXSTR, "The following ports are open: ");
    open_ports_size-=strlen(open_ports_str) +1;
    
    /* Testing All ports */ 
    try_to_access_ports();

    open_ports_str[strlen(open_ports_str)] = '\0';

    notify_rk(ALERT_OK, open_ports_str);
    
    #endif
    return;
}

/* EOF */
