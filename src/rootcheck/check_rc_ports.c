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
#include <errno.h>

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"

/* SunOS netstat */
#if defined(sun) || defined(__sun__)
#define NETSTAT "netstat -an -P %s | "\
                "grep \"[^0-9]%d \" > /dev/null 2>&1"
#endif

#ifndef NETSTAT
#define NETSTAT "netstat -an | grep \"^%s\" | " \
                "grep \"[^0-9]%d \" > /dev/null 2>&1"
#endif

int run_netstat(int proto, int port)
{
    char nt[OS_MAXSTR +1];

    if(proto == IPPROTO_TCP)
        snprintf(nt, OS_MAXSTR, NETSTAT, "tcp", port);
    else if(proto == IPPROTO_UDP)
        snprintf(nt, OS_MAXSTR, NETSTAT, "udp", port);
    else
    {
        merror("%s: Netstat error (wrong proto)", ARGV0);
        return(0);
    }

    if(system(nt) == 0)    
        return(1);
    
    return(0);    
}


int conn_port(int proto, int port)
{
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
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(ossock, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
        close(ossock);
        return(1);
    }

    close(ossock);  

    return(0);  
}


void test_ports(int proto, int *_errors, int *_total)
{
    int i;

    for(i = 0; i<= 65535; i++)
    {
        (*_total)++;
        if(conn_port(proto, i))
        {
            /* Checking if we can find it using netstat, if not,
             * check again to see if the port is still being used.
             */
            if(!run_netstat(proto, i) && conn_port(proto, i))
            {
                char op_msg[OS_MAXSTR +1];
                
                (*_errors)++;
                
                snprintf(op_msg, OS_MAXSTR, "Port '%d'(%d) hidden. "
                                "Kernel-level rootkit or trojaned "
                                "version of netstat.", i, proto);

                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }
        }
    }

}


/*  check_rc_ports: v0.1
 *  Check all ports
 */
void check_rc_ports()
{
    int _errors = 0;
    int _total = 0;
    
    /* Trsting TCP ports */ 
    test_ports(IPPROTO_TCP, &_errors, &_total);

    /* Testing UDP ports */
    test_ports(IPPROTO_UDP, &_errors, &_total);

    if(_errors == 0)
    {
        char op_msg[OS_MAXSTR +1];
        snprintf(op_msg, OS_MAXSTR,"No kernel-level rootkit hiding any port."
                                   "\n      Netstat is acting correctly."
                                    " Analized %d ports.", _total);
        notify_rk(ALERT_OK, op_msg);
    }
    
    return;
}

/* EOF */
