/* @(#) $Id: ./src/remoted/syslog.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "shared.h"
#include "os_net/os_net.h"

#include "remoted.h"



/* OS_IPNotAllowed, v0.1, 2005/02/11
 * Checks if an IP is not allowed.
 */
static int OS_IPNotAllowed(char *srcip)
{
    if(logr.denyips != NULL)
    {
        if(OS_IPFoundList(srcip, logr.denyips))
        {
            return(1);
        }
    }
    if(logr.allowips != NULL)
    {
        if(OS_IPFoundList(srcip, logr.allowips))
        {
            return(0);
        }
    }

    /* If the ip is not allowed, it will be denied */
    return(1);
}


/** void HandleSyslog() v0.2
 * Handle syslog connections
 */
void HandleSyslog()
{
    char buffer[OS_SIZE_1024 +2];
    char srcip[IPSIZE +1];

    char *buffer_pt = NULL;

    int recv_b;

    struct sockaddr_storage peer_info;
    socklen_t peer_size;


    /* setting peer size */
    peer_size = sizeof(peer_info);


    /* Initializing some variables */
    memset(buffer, '\0', OS_SIZE_1024 +2);


    /* Connecting to the message queue
     * Exit if it fails.
     */
    if((logr.m_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
    {
        ErrorExit(QUEUE_FATAL,ARGV0, DEFAULTQUEUE);
    }


    /* Infinite loop in here */
    while(1)
    {
        /* Receiving message  */
        recv_b = recvfrom(logr.sock, buffer, OS_SIZE_1024, 0,
                (struct sockaddr *)&peer_info, &peer_size);

        /* Nothing received */
        if(recv_b <= 0)
            continue;


        /* null terminating the message */
        buffer[recv_b] = '\0';


        /* Removing new line */
        if(buffer[recv_b -1] == '\n')
        {
            buffer[recv_b -1] = '\0';
        }

        /* Setting the source ip */
        satop((struct sockaddr *) &peer_info, srcip, IPSIZE);
        srcip[IPSIZE] = '\0';


        /* Removing syslog header */
        if(buffer[0] == '<')
        {
            buffer_pt = strchr(buffer+1, '>');
            if(buffer_pt)
            {
                buffer_pt++;
            }
            else
            {
                buffer_pt = buffer;
            }
        }
        else
        {
            buffer_pt = buffer;
        }

        /* Checking if IP is allowed here */
        if(OS_IPNotAllowed(srcip))
        {
            merror(DENYIP_WARN,ARGV0,srcip);
        }

        else if(SendMSG(logr.m_queue, buffer_pt, srcip,
                        SYSLOG_MQ) < 0)
        {
            merror(QUEUE_ERROR,ARGV0,DEFAULTQUEUE, strerror(errno));
            if((logr.m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
            {
                ErrorExit(QUEUE_FATAL,ARGV0,DEFAULTQUEUE);
            }
        }
    }
}



/* EOF */
