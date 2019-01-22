/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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

/* Prototypes */
static int OS_IPNotAllowed(const char *srcip);


/* Check if an IP is not allowed */
static int OS_IPNotAllowed(const char *srcip)
{
    if (logr.denyips != NULL) {
        if (OS_IPFoundList(srcip, logr.denyips)) {
            return (1);
        }
    }
    if (logr.allowips != NULL) {
        if (OS_IPFoundList(srcip, logr.allowips)) {
            return (0);
        }
    }

    /* If the IP is not allowed, it will be denied */
    return (1);
}

/* Handle syslog connections */
void HandleSyslog()
{
    char buffer[OS_MAXSTR + 2];
    char srcip[IPSIZE + 1];
    char *buffer_pt = NULL;
    ssize_t recv_b;
    struct sockaddr_in peer_info;
    socklen_t peer_size;

    /* Set peer size */
    peer_size = sizeof(peer_info);

    /* Initialize some variables */
    memset(buffer, '\0', OS_MAXSTR + 2);

    /* Connect to the message queue
     * Exit if it fails.
     */
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    /* Infinite loop */
    while (1) {
        /* Receive message */
        recv_b = recvfrom(logr.sock, buffer, OS_MAXSTR, 0,
                          (struct sockaddr *)&peer_info, &peer_size);

        /* Nothing received */
        if (recv_b <= 0) {
            continue;
        }

        /* Null-terminate the message */
        buffer[recv_b] = '\0';

        /* Remove newline */
        if (buffer[recv_b - 1] == '\n') {
            buffer[recv_b - 1] = '\0';
        }

        /* Set the source IP */
        strncpy(srcip, inet_ntoa(peer_info.sin_addr), IPSIZE);
        srcip[IPSIZE] = '\0';

        /* Remove syslog header */
        if (buffer[0] == '<') {
            buffer_pt = strchr(buffer + 1, '>');
            if (buffer_pt) {
                buffer_pt++;
            } else {
                buffer_pt = buffer;
            }
        } else {
            buffer_pt = buffer;
        }

        /* Check if IP is allowed here */
        if (OS_IPNotAllowed(srcip)) {
            mwarn(DENYIP_WARN, srcip);
            continue;
        }

        if (SendMSG(logr.m_queue, buffer_pt, srcip, SYSLOG_MQ) < 0) {
            merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

            if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
                merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
            }
        }
    }
}
