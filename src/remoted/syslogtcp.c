/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"


/* Checks if an IP is not allowed */
static int OS_IPNotAllowed(char *srcip)
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

/**
 * @brief Function that sends a buffer to a queue.
 * @param buffer String with the received contents from the TCP socket.
 * @param buff_size Size of the buffer.
 * @param srcip String with the IP of the queue where the message will be sent.
 */
void send_buffer(char *buffer, int *buff_size, char *srcip) {
    int offset;
    char *buffer_pt = strchr(buffer, '\n');

    while(buffer_pt != NULL) {
        // Get the position of '\n' in buffer
        offset = ((int)(buffer_pt - buffer));
        *buffer_pt = '\0';
        // Send message to the queue
        if (SendMSG(logr.m_queue, buffer, srcip, SYSLOG_MQ) < 0) {
            merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

            if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
                merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
            }
        }
        // Re-calculate the used size of buffer and remove the message from the buffer
        *buff_size = *buff_size - (offset + 1);
        memcpy(buffer, buffer_pt + 1, *buff_size);
        // Find the next '\n'
        buffer_pt = strchr(buffer, '\n');
    }
}
/* Handle each client */
static void HandleClient(int client_socket, char *srcip)
{
    int r_sz = 0, buff_size = 0;
    char buffer[OS_MAXSTR + 2];

    /* Create PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Initialize some variables */
    memset(buffer, '\0', OS_MAXSTR + 2);
    while (1) {
        /* If an error occurred, or received 0 bytes, we need to return and close the socket */
        r_sz = recv(client_socket, buffer + buff_size, (OS_MAXSTR - buff_size) - 2, 0);
        switch (r_sz) {
            case -1:
                merror(RECV_ERROR, strerror(errno), errno);
                // Fallthrough
            case 0:
                close(client_socket);
                DeletePID(ARGV0);
                return;
            default:
                mdebug2("Received %d bytes from '%s'", r_sz, srcip);
                break;
        }
        buff_size += r_sz;
        send_buffer(buffer, &buff_size, srcip);
    }
}

/* Handle syslog TCP connections */
void HandleSyslogTCP()
{
    int childcount = 0;
    char srcip[IPSIZE + 1];

    /* Initialize some variables */
    memset(srcip, '\0', IPSIZE + 1);

    /* Connecting to the message queue
     * Exit if it fails.
     */
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    while (1) {
        /* Wait for the children */
        while (childcount) {
            int wp;
            wp = waitpid((pid_t) - 1, NULL, WNOHANG);
            if (wp < 0) {
                merror(WAITPID_ERROR, errno, strerror(errno));
            }

            /* if = 0, we still need to wait for the child process */
            else if (wp == 0) {
                break;
            } else {
                childcount--;
            }
        }

        /* Accept new connections */
        int client_socket = OS_AcceptTCP(logr.sock, srcip, IPSIZE);
        if (client_socket < 0) {
            mwarn("Accepting TCP connection from client failed: %s (%d)", strerror(errno), errno);
            continue;
        }

        /* Check if IP is allowed here */
        if (OS_IPNotAllowed(srcip)) {
            mwarn(DENYIP_WARN, srcip);
            close(client_socket);
            continue;
        }

        /* Fork to deal with new client */
        if (fork() == 0) {
            HandleClient(client_socket, srcip);
            exit(0);
        } else {
            childcount++;

            /* Close client socket, since the child is handling it */
            close(client_socket);
            continue;
        }
    }
}
