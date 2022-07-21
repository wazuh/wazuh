/* Copyright (C) 2015, Wazuh Inc.
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

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

/**
 * @brief Get the offset of the syslog message, discarding the PRI header.
 *
 * @param syslog_msg RAW syslog message
 * @return Length of the PRI header, 0 if not present
 */
STATIC size_t w_get_pri_header_len(const char * syslog_msg);

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
 * @param socket_buffer sockbuffer_t structure that contains the data from the socket.
 * @param srcip String with the IP of the queue where the message will be sent.
 */
void send_buffer(sockbuffer_t *socket_buffer, char *srcip) {
    char *data_pt = socket_buffer->data;
    int offset;
    char * buffer_pt = NULL;

    buffer_pt = strchr(data_pt, '\n');

    while(buffer_pt != NULL) {
        // Get the position of '\n' in buffer
        offset = ((int)(buffer_pt - data_pt));
        *buffer_pt = '\0';
        // Send message to the queue
        if (SendMSG(logr.m_queue, data_pt + w_get_pri_header_len(data_pt), srcip, SYSLOG_MQ) < 0) {
            merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

            if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
                merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
            }
        }
        // Re-calculate the used size of buffer and remove the message from the buffer
        socket_buffer->data_len = socket_buffer->data_len - (offset + 1);
        data_pt += (offset + 1);
        // Find the next '\n'
        buffer_pt = strchr(data_pt, '\n');
    }
    memcpy(socket_buffer->data, data_pt, socket_buffer->data_len);

}

/* Handle each client */
static void HandleClient(int client_socket, char *srcip)
{
    int r_sz = 0;
    sockbuffer_t socket_buff;

    os_calloc(OS_MAXSTR + 2, sizeof(char), socket_buff.data);
    socket_buff.data_len = 0;

    /* Create PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }
    while (1) {
        /* If an error occurred, or received 0 bytes, we need to return and close the socket */
        r_sz = recv(client_socket, socket_buff.data + socket_buff.data_len, OS_MAXSTR - socket_buff.data_len, 0);
        socket_buff.data_len += r_sz;

        socket_buff.data[socket_buff.data_len] = '\0';
        switch (r_sz) {
            case -1:
                merror(RECV_ERROR, strerror(errno), errno);
                // Fallthrough
            case 0:
                close(client_socket);
                DeletePID(ARGV0);
                os_free(socket_buff.data);
                return;
            default:
                mdebug2("Received %d bytes from '%s'", r_sz, srcip);
                break;
        }
        send_buffer(&socket_buff, srcip);
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
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
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
        int client_socket = OS_AcceptTCP(logr.tcp_sock, srcip, IPSIZE);
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

STATIC size_t w_get_pri_header_len(const char * syslog_msg) {

    size_t retval = 0;          // Offset
    char * pri_head_end = NULL; // end of <PRI> head

    if (syslog_msg != NULL && syslog_msg[0] == '<') {
        pri_head_end = strchr(syslog_msg + 1, '>');
        if (pri_head_end != NULL) {
            retval = (pri_head_end + 1) - syslog_msg;
        }
    }

    return retval;
}
