/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <sys/epoll.h>
#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"

/* Handle each message received */
static void HandleSecureMessage();

/* Handle secure connections */
void HandleSecure()
{
    const int protocol = logr.proto[logr.position];
    int sock_client;
    int n_events, epoll_fd = 0;
    char buffer[OS_MAXSTR + 1];
    char srcip[IPSIZE + 1];
    ssize_t recv_b;
    netsize_t length;
    struct sockaddr_in peer_info;
    struct epoll_event request, *events;

    /* Send msg init */
    send_msg_init();

    /* Initialize key mutex */
    keyupdate_init();

    /* Initialize manager */
    manager_init(0);

    /* Create Active Response forwarder thread */
    if (CreateThread(AR_Forward, (void *)NULL) != 0) {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    /* Create wait_for_msgs thread */
    if (CreateThread(wait_for_msgs, (void *)NULL) != 0) {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    /* Connect to the message queue
     * Exit if it fails.
     */
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }

    verbose(AG_AX_AGENTS, ARGV0, MAX_AGENTS);

    /* Read authentication keys */
    verbose(ENC_READ, ARGV0);
    OS_ReadKeys(&keys);
    OS_StartCounter(&keys);

    /* Set up peer size */
    logr.peer_size = sizeof(peer_info);

    /* Initialize some variables */
    memset(buffer, '\0', OS_MAXSTR + 1);

    if (protocol == TCP_PROTO) {
        os_calloc(MAX_EVENTS, sizeof(struct epoll_event), events);
        epoll_fd = epoll_create(MAX_EVENTS);

        if (epoll_fd < 0) {
            ErrorExit(EPOLL_ERROR, ARGV0);
        }

        request.events = EPOLLIN;
        request.data.fd = logr.sock;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, logr.sock, &request) < 0) {
            ErrorExit(EPOLL_ERROR, ARGV0);
        }
    } else {
        events = NULL;
    }

    while (1) {
        /* Receive message  */
        if (protocol == TCP_PROTO) {
            n_events = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_MILLIS);

            int i;
            for (i = 0; i < n_events; i++) {
                if (events[i].data.fd == logr.sock) {
                    sock_client = OS_AcceptTCP(logr.sock, srcip, IPSIZE);
                    if (sock_client < 0) {
                        ErrorExit(ACCEPT_ERROR, ARGV0);
                    }

                    request.data.fd = sock_client;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_client, &request) < 0) {
                        ErrorExit(EPOLL_ERROR, ARGV0);
                    }
                } else {
                    sock_client = events[i].data.fd;
                    recv_b = recv(sock_client, (char*)&length, sizeof(length), 0);

                    /* Nothing received */
                    if (recv_b <= 0) {
                        request.data.fd = sock_client;
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock_client, &request) < 0) {
                            ErrorExit(EPOLL_ERROR, ARGV0);
                        }

                        close(sock_client);
                        continue;
                    }

                    recv_b = recv(sock_client, buffer, length, 0);

                    if (recv_b != length) {
                        merror(RECV_ERROR, ARGV0);
                        continue;
                    } else {
                        HandleSecureMessage(buffer, recv_b, srcip, &sock_client);
                    }
                }
            }
        } else {
            recv_b = recvfrom(logr.sock, buffer, OS_MAXSTR, 0, (struct sockaddr *)&peer_info, &logr.peer_size);

            /* Set the source IP */
            strncpy(srcip, inet_ntoa(peer_info.sin_addr), IPSIZE);
            srcip[IPSIZE] = '\0';

            /* Nothing received */
            if (recv_b <= 0) {
                continue;
            } else {
                HandleSecureMessage(buffer, recv_b, srcip, &peer_info);
            }
        }
    }
}

static void HandleSecureMessage(char *buffer, int recv_b, char *srcip, void *peer) {
    struct sockaddr_in *peer_info;
    int agentid, sock_client = -1;
    int protocol = logr.proto[logr.position];
    char cleartext_msg[OS_MAXSTR + 1];
    char srcmsg[OS_FLSIZE + 1];
    char *tmp_msg;

    if (protocol == TCP_PROTO) {
        sock_client = *(int*)peer;
    } else {
        peer_info = (struct sockaddr_in *)peer;
    }

    /* Initialize some variables */
    memset(cleartext_msg, '\0', OS_MAXSTR + 1);
    memset(srcmsg, '\0', OS_FLSIZE + 1);
    tmp_msg = NULL;

    /* Get a valid agent id */
    if (buffer[0] == '!') {
        tmp_msg = buffer;
        tmp_msg++;

        /* We need to make sure that we have a valid id
         * and that we reduce the recv buffer size
         */
        while (isdigit((int)*tmp_msg)) {
            tmp_msg++;
            recv_b--;
        }

        if (*tmp_msg != '!') {
            merror(ENCFORMAT_ERROR, __local_name, srcip);
            return;
        }

        *tmp_msg = '\0';
        tmp_msg++;
        recv_b -= 2;

        agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);

        if (agentid == -1) {
            if (check_keyupdate()) {
                agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);
                if (agentid == -1) {
                    merror(ENC_IP_ERROR, ARGV0, buffer + 1, srcip);
                    return;
                }
            } else {
                merror(ENC_IP_ERROR, ARGV0, buffer + 1, srcip);
                return;
            }
        }
    } else {
        agentid = OS_IsAllowedIP(&keys, srcip);

        if (agentid < 0) {
            if (check_keyupdate()) {
                agentid = OS_IsAllowedIP(&keys, srcip);
                if (agentid == -1) {
                    merror(DENYIP_WARN, ARGV0, srcip);
                    return;
                }
            } else {
                merror(DENYIP_WARN, ARGV0, srcip);
                return;
            }
        }
        tmp_msg = buffer;
    }

    /* Decrypt the message */
    tmp_msg = ReadSecMSG(&keys, tmp_msg, cleartext_msg,
                         agentid, recv_b - 1);

    if (tmp_msg == NULL) {

        /* If duplicated, a warning was already generated */
        return;
    }


    /* Check if it is a control message */
    if (IsValidHeader(tmp_msg)) {
        /* We need to save the peerinfo if it is a control msg */
        if (protocol == UDP_PROTO) {
            memcpy(&keys.keyentries[agentid]->peer_info, &peer_info, logr.peer_size);
        } else {
            keys.keyentries[agentid]->sock = sock_client;
        }

        keys.keyentries[agentid]->rcvd = time(0);
        save_controlmsg((unsigned)agentid, tmp_msg);

        return;
    }

    /* Generate srcmsg */
    snprintf(srcmsg, OS_FLSIZE, "(%s) %s", keys.keyentries[agentid]->name,
             keys.keyentries[agentid]->ip->ip);

    /* If we can't send the message, try to connect to the
     * socket again. If it not exit.
     */
    if (SendMSG(logr.m_queue, tmp_msg, srcmsg,
                SECURE_MQ) < 0) {
        merror(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));

        if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
        }
    }
}
