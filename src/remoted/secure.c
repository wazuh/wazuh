/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#if defined(__linux__)
#include <sys/epoll.h>
#elif defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/types.h>
#include <sys/event.h>
#endif /* __linux__ */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"

/* Handle each message received */
static void HandleSecureMessage(char *buffer, int recv_b, struct sockaddr_in *peer_info, int sock_client);

/* Handle secure connections */
void HandleSecure()
{
    const int protocol = logr.proto[logr.position];
    int sock_client;
    int n_events = 0;
    char buffer[OS_MAXSTR + 1];
    ssize_t recv_b;
    netsize_t length;
    struct sockaddr_in peer_info;

#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    const struct timespec TS_ZERO = { 0, 0 };
    struct timespec ts_timeout = { EPOLL_MILLIS / 1000, (EPOLL_MILLIS % 1000) * 1000000 };
    struct timespec *p_timeout = EPOLL_MILLIS < 0 ? NULL : &ts_timeout;
    int kqueue_fd = 0;
    struct kevent request;
    struct kevent *events = NULL;
#elif defined(__linux__)
    int epoll_fd = 0;
    struct epoll_event request = { 0 };
    struct epoll_event *events = NULL;
#endif /* __MACH__ || __FreeBSD__ || __OpenBSD__ */

    /* Initialize key mutex */
    keyupdate_init();

    /* Initialize manager */
    manager_init();

    /* Create Active Response forwarder thread */
    if (CreateThread(update_shared_files, (void *)NULL) != 0) {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    /* Create Active Response forwarder thread */
    if (CreateThread(AR_Forward, (void *)NULL) != 0) {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    /* Create wait_for_msgs threads */

    {
        int i;
        int thread_pool = getDefine_Int("remoted", "thread_pool", 0, 64);

        debug2(ARGV0 ": DEBUG: Creating %d sender threads.", thread_pool);

        for (i = 0; i < thread_pool; i++) {
            if (CreateThread(wait_for_msgs, (void *)NULL) != 0) {
                ErrorExit(THREAD_ERROR, ARGV0);
            }
        }
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
    OS_ReadKeys(&keys, 1, 0);
    OS_StartCounter(&keys);

    /* Set up peer size */
    logr.peer_size = sizeof(peer_info);

    /* Initialize some variables */
    memset(buffer, '\0', OS_MAXSTR + 1);

    if (protocol == TCP_PROTO) {
#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        os_calloc(MAX_EVENTS, sizeof(struct kevent), events);
        kqueue_fd = kqueue();

        if (kqueue_fd < 0) {
            ErrorExit(KQUEUE_ERROR, ARGV0);
        }

        EV_SET(&request, logr.sock, EVFILT_READ, EV_ADD, 0, 0, 0);
        kevent(kqueue_fd, &request, 1, NULL, 0, &TS_ZERO);
#elif defined(__linux__)
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
#endif /* __MACH__ || __FreeBSD__ || __OpenBSD__ */
    }

    while (1) {
        /* Receive message  */
        if (protocol == TCP_PROTO) {
#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
            n_events = kevent(kqueue_fd, NULL, 0, events, MAX_EVENTS, p_timeout);
#elif defined(__linux__)
            n_events = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_MILLIS);
#endif /* __MACH__ || __FreeBSD__ || __OpenBSD__ */

            int i;
            for (i = 0; i < n_events; i++) {
#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
                int fd = events[i].ident;
#elif defined(__linux__)
                int fd = events[i].data.fd;
#else
                int fd = 0;
#endif /* __MACH__ || __FreeBSD__ || __FreeBSD__ */
                if (fd == logr.sock) {
                    sock_client = accept(logr.sock, (struct sockaddr *)&peer_info, &logr.peer_size);
                    if (sock_client < 0) {
                        ErrorExit(ACCEPT_ERROR, ARGV0);
                    }

                    debug1("%s: DEBUG: New TCP connection at %s.", ARGV0, inet_ntoa(peer_info.sin_addr));
#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
                    EV_SET(&request, sock_client, EVFILT_READ, EV_ADD, 0, 0, 0);
                    kevent(kqueue_fd, &request, 1, NULL, 0, &TS_ZERO);
#elif defined(__linux__)
                    request.data.fd = sock_client;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_client, &request) < 0) {
                        ErrorExit(EPOLL_ERROR, ARGV0);
                    }
#endif /* __MACH__ || __FreeBSD__ || __OpenBSD__ */
                } else {
                    sock_client = fd;
                    recv_b = recv(sock_client, (char*)&length, sizeof(length), MSG_WAITALL);

                    if (getpeername(sock_client, (struct sockaddr *)&peer_info, &logr.peer_size) < 0) {
                        merror("%s: ERROR: Couldn't get the remote peer information: %s", ARGV0, strerror(errno));
                        close(sock_client);
                        continue;
                    }

                    debug2("%s: DEBUG: recv(): length=%d [%zu]", ARGV0, length, recv_b);

                    /* Nothing received */
                    if (recv_b <= 0 || length > OS_MAXSTR) {
                        if (recv_b <= 0) {
                            debug1("%s: DEBUG: TCP peer at %s disconnected.", ARGV0, inet_ntoa(peer_info.sin_addr));
                        } else {
                            merror(RECV_ERROR, ARGV0);
                        }
#ifdef __linux__
                        /* Kernel event is automatically deleted when closed */
                        request.data.fd = sock_client;
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock_client, &request) < 0) {
                            ErrorExit(EPOLL_ERROR, ARGV0);
                        }
#endif /* __linux__ */

                        close(sock_client);
                        continue;
                    }

                    recv_b = recv(sock_client, buffer, length, MSG_WAITALL);

                    if (recv_b != length) {
                        merror(RECV_ERROR, ARGV0);
#ifdef __linux__
                        request.data.fd = sock_client;
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock_client, &request) < 0) {
                            ErrorExit(EPOLL_ERROR, ARGV0);
                        }
#endif /* __linux__ */
                        close(sock_client);
                        continue;
                    } else {
                        HandleSecureMessage(buffer, recv_b, &peer_info, sock_client);
                    }
                }
            }
        } else {
            recv_b = recvfrom(logr.sock, buffer, OS_MAXSTR, 0, (struct sockaddr *)&peer_info, &logr.peer_size);

            /* Nothing received */
            if (recv_b <= 0) {
                continue;
            } else {
                HandleSecureMessage(buffer, recv_b, &peer_info, -1);
            }
        }
    }
}

static void HandleSecureMessage(char *buffer, int recv_b, struct sockaddr_in *peer_info, int sock_client) {
    int agentid;
    int protocol = logr.proto[logr.position];
    char cleartext_msg[OS_MAXSTR + 1];
    char srcmsg[OS_FLSIZE + 1];
    char srcip[IPSIZE + 1];
    char *tmp_msg;

    /* Set the source IP */
    strncpy(srcip, inet_ntoa(peer_info->sin_addr), IPSIZE);
    srcip[IPSIZE] = '\0';

    /* Initialize some variables */
    memset(cleartext_msg, '\0', OS_MAXSTR + 1);
    memset(srcmsg, '\0', OS_FLSIZE + 1);
    tmp_msg = NULL;

    check_keyupdate();

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

            if (sock_client >= 0)
                close(sock_client);

            return;
        }

        *tmp_msg = '\0';
        tmp_msg++;
        recv_b -= 2;

        agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);

        if (agentid == -1) {
            merror(ENC_IP_ERROR, ARGV0, buffer + 1, srcip);

            if (sock_client >= 0)
                close(sock_client);

            return;
        }
    } else {
        agentid = OS_IsAllowedIP(&keys, srcip);

        if (agentid < 0) {
            merror(DENYIP_WARN, ARGV0, srcip);

            if (sock_client >= 0)
                close(sock_client);

            return;
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
            memcpy(&keys.keyentries[agentid]->peer_info, peer_info, logr.peer_size);
        } else {
            keys.keyentries[agentid]->sock = sock_client;
        }

        keys.keyentries[agentid]->rcvd = time(0);
        save_controlmsg((unsigned)agentid, tmp_msg);

        return;
    }

    /* Generate srcmsg */
    snprintf(srcmsg, OS_FLSIZE, "[%s] (%s) %s", keys.keyentries[agentid]->id,
             keys.keyentries[agentid]->name, keys.keyentries[agentid]->ip->ip);

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
