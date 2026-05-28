/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* remote daemon
 * Listen to remote packets and forward them to the analysis system
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"

#define WM_STRCAT_NO_SEPARATOR 0

/* Global variables */
keystore keys;
remoted logr;
char* node_name;

/* Handle remote connections */
void HandleRemote(int uid)
{
    const int position = logr.position;

    /* If syslog connection and allowips is not defined, exit */
    if (logr.conn[position] == SYSLOG_CONN) {
        if (logr.allowips == NULL) {
            minfo(NO_SYSLOG);
            exit(0);
        } else {
            os_ip **tmp_ips;

            tmp_ips = logr.allowips;
            while (*tmp_ips) {
                minfo("Remote syslog allowed from: '%s'", (*tmp_ips)->ip);
                tmp_ips++;
            }
        }
    }

    // Set resource limit for file descriptors

    {
        struct rlimit rlimit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
            merror("Could not set resource limit for file descriptors to %d: %s (%d)", (int)nofile, strerror(errno), errno);
        }
    }

    /* If TCP is enabled then bind the TCP socket */
    if (logr.proto[position] & REMOTED_NET_PROTOCOL_TCP) {

        logr.tcp_sock = OS_Bindporttcp(logr.port[position], logr.lip[position], logr.ipv6[position]);

        if (logr.tcp_sock < 0) {
            merror_exit(BIND_ERROR, logr.port[position], errno, strerror(errno));
        }
        else if (logr.conn[position] == SECURE_CONN) {

            if (OS_SetKeepalive(logr.tcp_sock) < 0) {
                merror("OS_SetKeepalive failed with error '%s'", strerror(errno));
            }
#ifndef CLIENT
            else {
                OS_SetKeepalive_Options(logr.tcp_sock, tcp_keepidle, tcp_keepintvl, tcp_keepcnt);
            }
#endif
            if (OS_SetRecvTimeout(logr.tcp_sock, recv_timeout, 0) < 0) {
                merror("OS_SetRecvTimeout failed with error '%s'", strerror(errno));
            }
        }
    }
    /* If UDP is enabled then bind the UDP socket */
    if (logr.proto[position] & REMOTED_NET_PROTOCOL_UDP) {
        /* Using UDP. Fast, unreliable... perfect */
        logr.udp_sock = OS_Bindportudp(logr.port[position], logr.lip[position], logr.ipv6[position]);

        if (logr.udp_sock < 0) {
            merror_exit(BIND_ERROR, logr.port[position], errno, strerror(errno));
        }
    }


    /* Revoke privileges */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, USER, errno, strerror(errno));
    }

    /* Create PID */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* If secure connection, deal with it */
    if (logr.conn[position] == SECURE_CONN) {
        HandleSecure();
    }
    else if (logr.proto[position] == REMOTED_NET_PROTOCOL_TCP) {
        HandleSyslogTCP();
    }
    else { /* If not, deal with syslog */
        HandleSyslog();
    }
}
