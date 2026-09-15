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
#include "os_net.h"
#include "remoted.h"

/* Global variables */
keystore keys;
remoted logr;
char* node_name;
char* cluster_name;

/* Handle remote connections */
void HandleRemote(int uid)
{
    // Raise the soft file descriptor limit; the hard limit belongs to whoever started the manager

    {
        const long effective = w_raise_nofile_limit((long)nofile, "remoted.rlimit_nofile");

        if (effective >= 0) {
            nofile = (rlim_t)effective;
        }
    }

    /* The classic TCP/UDP listener only serves 4.x agents. proto is 0 when remote.legacy
     * is absent or disabled. */

    /* If TCP is enabled then bind the TCP socket */
    if (logr.proto & REMOTED_NET_PROTOCOL_TCP) {

        logr.tcp_sock = OS_Bindporttcp(logr.port, logr.lip, logr.ipv6);

        if (logr.tcp_sock < 0) {
            merror_exit(BIND_ERROR, logr.port, errno, strerror(errno));
        }
        else {

            if (OS_SetKeepalive(logr.tcp_sock) < 0) {
                merror("OS_SetKeepalive failed with error '%s'", strerror(errno));
            }
            else {
                OS_SetKeepalive_Options(logr.tcp_sock, tcp_keepidle, tcp_keepintvl, tcp_keepcnt);
            }
            if (OS_SetRecvTimeout(logr.tcp_sock, recv_timeout, 0) < 0) {
                merror("OS_SetRecvTimeout failed with error '%s'", strerror(errno));
            }
        }
    }
    /* If UDP is enabled then bind the UDP socket */
    if (logr.proto & REMOTED_NET_PROTOCOL_UDP) {
        /* Using UDP. Fast, unreliable... perfect */
        logr.udp_sock = OS_Bindportudp(logr.port, logr.lip, logr.ipv6);

        if (logr.udp_sock < 0) {
            merror_exit(BIND_ERROR, logr.port, errno, strerror(errno));
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

    HandleSecure();
}
