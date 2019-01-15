/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

/* Global variables */
keystore keys;
remoted logr;
char* node_name;
rlim_t nofile;

/* Handle remote connections */
void HandleRemote(int uid)
{
    int position = logr.position;
    int recv_timeout;    //timeout in seconds waiting for a client reply
    int send_timeout;

    recv_timeout = getDefine_Int("remoted", "recv_timeout", 1, 60);
    send_timeout = getDefine_Int("remoted", "send_timeout", 1, 60);

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
        nofile = getDefine_Int("remoted", "rlimit_nofile", 1024, 1048576);
        struct rlimit rlimit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
            merror("Could not set resource limit for file descriptors to %d: %s (%d)", (int)nofile, strerror(errno), errno);
        }
    }

    /* Bind TCP */
    if (logr.proto[position] == TCP_PROTO) {
        if ((logr.sock = OS_Bindporttcp(logr.port[position], logr.lip[position], logr.ipv6[position])) < 0) {
            merror_exit(BIND_ERROR, logr.port[position], errno, strerror(errno));
        } else if (logr.conn[position] == SECURE_CONN) {
            if (OS_SetRecvTimeout(logr.sock, recv_timeout, 0) < 0){
                merror("OS_SetRecvTimeout failed with error '%s'", strerror(errno));
            }
            if (OS_SetSendTimeout(logr.sock, send_timeout) < 0){
                merror("OS_SetSendTimeout failed with error '%s'", strerror(errno));
            }
        }
    } else {
        /* Using UDP. Fast, unreliable... perfect */
        if ((logr.sock =
                    OS_Bindportudp(logr.port[position], logr.lip[position], logr.ipv6[position])) < 0) {
            merror_exit(BIND_ERROR, logr.port[position], errno, strerror(errno));
        }
    }

    /* Revoke privileges */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, REMUSER, errno, strerror(errno));
    }

    /* Create PID */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* If secure connection, deal with it */
    if (logr.conn[position] == SECURE_CONN) {
        HandleSecure();
    }

    else if (logr.proto[position] == TCP_PROTO) {
        HandleSyslogTCP();
    }

    /* If not, deal with syslog */
    else {
        HandleSyslog();
    }
}
