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
#include "remoted_module.h" // REMOTED_MODULE_PEM_MAX_SIZE

/* Global variables */
keystore keys;
remoted logr;
char* node_name;
char* cluster_name;

// Chroot-relative: evaluated once Privsep_Chroot() (in main.c) has already run, so these
// resolve to /var/wazuh-manager/etc/https-manager.{cert,key} from the host's perspective.
#define HTTPS_MANAGER_CERT_PATH "etc/https-manager.cert"
#define HTTPS_MANAGER_KEY_PATH "etc/https-manager.key"

/* Handle remote connections */
void HandleRemote(int uid)
{
    // Set resource limit for file descriptors

    {
        struct rlimit rlimit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
            merror("Could not set resource limit for file descriptors to %d: %s (%d)", (int)nofile, strerror(errno), errno);
        }
    }

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


    /* Read the HTTPS agent server's certificate/key while still root: this lets the files
     * stay root:root (like sslmanager.cert/.key) since remoted never opens them again as
     * an unprivileged user -- only the raw PEM bytes, already in memory, cross the
     * privilege drop below. NULL (missing/unreadable/oversized) is handled downstream:
     * the module fails to start and logs why. */
    char *https_cert_pem = w_get_file_content(HTTPS_MANAGER_CERT_PATH, REMOTED_MODULE_PEM_MAX_SIZE - 1);
    char *https_key_pem = w_get_file_content(HTTPS_MANAGER_KEY_PATH, REMOTED_MODULE_PEM_MAX_SIZE - 1);

    /* Revoke privileges */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, USER, errno, strerror(errno));
    }

    /* Create PID */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    HandleSecure(https_cert_pem, https_key_pem);
}
