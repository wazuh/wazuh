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
#include "os_auth/auth.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#define WM_STRCAT_NO_SEPARATOR 0

/* Global variables */
keystore keys;
remoted logr;
char* node_name;

/* Forward declaration of the local helper used by load_remoted_tls_contexts(). */
static SSL_CTX *build_syslog_tls_context(const char *cert,
                                         const char *key,
                                         const char *ca_cert,
                                         int min_version,
                                         int block_index);

int load_remoted_tls_contexts(remoted *logr_cfg)
{
    int i;
    int any_failed = 0;

    if (logr_cfg == NULL || logr_cfg->conn == NULL) {
        return 0;
    }

    for (i = 0; logr_cfg->conn[i] != 0; i++) {
        if (logr_cfg->conn[i] != SYSLOG_CONN || !logr_cfg->tls_enabled[i]) {
            continue;
        }

        logr_cfg->ssl_ctx[i] = build_syslog_tls_context(logr_cfg->tls_cert[i],
                                                        logr_cfg->tls_key[i],
                                                        logr_cfg->tls_ca_cert[i],
                                                        logr_cfg->tls_min_version[i],
                                                        i);
        if (logr_cfg->ssl_ctx[i] == NULL) {
            any_failed = 1;
        }
    }

    return any_failed ? -1 : 0;
}

void free_remoted_tls_contexts(remoted *logr_cfg)
{
    int i;

    if (logr_cfg == NULL || logr_cfg->ssl_ctx == NULL || logr_cfg->conn == NULL) {
        return;
    }

    for (i = 0; logr_cfg->conn[i] != 0; i++) {
        if (logr_cfg->ssl_ctx[i] != NULL) {
            SSL_CTX_free(logr_cfg->ssl_ctx[i]);
            logr_cfg->ssl_ctx[i] = NULL;
        }
    }
}

static SSL_CTX *build_syslog_tls_context(const char *cert,
                                         const char *key,
                                         const char *ca_cert,
                                         int min_version,
                                         int block_index)
{
    SSL_CTX *ctx;
    int verify_client = (ca_cert != NULL) ? 1 : 0;

    /* Reuse the same helper that wazuh-authd uses for agent enrollment so every
     * TLS endpoint in the Wazuh manager shares identical cipher and protocol
     * policy. auto_method=0 pins the minimum protocol version to TLS 1.2.
     */
    ctx = os_ssl_keys(1,                /* is_server */
                      NULL,             /* os_dir (paths below are already resolvable) */
                      DEFAULT_CIPHERS,
                      cert,
                      key,
                      ca_cert,          /* NULL disables client cert verification */
                      0);               /* auto_method=0 -> TLS 1.2 floor */
    if (ctx == NULL) {
        merror("Failed to build TLS context for syslog listener block %d. "
               "Check that the certificate and key files exist and are readable: "
               "cert='%s', key='%s'.",
               block_index, cert, key);
        return NULL;
    }

    /* Promote the minimum protocol version to TLS 1.3 if the user asked for it.
     * Older versions of OpenSSL lack SSL_CTX_set_min_proto_version; we require
     * at least OpenSSL 1.1.0 via the existing authd dependency chain so this
     * call is always available on supported platforms.
     */
    if (min_version >= 13) {
        if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            merror("Failed to enforce TLS 1.3 minimum on syslog listener block %d: %s",
                   block_index, err_buf);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    /* When a CA bundle is supplied, enforce mutual TLS: any client that cannot
     * present a certificate signed by one of the trusted CAs is rejected during
     * the handshake. There is no "optional" client cert mode by design — a
     * half-verified client is a footgun.
     */
    if (verify_client) {
        SSL_CTX_set_verify(ctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           NULL);
    }

    return ctx;
}

/* Handle remote connections */
void HandleRemote(int uid)
{
    const int position = logr.position;
    char * str_protocol = NULL;

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

    /* Start up message */
    // If TCP is enabled
    if (logr.proto[position] & REMOTED_NET_PROTOCOL_TCP) {
        wm_strcat(&str_protocol, REMOTED_NET_PROTOCOL_TCP_STR, WM_STRCAT_NO_SEPARATOR);
    }
    // If UDP is enabled
    if (logr.proto[position] & REMOTED_NET_PROTOCOL_UDP) {
        wm_strcat(&str_protocol, REMOTED_NET_PROTOCOL_UDP_STR, (str_protocol == NULL) ? WM_STRCAT_NO_SEPARATOR : ',');
    }

    /* This should never happen */
    if (str_protocol == NULL) {
        merror_exit(REMOTED_NET_PROTOCOL_NOT_SET);
    }

    minfo(STARTUP_MSG " Listening on port %d/%s (%s%s).",
        (int)getpid(),
        logr.port[position],
        str_protocol,
        logr.conn[position] == SECURE_CONN ? "secure" : "syslog",
        (logr.conn[position] == SYSLOG_CONN && logr.tls_enabled[position]) ? " - TLS" : "");
    os_free(str_protocol);

    if (logr.conn[position] == SYSLOG_CONN && logr.tls_enabled[position]) {
        const char *min_ver = (logr.tls_min_version[position] >= 13) ? "1.3" : "1.2";
        const char *ca = logr.tls_ca_cert[position];
        minfo("Syslog TLS ready on port %d (min protocol TLS %s, client cert %s).",
              logr.port[position],
              min_ver,
              ca ? "required (mutual TLS)" : "not required");
    }

    /* If secure connection, deal with it */
    if (logr.conn[position] == SECURE_CONN) {
        HandleSecure();
    }
    else if (logr.proto[position] == REMOTED_NET_PROTOCOL_TCP) {
        HandleSyslogTCP(logr.ssl_ctx[position]);
    }
    else { /* If not, deal with syslog */
        HandleSyslog();
    }
}
