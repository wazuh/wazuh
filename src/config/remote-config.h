/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CLOGREMOTE_H
#define CLOGREMOTE_H

#define SYSLOG_CONN 1
#define SECURE_CONN 2

#define REMOTED_NET_PROTOCOL_TCP     (0x1 << 0)               ///< Config for TCP protocol enabled
#define REMOTED_NET_PROTOCOL_UDP     (0x1 << 1)               ///< Config for UDP protocol enabled
#define REMOTED_NET_PROTOCOL_DEFAULT REMOTED_NET_PROTOCOL_TCP ///< Default remoted protocol

#define REMOTED_NET_PROTOCOL_TCP_STR "TCP" ///< String to represent the TCP protocol
#define REMOTED_NET_PROTOCOL_UDP_STR "UDP" ///< String to represent the UDP protocol
#define REMOTED_NET_PROTOCOL_DEFAULT_STR  (REMOTED_NET_PROTOCOL_DEFAULT == REMOTED_NET_PROTOCOL_TCP \
                ? REMOTED_NET_PROTOCOL_TCP_STR : REMOTED_NET_PROTOCOL_UDP_STR) ///< String to represent default protocol

#define REMOTED_NET_PROTOCOL_TCP_UDP (REMOTED_NET_PROTOCOL_TCP | REMOTED_NET_PROTOCOL_UDP) ///< Either UDP or TCP
#define REMOTED_RIDS_CLOSING_TIME_DEFAULT   (5 * 60) ///< Default rids_closing_time value (5 minutes)

#define REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT false  ///< Default allow_higher_versions value (false)

#include "shared.h"
#include "global-config.h"

#include <openssl/ssl.h>

/* socklen_t header */
typedef struct _remoted {
    int *proto;
    int *port;
    int *conn;
    int *ipv6;

    char **lip;
    os_ip **allowips;
    os_ip **denyips;

    bool allow_higher_versions;

    /* Per-listener-block TLS configuration for syslog input.
     * Arrays are parallel to port[]/conn[]/proto[] and indexed by listener block.
     * Populated by Read_Remote() at config parse time.
     */
    int *tls_enabled;           ///< 1 if TLS is enabled for this block, 0 otherwise
    char **tls_cert;            ///< Path to server certificate (PEM), required when tls_enabled
    char **tls_key;             ///< Path to server private key (PEM), required when tls_enabled
    char **tls_ca_cert;         ///< Path to CA bundle for client cert verification (PEM), optional; presence enables mutual TLS
    int *tls_min_version;       ///< Minimum TLS protocol: 12 for TLS 1.2 (default), 13 for TLS 1.3
    SSL_CTX **ssl_ctx;          ///< OpenSSL context built at startup, NULL when tls_enabled is 0

    int m_queue;
    int tcp_sock;       ///< This socket is used to receive requests over TCP
    int udp_sock;       ///< This socket is used to receive requests over UDP
    int position;       ///< This allows the childs to access its corresponding remoted parameters (unique per child)
    socklen_t peer_size;
    long queue_size;
    bool worker_node;
    int rids_closing_time;
    int connection_overtake_time;
    _Config global;
} remoted;

#endif /* CLOGREMOTE_H */
