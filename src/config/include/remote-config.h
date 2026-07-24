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

/* <remote><https><verification_mode> values. Kept in sync by hand with the C-ABI
 * mirror in src/remoted/remoted_module/include/remoted_module.h, since the value
 * crosses to the C++ module as a plain int. */
#define REMOTED_HTTPS_VERIFY_NONE        0
#define REMOTED_HTTPS_VERIFY_CERTIFICATE 1
#define REMOTED_HTTPS_VERIFY_FULL        2
#define REMOTED_HTTPS_VERIFY_DEFAULT     REMOTED_HTTPS_VERIFY_NONE

#include "shared.h"
#include "global-config.h"

/* <remote><https> configuration. Every field defaults to an "unset" sentinel
 * (0/NULL) so an absent <https> block leaves the module's own defaults/env-var
 * fallback untouched. */
typedef struct _remoted_https_config {
    int port;                  ///< 0 -> module default/env
    char *bind_addr;           ///< NULL -> module default/env
    char *certificate;         ///< NULL -> module default/env
    char *key;                 ///< NULL -> module default/env
    char *ca;                  ///< NULL -> client-certificate verification disabled
    char *ciphers;             ///< NULL -> library default cipher list
    int verification_mode;     ///< REMOTED_HTTPS_VERIFY_*
    long max_body_size;        ///< bytes; 0 -> module default/env
} remoted_https_config;

/* socklen_t header */
typedef struct _remoted {
    int proto;
    int port;
    int ipv6;

    char *lip;

    bool allow_higher_versions;

    int tcp_sock;       ///< This socket is used to receive requests over TCP
    int udp_sock;       ///< This socket is used to receive requests over UDP
    socklen_t peer_size;
    long queue_size;
    bool worker_node;
    int rids_closing_time;
    int connection_overtake_time;
    remoted_https_config https;
    _Config global;
} remoted;

#endif /* CLOGREMOTE_H */
