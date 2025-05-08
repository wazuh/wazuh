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

    int m_queue;
    int tcp_sock;       ///< This socket is used to receive requests over TCP
    int udp_sock;       ///< This socket is used to receive requests over UDP
    int position;       ///< This allows the childs to access its corresponding remoted parameters (unique per child)
    int nocmerged;
    socklen_t peer_size;
    long queue_size;
    bool worker_node;
    int rids_closing_time;
    int connection_overtake_time;
    bool allow_agents_enrollment;
    _Config global;
} remoted;

#endif /* CLOGREMOTE_H */
