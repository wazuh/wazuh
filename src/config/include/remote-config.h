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

#define REMOTED_LEGACY_LOCAL_IP_DEFAULT "127.0.0.1"

#define REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT false  ///< Default allow_higher_versions value (false)

/* <remote><https><verification_mode> values. Kept in sync by hand with the C-ABI
 * mirror in src/remoted/remoted_module/include/remoted_module.h (REMOTED_MODULE_HTTPS_VERIFY_*),
 * since the value crosses to the C++ module as a plain int. secure.c statically
 * asserts the two stay numerically aligned (see its REMOTED_HTTPS_VERIFY_* checks).
 *
 * REMOTED_HTTPS_VERIFY_UNSET is distinct from REMOTED_HTTPS_VERIFY_NONE: UNSET means
 * "the operator did not configure this option," so the module falls back to its
 * environment-variable/default resolution; NONE means "the operator explicitly
 * disabled client-certificate verification," which must win over any environment
 * override. Both RemotedConfig() (pre-parse initialization) and the C-ABI struct must
 * use UNSET as their initial value, never NONE/0, or the two become indistinguishable. */
#define REMOTED_HTTPS_VERIFY_UNSET       (-1)
#define REMOTED_HTTPS_VERIFY_NONE        0
#define REMOTED_HTTPS_VERIFY_CERTIFICATE 1
#define REMOTED_HTTPS_VERIFY_FULL        2
#define REMOTED_HTTPS_VERIFY_DEFAULT     REMOTED_HTTPS_VERIFY_NONE

/* <remote><https><dual_stack> values. Only meaningful when bind_addr resolves to
 * IPv6 (e.g. "::"): controls the IPV6_V6ONLY socket option, i.e. whether the same
 * socket also accepts IPv4 clients. Kept in sync by hand with the C-ABI mirror in
 * src/remoted/remoted_module/include/remoted_module.h. */
#define REMOTED_HTTPS_DUAL_STACK_UNSET 0 ///< Not configured -> module defaults to IPv6-only (RestinioHttpServer.cpp).
                                          ///< Kept distinct from _NO so the "dual_stack only applies to an IPv6
                                          ///< bind_addr" warning doesn't fire when the operator never touched it.
#define REMOTED_HTTPS_DUAL_STACK_YES   1 ///< Force dual-stack on (IPV6_V6ONLY=0): also accept IPv4
#define REMOTED_HTTPS_DUAL_STACK_NO    2 ///< Force IPv6-only (IPV6_V6ONLY=1): reject IPv4 on this socket

/* Maximum lengths for <remote><https> string options. Kept in sync by hand with the
 * fixed-size C-ABI buffers in src/remoted/remoted_module/include/remoted_module.h
 * (bind_address[256], certificate_path[512], private_key_path[512], ca_path[512],
 * ciphers[256]) that secure.c's HandleSecure() copies these values into via snprintf.
 * Each limit is one less than its buffer size, to leave room for the NUL terminator.
 * A value that doesn't fit must be rejected here instead of silently truncated: past
 * this point it is a plain char* with no length limit until it reaches that buffer. */
#define REMOTED_HTTPS_BIND_ADDR_MAX_LEN   255
#define REMOTED_HTTPS_CERTIFICATE_MAX_LEN 511
#define REMOTED_HTTPS_KEY_MAX_LEN         511
#define REMOTED_HTTPS_CA_MAX_LEN          511
#define REMOTED_HTTPS_CIPHERS_MAX_LEN     255

#include "shared.h"
#include "global-config.h"

/* <remote><https> configuration. Every field defaults to an "unset" sentinel
 * (0/NULL) so an absent <https> block leaves the module's own defaults untouched. */
typedef struct _remoted_https_config {
    int port;                  ///< 0 -> module default
    char *bind_addr;           ///< NULL -> module default
    char *certificate;         ///< NULL -> module default
    char *key;                 ///< NULL -> module default
    char *ca;                  ///< NULL -> client-certificate verification disabled
    char *ciphers;             ///< NULL -> library default cipher list
    int verification_mode;     ///< REMOTED_HTTPS_VERIFY_*
    long max_body_size;        ///< bytes; 0 -> module default
    int dual_stack;            ///< REMOTED_HTTPS_DUAL_STACK_*; only applies to an IPv6 bind_addr
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
