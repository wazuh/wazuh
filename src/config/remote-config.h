/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __CLOGREMOTE_H
#define __CLOGREMOTE_H

#define SYSLOG_CONN 1
#define SECURE_CONN 2
#define UDP_PROTO   6
#define TCP_PROTO   17

#include "shared.h"

/* socklen_t header */
typedef struct _remoted {
    int *proto;
    int *port;
    int *conn;
    int *ipv6;

    char **lip;
    os_ip **allowips;
    os_ip **denyips;

    int m_queue;
    int sock;
    socklen_t peer_size;
} remoted;

#endif /* __CLOGREMOTE_H */

