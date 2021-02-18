/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WINSOCK_WRAPPERS_H
#define WINSOCK_WRAPPERS_H

#include <winsock2.h>
#include <winsock.h>

#define gethostname wrap_gethostname
#define socket wrap_socket
#define setsockopt wrap_setsockopt
#define bind wrap_bind
#define listen wrap_listen

int wrap_gethostname(char *name, int len);

SOCKET wrap_socket(int af, int type, int protocol);
int wrap_setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen);
int wrap_bind(SOCKET s, const int *addr, int namelen);
WSAAPI wrap_listen(SOCKET s, int backlog);

#endif
