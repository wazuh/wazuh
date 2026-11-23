/* Copyright (C) Wazuh Inc.
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

#define gethostname wrap_gethostname

int wrap_gethostname(char *name, int len);

/* Destination of the last wrap_connect call. */
extern struct sockaddr_storage wrap_connect_addr;

SOCKET wrap_socket(int af, int type, int protocol);

int wrap_connect(SOCKET s, const struct sockaddr * name, int namelen);

/* Copies the sockaddr given with will_return (NULL leaves it untouched), then returns the next mock value. */
int wrap_getsockname(SOCKET s, struct sockaddr * name, int * namelen);

int wrap_closesocket(SOCKET s);

#define socket wrap_socket
#define connect wrap_connect
#define getsockname wrap_getsockname
#define closesocket wrap_closesocket

#endif
