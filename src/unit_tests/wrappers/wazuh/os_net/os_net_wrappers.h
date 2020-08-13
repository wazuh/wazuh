/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef OS_NET_WRAPPERS_H
#define OS_NET_WRAPPERS_H

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#ifdef WIN32
typedef uint16_t u_int16_t;
#endif

int __wrap_OS_ConnectUnixDomain(const char *path, int type, int max_msg_size);

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg);

int __wrap_OS_RecvSecureTCP(int sock, char * ret, uint32_t size);

char *__wrap_OS_GetHost(const char *host, unsigned int attempts);

int __wrap_OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6);

int __wrap_OS_ConnectUDP(u_int16_t _port, const char *_ip, int ipv6);

int __wrap_OS_SetRecvTimeout(int socket, long seconds, long useconds);

int __wrap_wnet_select(int sock, int timeout);

#endif
