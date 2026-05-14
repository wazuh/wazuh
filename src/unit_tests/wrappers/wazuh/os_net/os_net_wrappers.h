/* Copyright (C) 2015, Wazuh Inc.
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
#include "../../headers/shared.h"

#ifdef WIN32
typedef uint16_t u_int16_t;
#endif

int __wrap_OS_BindUnixDomainWithPerms(const char *path, int type, int max_msg_size, uid_t uid, gid_t gid, mode_t perm);

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size);

int __wrap_OS_ConnectUnixDomain(const char *path, int type, int max_msg_size);

int __wrap_OS_SendUDPbySize(int sock, int size, const char *msg);

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg);

int __wrap_OS_SendUnix(int socket, const char *msg, int size);

void expect_OS_SendUnix_call(int socket, const char *msg, int size, int ret);

int __wrap_OS_RecvSecureTCP(int sock, char * ret, uint32_t size);

int __wrap_OS_RecvUnix(int socket, int sizet, char *ret);

char *__wrap_OS_GetHost(const char *host, unsigned int attempts);

int __wrap_OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6);

int __wrap_OS_ConnectUDP(u_int16_t _port, const char *_ip, int ipv6);

int __wrap_OS_SetRecvTimeout(int socket, long seconds, long useconds);

int __wrap_OS_SetSendTimeout(int socket, int seconds);

int __wrap_wnet_select(int sock, int timeout);

uint32_t __wrap_wnet_order(uint32_t value);

int __wrap_external_socket_connect(char *socket_path, int response_timeout);

int __wrap_get_ipv4_numeric(const char *address, struct in_addr *addr);

int __wrap_get_ipv6_numeric(const char *address, struct in6_addr *addr6);

int __wrap_get_ipv4_string(struct in_addr addr, char *address, size_t address_size);

int __wrap_get_ipv6_string(struct in6_addr addr6, char *address, size_t address_size);

int __wrap_OS_SendSecureTCPCluster(int sock, const void *command, const void *payload, size_t length);

int __wrap_OS_RecvSecureClusterTCP(int sock, char *ret, size_t length);

int __wrap_OS_CloseSocket(int sock);

#endif
