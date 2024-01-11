/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SOCKET_WRAPPERS_H
#define SOCKET_WRAPPERS_H

#include <sys/socket.h>
#include <netdb.h>

int __wrap_socket(__attribute__((unused))int __domain,__attribute__((unused))int __type,__attribute__((unused))int __protocol);

int __wrap_bind(__attribute__((unused))int __fd, __attribute__((unused))__CONST_SOCKADDR_ARG __addr, __attribute__((unused))socklen_t __len);

int __wrap_setsockopt(__attribute__((unused))int __fd, __attribute__((unused))int __level, __attribute__((unused))int __optname, __attribute__((unused))const void *__optval, __attribute__((unused))socklen_t __optlen);

int __wrap_getsockopt(__attribute__((unused))int __fd, __attribute__((unused))int __level, __attribute__((unused))int __optname, __attribute__((unused))void *__restrict __optval, __attribute__((unused))socklen_t *__restrict __optlen);

int __wrap_listen(__attribute__((unused))int __fd, __attribute__((unused))int __n);

int __wrap_connect(__attribute__((unused))int __fd, __attribute__((unused))__CONST_SOCKADDR_ARG __addr, __attribute__((unused))socklen_t __len);

int __wrap_accept(__attribute__((unused))int __fd, struct sockaddr * __addr, __attribute__((unused))socklen_t *__restrict __addr_len);

ssize_t __wrap_send(__attribute__((unused))int __fd, __attribute__((unused))const void *__buf, __attribute__((unused))size_t __n, __attribute__((unused))int __flags);

ssize_t __wrap_sendto(__attribute__((unused))int __fd, __attribute__((unused))const void *__buf, __attribute__((unused))size_t __n, __attribute__((unused)) int __flags,
                      __attribute__((unused)) __CONST_SOCKADDR_ARG __addr, __attribute__((unused))socklen_t __len);

ssize_t __wrap_recv(__attribute__((unused))int __fd, __attribute__((unused))void *__buf, __attribute__((unused))size_t __n, __attribute__((unused))int __flags);

ssize_t __wrap_recvfrom(__attribute__((unused))int __fd, __attribute__((unused))void *__restrict __buf, __attribute__((unused))size_t __n, __attribute__((unused))int __flags, __attribute__((unused))__SOCKADDR_ARG __addr, __attribute__((unused))socklen_t *__restrict __addr_len);

int __wrap_fcntl(__attribute__((unused))int __fd, __attribute__((unused))int __cmd, ...);

int __wrap_getaddrinfo(const char *node, __attribute__((unused))const char *service, __attribute__((unused))const struct addrinfo *hints, struct addrinfo **res);

#endif
