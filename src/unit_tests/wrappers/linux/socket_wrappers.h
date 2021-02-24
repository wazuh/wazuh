/* Copyright (C) 2015-2021, Wazuh Inc.
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

int __wrap_socket(int __domain, int __type, int __protocol);

int __wrap_bind(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);

int __wrap_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen);

int __wrap_getsockopt(int __fd, int __level, int __optname, void *__restrict __optval, socklen_t *__restrict __optlen);

int __wrap_listen(int __fd, int __n);

int __wrap_connect(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len);

ssize_t __wrap_send(int __fd, const void *__buf, size_t __n, int __flags);

int __wrap_recv(int __fd, void *__buf, size_t __n, int __flags);

int __wrap_recvfrom(int __fd, void *__restrict __buf, size_t __n, int __flags, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len);

int __wrap_fcntl(int __fd, int __cmd, ...);

struct hostent *__wrap_gethostbyname(const char *__name);

#endif
