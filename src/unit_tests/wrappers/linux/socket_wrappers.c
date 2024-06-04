/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "socket_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include "../common.h"

#define BUFFERSIZE 1024
#define SENDSTRING "Hello World!\n"

int __wrap_socket(__attribute__((unused))int __domain, __attribute__((unused))int __type, __attribute__((unused))int __protocol) {
    return mock();
}

int __wrap_bind(__attribute__((unused))int __fd, __attribute__((unused))__CONST_SOCKADDR_ARG __addr, __attribute__((unused))socklen_t __len) {
    return mock();
}

int __wrap_setsockopt(__attribute__((unused))int __fd, __attribute__((unused))int __level, __attribute__((unused))int __optname, __attribute__((unused))const void *__optval, __attribute__((unused))socklen_t __optlen) {
    return mock();
}

int __wrap_getsockopt(__attribute__((unused))int __fd, __attribute__((unused))int __level, __attribute__((unused))int __optname, __attribute__((unused))void *__restrict __optval, __attribute__((unused))socklen_t *__restrict __optlen) {

    int number = 100000;
    void *len = &number;
    memcpy((int*)__optval, (int*)len, sizeof(int));

    return mock();
}

int __wrap_listen(__attribute__((unused))int __fd, __attribute__((unused))int __n) {
    return mock();
}

int __wrap_connect(__attribute__((unused))int __fd, __attribute__((unused))__CONST_SOCKADDR_ARG __addr, __attribute__((unused))socklen_t __len) {
    return mock();
}

int __wrap_accept(__attribute__((unused))int __fd, struct sockaddr * __addr, __attribute__((unused))socklen_t *__restrict __addr_len) {
    __addr->sa_family = mock();
    return mock();
}

ssize_t __wrap_send(__attribute__((unused))int __fd, __attribute__((unused))const void *__buf, __attribute__((unused))size_t __n, __attribute__((unused))int __flags) {
    return mock();
}

ssize_t __wrap_sendto(__attribute__((unused)) int __fd, __attribute__((unused)) const void *__buf, __attribute__((unused)) size_t __n, __attribute__((unused)) int __flags,
                      __attribute__((unused)) __CONST_SOCKADDR_ARG __addr, __attribute__((unused))socklen_t __len){
    return mock();
}

ssize_t __wrap_recv(__attribute__((unused))int __fd, __attribute__((unused))void *__buf, __attribute__((unused))size_t __n, __attribute__((unused))int __flags) {

    if(__fd == -1) {
        return mock();
    }

    if(__fd == 3 || __fd == 4 || (__fd == 5 && __n == 13)) {
        char text[BUFFERSIZE];
        strcpy(text, SENDSTRING);
        void *buffer = &text;
        memcpy((char*)__buf, (char*)buffer, sizeof(SENDSTRING));
    } else if(__fd == 5 && __n != 13) {
        u_int32_t number = 13;
        void *buffer = &number;
        memcpy((u_int32_t*)__buf, (u_int32_t*)buffer, sizeof(u_int32_t));
    } else if(__fd == 7) {
        char text[BUFFERSIZE];
        strcpy(text, "err --------");
        void *buffertext = &text;
        // Set the payload buffer size to simulate the cluster message format
        size_t payload_size = 9;
        *(uint32_t *)(__buf+4) = wnet_order_big(payload_size);
        memcpy((char*)__buf+8, (char*)buffertext, 12);
    }

    return mock();
}

ssize_t __wrap_recvfrom(__attribute__((unused))int __fd, __attribute__((unused))void *__restrict __buf, __attribute__((unused))size_t __n, __attribute__((unused))int __flags, __attribute__((unused))__SOCKADDR_ARG __addr, __attribute__((unused))socklen_t *__restrict __addr_len) {

    if(__fd != -1) {
        char text[BUFFERSIZE];
        strcpy(text, SENDSTRING);
        void *buffer = &text;
        memcpy((char*)__buf, (char*)buffer, sizeof(SENDSTRING));
    }

    return mock();
}

extern int __real_fcntl(__attribute__((unused))int __fd, __attribute__((unused))int __cmd, __attribute__((unused))unsigned long);
int __wrap_fcntl(int __fd, int __cmd, ...) {

    va_list ap;
    va_start(ap, __cmd);
    unsigned long arg = va_arg(ap, unsigned long);
    va_end(ap);

    if(!test_mode) {
        return __real_fcntl(__fd, __cmd, arg);
    }
    return mock();
}

int __wrap_getaddrinfo(const char *node, __attribute__((unused))const char *service, __attribute__((unused))const struct addrinfo *hints, struct addrinfo **res) {
    struct addrinfo* addr;
    check_expected(node);

    addr = mock_type(struct addrinfo*);
    if (addr != NULL) {
        *res = calloc(1, sizeof(struct addrinfo));
        memcpy(*res, addr, sizeof(struct addrinfo));
    }
    return mock();
}
