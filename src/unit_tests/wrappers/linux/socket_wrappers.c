/* Copyright (C) 2015-2021, Wazuh Inc.
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
#include "../common.h"

#define BUFFERSIZE 1024
#define SENDSTRING "Hello World!\n"

int __wrap_socket(int __domain, int __type, int __protocol) {
    return mock();
}

int __wrap_bind(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len) {
    return mock();
}

int __wrap_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen) {
    return mock();
}

int __wrap_getsockopt(int __fd, int __level, int __optname, void *__restrict __optval, socklen_t *__restrict __optlen) {

    int number = 100000;
    void *len = &number;
    memcpy((int*)__optval, (int*)len, sizeof(int));

    return mock();
}

int __wrap_listen(int __fd, int __n) {
    return mock();
}

int __wrap_connect(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len) {
    return mock();
}

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {
    return mock();
}

ssize_t __wrap_send(int __fd, const void *__buf, size_t __n, int __flags) {
    return mock();
}

int __wrap_recv(int __fd, void *__buf, size_t __n, int __flags) {

    if(__fd == -1) {
        return mock();
    }

    if(__fd == 3 || __fd == 4 || (__fd == 5 && __n == 13)) {
        char text[BUFFERSIZE];
        strcpy(text, SENDSTRING);
        void *buffer = &text;
        memcpy((char*)__buf, (char*)buffer, sizeof(SENDSTRING));
    } else if(__fd == 5 && __n != 13) {
        uint32_t number = 13;
        void *buffer = &number;
        memcpy((uint32_t*)__buf, (uint32_t*)buffer, sizeof(uint32_t));
    }
    return mock();
}

int __wrap_recvfrom(int __fd, void *__restrict __buf, size_t __n, int __flags, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {

    if(__fd != -1) {
        char text[BUFFERSIZE];
        strcpy(text, SENDSTRING);
        void *buffer = &text;
        memcpy((char*)__buf, (char*)buffer, sizeof(SENDSTRING));
    }

    return mock();
}

extern int __real_fcntl(int __fd, int __cmd, unsigned long);
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

struct hostent *__wrap_gethostbyname(const char *__name) {
    return mock_type(struct hostent *);
}
