/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "os_net_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_OS_ConnectUnixDomain(const char *path, int type, int max_msg_size) {
    check_expected(path);
    check_expected(type);
    check_expected(max_msg_size);

    return mock();
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    check_expected(sock);
    check_expected(size);
    check_expected(msg);

    return mock();
}

int __wrap_OS_RecvSecureTCP(int sock, char * ret, uint32_t size) {
    check_expected(sock);
    check_expected(size);

    strncpy(ret, mock_type(char*), size);

    return mock();
}

char *__wrap_OS_GetHost(const char *host, __attribute__((unused)) unsigned int attempts) {
    check_expected(host);
    return mock_ptr_type(char *);
}

int __wrap_OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6) {
    check_expected(_port);
    check_expected(_ip);
    check_expected(ipv6);
    return mock_type(int);
}

int __wrap_OS_ConnectUDP(__attribute__((unused)) u_int16_t _port,
                         __attribute__((unused)) const char *_ip,
                         __attribute__((unused)) int ipv6) {
    return mock();
}

int __wrap_OS_SetRecvTimeout(__attribute__((unused)) int socket,
                             __attribute__((unused)) long seconds,
                             __attribute__((unused)) long useconds) {
    return mock();
}


int __wrap_wnet_select(__attribute__((unused)) int sock,
                       __attribute__((unused)) int timeout) {
    return (int)mock();
}
