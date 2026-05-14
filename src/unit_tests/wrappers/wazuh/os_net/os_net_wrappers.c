/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../headers/shared.h"
#include "os_net_wrappers.h"

int __wrap_OS_BindUnixDomainWithPerms(const char *path, int type, int max_msg_size, uid_t uid, gid_t gid, mode_t perm) {
    check_expected(path);
    check_expected(type);
    check_expected(max_msg_size);
    check_expected(uid);
    check_expected(gid);
    check_expected(perm);

    return mock();
}

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size) {
    check_expected(path);
    check_expected(type);
    check_expected(max_msg_size);

    return mock();
}

int __wrap_OS_ConnectUnixDomain(const char *path, int type, int max_msg_size) {
    check_expected(path);
    check_expected(type);
    check_expected(max_msg_size);

    return mock();
}

int __wrap_OS_SendUDPbySize(int sock, int size, const char *msg) {
    check_expected(sock);
    check_expected(size);
    check_expected(msg);

    return mock();
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    check_expected(sock);
    check_expected(size);
    check_expected(msg);

    return mock();
}

int __wrap_OS_SendUnix(int socket, const char *msg, int size) {
    check_expected(socket);
    check_expected(msg);
    check_expected(size);

    return mock();
}

void expect_OS_SendUnix_call(int socket, const char *msg, int size, int ret) {
    expect_value(__wrap_OS_SendUnix, socket, socket);
    expect_string(__wrap_OS_SendUnix, msg, msg);
    expect_value(__wrap_OS_SendUnix, size, size);
    will_return(__wrap_OS_SendUnix, ret);
}

int __wrap_OS_RecvSecureTCP(int sock, char * ret, uint32_t size) {
    check_expected(sock);
    check_expected(size);

    strncpy(ret, mock_type(char*), size);

    return mock();
}

int __wrap_OS_RecvUnix(int socket, int sizet, char *ret) {
    check_expected(socket);
    check_expected(sizet);

    strncpy(ret, mock_type(char*), sizet);

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

int __wrap_OS_SetSendTimeout(__attribute__((unused)) int socket,
                             __attribute__((unused)) int seconds) {
    return mock();
}


int __wrap_wnet_select(__attribute__((unused)) int sock,
                       __attribute__((unused)) int timeout) {
    return (int)mock();
}

uint32_t __wrap_wnet_order(uint32_t value) {
    check_expected(value);
    return mock();
}

int __wrap_external_socket_connect(__attribute__((unused)) char *socket_path,
                                   __attribute__((unused)) int response_timeout) {

    return (int)mock();
}

int __wrap_get_ipv4_numeric(__attribute__((unused)) const char *address,
                            __attribute__((unused)) struct in_addr *addr) {
    int ret = mock();
    if(ret > 0) {
        ret = 0;
        addr->s_addr = mock();
    }

    return ret;
}

int __wrap_get_ipv6_numeric(__attribute__((unused)) const char *address,
                            __attribute__((unused)) struct in6_addr *addr6) {
    int ret = mock();
    if(ret > 0) {
        ret = 0;
        int value = mock();
        for(unsigned int a = 0; a < 16; a++) {
#ifndef WIN32
            addr6->s6_addr[a] = value;
#else
            addr6->u.Byte[a] = value;
#endif
        }
    }

    return ret;
}

int __wrap_get_ipv4_string(__attribute__((unused)) struct in_addr addr,
                            char *address, size_t address_size) {
    int ret = mock();
    if (ret == OS_INVALID)
    {
        check_expected(address);
    }
    else
    {
        strncpy(address, mock_ptr_type(char *), address_size);
    }
    check_expected(address_size);
    return ret;
}

int __wrap_get_ipv6_string(__attribute__((unused)) struct in6_addr addr6,
                            char *address, size_t address_size) {
    int ret = mock();
    if (ret == OS_INVALID)
    {
        check_expected(address);
    }
    else
    {
        strncpy(address, mock_ptr_type(char *), address_size);
    }
    check_expected(address_size);
    return ret;
}

int __wrap_OS_SendSecureTCPCluster(int sock, const void *command, const void *payload, size_t length) {
    check_expected(sock);
    check_expected(command);
    check_expected(payload);
    check_expected(length);

    return mock();
}

int __wrap_OS_RecvSecureClusterTCP(int sock, char *ret, size_t length) {
    check_expected(sock);
    check_expected(length);

    strncpy(ret, mock_type(char*), length);

    return mock();
}

int __wrap_OS_CloseSocket(int sock) {
    check_expected(sock);
    return mock();
}
