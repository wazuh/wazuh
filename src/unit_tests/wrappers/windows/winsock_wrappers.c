/* Copyright (C) Wazuh Inc.
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
#include <stdio.h>
#include <string.h>

#include "winsock_wrappers.h"
#include <ws2tcpip.h>

struct sockaddr_storage wrap_connect_addr;

int wrap_gethostname(char *name, int len) {
    snprintf(name, len, "%s", mock_type(char *));
    return mock_type(int);
}

SOCKET wrap_socket(__attribute__((unused)) int af, __attribute__((unused)) int type, __attribute__((unused)) int protocol) {
    return (SOCKET)mock();
}

int wrap_connect(__attribute__((unused)) SOCKET s, const struct sockaddr * name, int namelen) {
    memset(&wrap_connect_addr, 0, sizeof(wrap_connect_addr));

    if (name && namelen > 0 && (size_t)namelen <= sizeof(wrap_connect_addr)) {
        memcpy(&wrap_connect_addr, name, namelen);
    }

    return mock();
}

int wrap_getsockname(__attribute__((unused)) SOCKET s, struct sockaddr * name, int * namelen) {
    const struct sockaddr * address = mock_ptr_type(const struct sockaddr *);

    if (address) {
        const int size = AF_INET6 == address->sa_family ? (int)sizeof(struct sockaddr_in6) : (int)sizeof(struct sockaddr_in);
        memcpy(name, address, size < *namelen ? size : *namelen);
        *namelen = size;
    }

    return mock();
}

int wrap_closesocket(__attribute__((unused)) SOCKET s) {
    return 0;
}
