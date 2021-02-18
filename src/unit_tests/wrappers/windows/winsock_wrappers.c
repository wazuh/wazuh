/* Copyright (C) 2015-2020, Wazuh Inc.
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
#include "winsock_wrappers.h"

int wrap_gethostname(char *name, int len) {
    snprintf(name, len, "%s", mock_type(char *));
    return mock_type(int);
}

SOCKET wrap_socket(int af, int type, int protocol) {
    check_expected(af);
    check_expected(type);
    check_expected(protocol);

    return (int) mock();
}

int wrap_setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen){

    check_expected(s);
    check_expected(level);
    check_expected(optname);
    check_expected(optval);
    check_expected(optlen);

    return (int) mock();
}

int wrap_bind(SOCKET s, const int *addr, int namelen){

    check_expected(s);
    check_expected(addr);
    check_expected(namelen);

    return (int) mock();

}

WSAAPI wrap_listen(SOCKET s, int backlog){

    check_expected(s);
    check_expected(backlog);

    return (int) mock();
}
