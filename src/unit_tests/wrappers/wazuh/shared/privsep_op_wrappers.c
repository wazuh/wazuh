/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "privsep_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>

#ifndef WIN32
struct group *__wrap_w_getgrgid(gid_t gid, struct group *grp, char *buf, int buflen) {
    struct group *mock_grp;
    char *mock_buf;
    check_expected(gid);

    mock_grp = mock_type(struct group *);

    if (mock_grp && grp) {
        memcpy(grp, mock_grp, sizeof(char **) + 2 * sizeof(char *) + sizeof(gid_t));
    }

    mock_buf = mock_type(char *);
    if (mock_buf && buf) {
        strncpy(buf, mock_buf, buflen);
    }

    if (mock()) {
        return grp;
    } else {
        return NULL;
    }
}
#endif

int __wrap_Privsep_GetUser(const char *name) {
    check_expected(name);

    return mock();
}

int __wrap_Privsep_GetGroup(const char *name) {
    check_expected(name);

    return mock();
}
