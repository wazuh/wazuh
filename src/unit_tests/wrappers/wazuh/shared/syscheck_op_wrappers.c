/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "syscheck_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

char *__wrap_decode_win_permissions(char *raw_perm) {
    check_expected(raw_perm);
    return mock_type(char*);
}

int __wrap_delete_target_file(const char *path) {
    check_expected(path);
    return mock();
}

const char *__wrap_get_group(int gid) {
    check_expected(gid);
    return mock_type(const char*);
}

#ifndef WIN32
char *__wrap_get_user(int uid) {
    check_expected(uid);

    return mock_type(char*);
}
#else
char *__wrap_get_user(const char *path, char **sid) {
    check_expected(path);
    *sid = mock_type(char*);

    return mock_type(char*);
}
#endif

unsigned int __wrap_w_directory_exists(const char *path) {
    check_expected(path);
    return mock();
}

unsigned int __wrap_w_get_file_attrs(const char *file_path) {
    check_expected(file_path);
    return mock();
}

int __wrap_w_get_file_permissions(const char *file_path, char *permissions, int perm_size) {
    check_expected(file_path);
    snprintf(permissions, perm_size, "%s", mock_type(char*));
    return mock();
}
