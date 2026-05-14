/* Copyright (C) 2015, Wazuh Inc.
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
#include "shared.h"

char *__wrap_decode_win_permissions(char *raw_perm) {
    check_expected(raw_perm);
    return mock_type(char*);
}

void __wrap_decode_win_acl_json(cJSON *perms) {
    check_expected(perms);
    return;
}

int __wrap_delete_target_file(const char *path) {
    check_expected(path);
    return mock();
}

char *__wrap_get_group(int gid) {
    check_expected(gid);
    return mock_type(char*);
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

char *__wrap_get_file_user(const char *path, char **sid) {
    check_expected(path);
    *sid = mock_type(char *);

    return mock_type(char *);
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

int __wrap_w_get_file_permissions(const char *file_path, cJSON **output_acl) {
    check_expected(file_path);

    assert_non_null(output_acl);

    *output_acl = mock_type(cJSON *);

    return mock();
}

int __wrap_remove_empty_folders(const char *folder) {
    check_expected(folder);
    return mock();
}

void expect_get_group(int gid, char *ret) {
    expect_value(__wrap_get_group, gid, gid);
    will_return(__wrap_get_group, ret);
}

#ifdef WIN32
void expect_get_user(const char *path, char **sid, char *user) {
    expect_string(__wrap_get_user, path, path);
    will_return(__wrap_get_user, sid);
    will_return(__wrap_get_user, user);
}

void expect_get_file_user(const char *path, char *sid, char *user) {
    expect_string(__wrap_get_file_user, path, path);
    will_return(__wrap_get_file_user, sid);
    will_return(__wrap_get_file_user, user);
}

void expect_w_get_file_permissions(const char *file_path, cJSON *perms, int ret) {
    expect_string(__wrap_w_get_file_permissions, file_path, file_path);
    will_return(__wrap_w_get_file_permissions, perms);
    will_return(__wrap_w_get_file_permissions, ret);
}

DWORD __wrap_get_registry_permissions(__attribute__((unused)) HKEY hndl, cJSON **output_acl) {
    assert_non_null(output_acl);

    *output_acl = mock_type(cJSON *);

    return mock();
}

void expect_get_registry_permissions(cJSON *permissions, DWORD retval) {
    will_return(__wrap_get_registry_permissions, permissions);
    will_return(__wrap_get_registry_permissions, retval);
}

#else

void expect_get_user(int uid, char *ret) {
    expect_value(__wrap_get_user, uid, uid);
    will_return(__wrap_get_user, ret);
}
#endif
