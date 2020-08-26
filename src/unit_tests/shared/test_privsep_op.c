/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <pwd.h>
#include <grp.h>

#include "../headers/privsep_op.h"

int __wrap_sysconf(int name) {
    return mock();
}

int __wrap_getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
    *result = NULL;

    if (buflen < 1024) {
        return ERANGE;
    }

    if (strcmp(name, "ossec") == 0) {
        pwd->pw_uid = 1000;
        *result = pwd;
    }

    return 0;
}

int __wrap_getgrnam_r(const char *name, struct group *grp, char *buf, size_t buflen, struct group **result) {
    *result = NULL;

    if (buflen < 1024) {
        return ERANGE;
    }

    if (strcmp(name, "ossec") == 0) {
        grp->gr_gid = 1000;
        *result = grp;
    }

    return 0;
}

static void test_GetUser_success(void ** state) {
    will_return(__wrap_sysconf, 1024);
    uid_t uid = Privsep_GetUser("ossec");
    assert_int_equal(uid, 1000);
}

static void test_GetUser_success_extend(void ** state) {
    will_return(__wrap_sysconf, 512);
    uid_t uid = Privsep_GetUser("ossec");
    assert_int_equal(uid, 1000);
}

static void test_GetUser_failure(void ** state) {
    will_return(__wrap_sysconf, 1024);
    uid_t uid = Privsep_GetUser("other");
    assert_int_equal(uid, (uid_t)-1);
}

static void test_GetGroup_success(void ** state) {
    will_return(__wrap_sysconf, 1024);
    uid_t uid = Privsep_GetGroup("ossec");
    assert_int_equal(uid, 1000);
}

static void test_GetGroup_success_extend(void ** state) {
    will_return(__wrap_sysconf, 512);
    uid_t uid = Privsep_GetGroup("ossec");
    assert_int_equal(uid, 1000);
}

static void test_GetGroup_failure(void ** state) {
    will_return(__wrap_sysconf, 1024);
    uid_t uid = Privsep_GetGroup("other");
    assert_int_equal(uid, (uid_t)-1);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_GetUser_success),
        cmocka_unit_test(test_GetUser_success_extend),
        cmocka_unit_test(test_GetUser_failure),
        cmocka_unit_test(test_GetGroup_success),
        cmocka_unit_test(test_GetGroup_success_extend),
        cmocka_unit_test(test_GetGroup_failure),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
