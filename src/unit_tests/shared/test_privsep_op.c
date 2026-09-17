/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "../wrappers/posix/grp_wrappers.h"
#include "../wrappers/posix/pwd_wrappers.h"
#include "../wrappers/posix/resource_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "privsep_op.h"

static void test_GetUser_success(void ** state) {
    will_return(__wrap_sysconf, 1024);
    uid_t uid = Privsep_GetUser("wazuh");
    assert_int_equal(uid, 1000);
}

static void test_GetUser_success_extend(void ** state) {
    will_return(__wrap_sysconf, 512);
    uid_t uid = Privsep_GetUser("wazuh");
    assert_int_equal(uid, 1000);
}

static void test_GetUser_failure(void ** state) {
    will_return(__wrap_sysconf, 1024);
    uid_t uid = Privsep_GetUser("other");
    assert_int_equal(uid, (uid_t)-1);
}

static void test_GetGroup_success(void ** state) {
    will_return(__wrap_sysconf, 1024);
    uid_t uid = Privsep_GetGroup("wazuh");
    assert_int_equal(uid, 1000);
}

static void test_GetGroup_success_extend(void ** state) {
    will_return(__wrap_sysconf, 512);
    uid_t uid = Privsep_GetGroup("wazuh");
    assert_int_equal(uid, 1000);
}

static void test_GetGroup_failure(void ** state) {
    will_return(__wrap_sysconf, 1024);
    uid_t uid = Privsep_GetGroup("other");
    assert_int_equal(uid, (uid_t)-1);
}

static void expect_getrlimit(const struct rlimit *inherited, int ret) {
    expect_value(__wrap_getrlimit, resource, RLIMIT_NOFILE);
    will_return(__wrap_getrlimit, inherited);
    will_return(__wrap_getrlimit, ret);
}

static void expect_setrlimit(rlim_t soft, rlim_t hard, int ret) {
    expect_value(__wrap_setrlimit, resource, RLIMIT_NOFILE);
    expect_value(__wrap_setrlimit, rlim_cur, soft);
    expect_value(__wrap_setrlimit, rlim_max, hard);
    will_return(__wrap_setrlimit, ret);
}

static void test_raise_nofile_hard_allows_target(void ** state) {
    static const struct rlimit inherited = { 1024, 524288 };
    expect_getrlimit(&inherited, 0);
    expect_setrlimit(65536, 524288, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "File descriptor limit raised to 65536");
    assert_int_equal(w_raise_nofile_limit(65536, "remoted.rlimit_nofile"), 65536);
}

static void test_raise_nofile_hard_unlimited(void ** state) {
    static const struct rlimit inherited = { 1024, RLIM_INFINITY };
    expect_getrlimit(&inherited, 0);
    expect_setrlimit(65536, RLIM_INFINITY, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "File descriptor limit raised to 65536");
    assert_int_equal(w_raise_nofile_limit(65536, "remoted.rlimit_nofile"), 65536);
}

static void test_raise_nofile_hard_below_target(void ** state) {
    static const struct rlimit inherited = { 8192, 8192 };
    expect_getrlimit(&inherited, 0);
    expect_string(__wrap__mwarn, formatted_msg, "File descriptor limit is 8192, below the 65536 requested by "
                  "'remoted.rlimit_nofile'. Raise the limit the process is started with (LimitNOFILE, ulimit -n, "
                  "container ulimits) to go higher.");
    assert_int_equal(w_raise_nofile_limit(65536, "remoted.rlimit_nofile"), 8192);
}

static void test_raise_nofile_hard_below_target_soft_lower(void ** state) {
    static const struct rlimit inherited = { 1024, 8192 };
    expect_getrlimit(&inherited, 0);
    expect_setrlimit(8192, 8192, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "File descriptor limit raised to 8192");
    expect_string(__wrap__mwarn, formatted_msg, "File descriptor limit is 8192, below the 65536 requested by "
                  "'wazuh_db.rlimit_nofile'. Raise the limit the process is started with (LimitNOFILE, ulimit -n, "
                  "container ulimits) to go higher.");
    assert_int_equal(w_raise_nofile_limit(65536, "wazuh_db.rlimit_nofile"), 8192);
}

static void test_raise_nofile_soft_already_higher(void ** state) {
    static const struct rlimit inherited = { 655360, 655360 };
    expect_getrlimit(&inherited, 0);
    assert_int_equal(w_raise_nofile_limit(65536, "remoted.rlimit_nofile"), 655360);
}

static void test_raise_nofile_getrlimit_fails(void ** state) {
    expect_getrlimit(NULL, -1);
    expect_any(__wrap__merror, formatted_msg);
    assert_int_equal(w_raise_nofile_limit(65536, "remoted.rlimit_nofile"), -1);
}

static void test_raise_nofile_setrlimit_fails(void ** state) {
    static const struct rlimit inherited = { 1024, 524288 };
    expect_getrlimit(&inherited, 0);
    expect_setrlimit(65536, 524288, -1);
    expect_any(__wrap__merror, formatted_msg);
    assert_int_equal(w_raise_nofile_limit(65536, "remoted.rlimit_nofile"), -1);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_GetUser_success),
        cmocka_unit_test(test_GetUser_success_extend),
        cmocka_unit_test(test_GetUser_failure),
        cmocka_unit_test(test_GetGroup_success),
        cmocka_unit_test(test_GetGroup_success_extend),
        cmocka_unit_test(test_GetGroup_failure),
        cmocka_unit_test(test_raise_nofile_hard_allows_target),
        cmocka_unit_test(test_raise_nofile_hard_unlimited),
        cmocka_unit_test(test_raise_nofile_hard_below_target),
        cmocka_unit_test(test_raise_nofile_hard_below_target_soft_lower),
        cmocka_unit_test(test_raise_nofile_soft_already_higher),
        cmocka_unit_test(test_raise_nofile_getrlimit_fails),
        cmocka_unit_test(test_raise_nofile_setrlimit_fails),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
