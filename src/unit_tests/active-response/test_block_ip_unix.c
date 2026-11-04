/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "active_responses.h"
#include "firewall_helpers.h"

#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/binaries_op_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"

/* block-ip-unix.c is compiled directly into this target (see CMakeLists.txt). */
firewall_result_t try_iptables(const char *srcip, int action, int ip_version, const char *argv0);

int __wrap_lock(__attribute__((unused)) const char *lock_path,
                __attribute__((unused)) const char *lock_pid_path,
                __attribute__((unused)) const char *log_path,
                __attribute__((unused)) const char *proc_name) {
    return OS_SUCCESS;
}

void __wrap_unlock(__attribute__((unused)) const char *lock_path, __attribute__((unused)) const char *log_path) {
}

#define EXIT_STATUS(code) ((code) << 8)

#define MAX_MOCK_WFD 16
static wfd_t *mock_wfds[MAX_MOCK_WFD];
static int mock_wfd_count = 0;

static wfd_t *make_wfd(void) {
    /* fmemopen() leaves size==0 undefined */
    static const char empty[] = "\n";

    wfd_t *wfd = calloc(1, sizeof(wfd_t));
    assert_non_null(wfd);
    wfd->file_out = fmemopen((void *)empty, strlen(empty), "r");
    assert_non_null(wfd->file_out);

    assert_true(mock_wfd_count < MAX_MOCK_WFD);
    mock_wfds[mock_wfd_count++] = wfd;
    return wfd;
}

static int teardown_wfds(void **state) {
    (void)state;
    for (int i = 0; i < mock_wfd_count; i++) {
        fclose(mock_wfds[i]->file_out);
        free(mock_wfds[i]);
    }
    mock_wfd_count = 0;
    return 0;
}

static void expect_binary(const char *name, const char *path) {
    expect_string(__wrap_get_binary_path, command, name);
    will_return(__wrap_get_binary_path, strdup(path));
    will_return(__wrap_get_binary_path, 0);
}

static void expect_iptables_run(int exit_code) {
    will_return(__wrap_wpopenv, make_wfd());
    will_return(__wrap_wpclose, EXIT_STATUS(exit_code));
}

static void assert_last_command(const char *binary, const char *op, const char *chain, const char *srcip) {
    assert_int_equal(wpopenv_captured_argc(), 7);
    assert_string_equal(wpopenv_captured_argv(0), binary);
    assert_string_equal(wpopenv_captured_argv(1), op);
    assert_string_equal(wpopenv_captured_argv(2), chain);
    assert_string_equal(wpopenv_captured_argv(3), "-s");
    assert_string_equal(wpopenv_captured_argv(4), srcip);
    assert_string_equal(wpopenv_captured_argv(5), "-j");
    assert_string_equal(wpopenv_captured_argv(6), "DROP");
}

void test_try_iptables_enable_inserts_missing_rules(void **state) {
    expect_binary("iptables", "/usr/sbin/iptables");
    expect_iptables_run(1);    // -C INPUT: not present
    expect_iptables_run(0);    // -I INPUT
    expect_iptables_run(1);    // -C FORWARD: not present
    expect_iptables_run(0);    // -I FORWARD

    assert_int_equal(try_iptables("192.168.56.1", ENABLE_COMMAND, 4, "block-ip"), FIREWALL_SUCCESS);
    assert_last_command("/usr/sbin/iptables", "-I", "FORWARD", "192.168.56.1");
}

void test_try_iptables_enable_already_blocked_does_not_insert(void **state) {
    expect_binary("iptables", "/usr/sbin/iptables");
    expect_iptables_run(0);    // -C INPUT: present
    expect_iptables_run(0);    // -C FORWARD: present

    assert_int_equal(try_iptables("192.168.56.1", ENABLE_COMMAND, 4, "block-ip"), FIREWALL_SUCCESS);
    assert_last_command("/usr/sbin/iptables", "-C", "FORWARD", "192.168.56.1");
}

void test_try_iptables_disable_removes_every_copy(void **state) {
    expect_binary("iptables", "/usr/sbin/iptables");
    expect_iptables_run(0);    // -D INPUT
    expect_iptables_run(0);    // -D INPUT
    expect_iptables_run(0);    // -D INPUT
    expect_iptables_run(1);    // -D INPUT: no copy left
    expect_iptables_run(0);    // -D FORWARD
    expect_iptables_run(1);    // -D FORWARD: no copy left

    assert_int_equal(try_iptables("192.168.56.1", DISABLE_COMMAND, 4, "block-ip"), FIREWALL_SUCCESS);
    assert_last_command("/usr/sbin/iptables", "-D", "FORWARD", "192.168.56.1");
}

void test_try_iptables_disable_not_blocked_is_success(void **state) {
    expect_binary("iptables", "/usr/sbin/iptables");
    expect_iptables_run(1);
    expect_iptables_run(1);

    assert_int_equal(try_iptables("192.168.56.1", DISABLE_COMMAND, 4, "block-ip"), FIREWALL_SUCCESS);
    assert_last_command("/usr/sbin/iptables", "-D", "FORWARD", "192.168.56.1");
}

void test_try_iptables_spawn_failure_is_execution_failed(void **state) {
    expect_binary("iptables", "/usr/sbin/iptables");
    for (int chain = 0; chain < 2; chain++) {
        for (int attempt = 1; attempt <= 5; attempt++) {
            will_return(__wrap_wpopenv, NULL);
            if (attempt < 5) {
                expect_value(__wrap_sleep, seconds, attempt);
            }
        }
    }

    assert_int_equal(try_iptables("192.168.56.1", DISABLE_COMMAND, 4, "block-ip"), FIREWALL_EXECUTION_FAILED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_try_iptables_enable_inserts_missing_rules, teardown_wfds),
        cmocka_unit_test_teardown(test_try_iptables_enable_already_blocked_does_not_insert, teardown_wfds),
        cmocka_unit_test_teardown(test_try_iptables_disable_removes_every_copy, teardown_wfds),
        cmocka_unit_test_teardown(test_try_iptables_disable_not_blocked_is_success, teardown_wfds),
        cmocka_unit_test(test_try_iptables_spawn_failure_is_execution_failed),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
