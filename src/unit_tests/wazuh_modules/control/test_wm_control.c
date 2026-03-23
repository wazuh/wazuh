/*
 * Wazuh Module for Agent control - Unit Tests
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
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_control_wrappers.h"
#include "wm_control.h"

/* WM_CONTROL_LOGTAG expands to ARGV0 ":control".
 * For the manager build ARGV0 is "wazuh-manager-modulesd". */
#define WM_CONTROL_TEST_LOGTAG "wazuh-manager-modulesd:control"

/* ------------------------------------------------------------------ */
/* Setup / teardown                                                     */
/* ------------------------------------------------------------------ */

static int setup_test_mode(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_test_mode(void **state) {
    test_mode = 0;
    return 0;
}

static void expect_check_systemd_not_available(void) {
    expect_string(__wrap_access, __name, "/run/systemd/system");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);
}

static void expect_check_systemd_available(void) {
    FILE *fp = (FILE *)1;

    expect_string(__wrap_access, __name, "/run/systemd/system");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    expect_string(__wrap_fopen, path, "/proc/1/comm");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp);

    will_return(__wrap_fgets, "systemd\n");
    expect_value(__wrap_fgets, __stream, fp);

    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, 0);
}

/* ------------------------------------------------------------------ */
/* wm_control_dispatch tests                                            */
/* ------------------------------------------------------------------ */

static void test_dispatch_restart(void **state) {
    char command[] = "restart";
    char *output = NULL;

    expect_string(__wrap__mtdebug2, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Dispatching command: 'restart'");
    expect_check_systemd_not_available();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'restart' on manager using wazuh-control");
    will_return(__wrap_fork, 1234);

    size_t ret = wm_control_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok ");
    assert_int_equal(ret, strlen("ok "));

    free(output);
}

static void test_dispatch_reload(void **state) {
    char command[] = "reload";
    char *output = NULL;

    expect_string(__wrap__mtdebug2, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Dispatching command: 'reload'");
    expect_check_systemd_not_available();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'reload' on manager using wazuh-control");
    will_return(__wrap_fork, 5678);

    size_t ret = wm_control_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok ");
    assert_int_equal(ret, strlen("ok "));

    free(output);
}

static void test_dispatch_restart_with_args(void **state) {
    /* Arguments after a space must be stripped before dispatch */
    char command[] = "restart somearg";
    char *output = NULL;

    expect_string(__wrap__mtdebug2, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Dispatching command: 'restart'");
    expect_check_systemd_not_available();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'restart' on manager using wazuh-control");
    will_return(__wrap_fork, 1234);

    size_t ret = wm_control_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok ");
    assert_int_equal(ret, strlen("ok "));

    free(output);
}

static void test_dispatch_unknown_command(void **state) {
    char command[] = "unknowncmd";
    char *output = NULL;

    expect_string(__wrap__mtdebug2, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Dispatching command: 'unknowncmd'");

    expect_string(__wrap__mterror, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Unknown command: 'unknowncmd'");

    size_t ret = wm_control_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "Err");
    assert_int_equal(ret, strlen("Err"));

    free(output);
}

/* ------------------------------------------------------------------ */
/* wm_control_execute_action tests                                      */
/* ------------------------------------------------------------------ */

static void test_execute_action_fork_fails(void **state) {
    char *output = NULL;

    expect_check_systemd_not_available();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'restart' on manager using wazuh-control");

    will_return(__wrap_fork, -1);
    expect_string(__wrap__mterror, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Cannot fork for restart");

    size_t ret = wm_control_execute_action("restart", &output);

    assert_non_null(output);
    assert_string_equal(output, "err Cannot fork");
    assert_int_equal(ret, strlen("err Cannot fork"));

    free(output);
}

static void test_execute_action_restart_no_systemd(void **state) {
    char *output = NULL;

    expect_check_systemd_not_available();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'restart' on manager using wazuh-control");

    will_return(__wrap_fork, 1234); /* Simulate parent process */

    size_t ret = wm_control_execute_action("restart", &output);

    assert_non_null(output);
    assert_string_equal(output, "ok ");
    assert_int_equal(ret, strlen("ok "));

    free(output);
}

static void test_execute_action_restart_systemd(void **state) {
    char *output = NULL;

    expect_check_systemd_available();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'restart' on manager using systemctl");

    will_return(__wrap_fork, 1234); /* Simulate parent process */

    size_t ret = wm_control_execute_action("restart", &output);

    assert_non_null(output);
    assert_string_equal(output, "ok ");
    assert_int_equal(ret, strlen("ok "));

    free(output);
}

static void test_execute_action_reload_no_systemd(void **state) {
    char *output = NULL;

    expect_check_systemd_not_available();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'reload' on manager using wazuh-control");

    will_return(__wrap_fork, 5678); /* Simulate parent process */

    size_t ret = wm_control_execute_action("reload", &output);

    assert_non_null(output);
    assert_string_equal(output, "ok ");
    assert_int_equal(ret, strlen("ok "));

    free(output);
}

static void test_execute_action_reload_systemd(void **state) {
    char *output = NULL;

    expect_check_systemd_available();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'reload' on manager using systemctl");

    will_return(__wrap_fork, 5678); /* Simulate parent process */

    size_t ret = wm_control_execute_action("reload", &output);

    assert_non_null(output);
    assert_string_equal(output, "ok ");
    assert_int_equal(ret, strlen("ok "));

    free(output);
}

/* ------------------------------------------------------------------ */
/* wm_control_check_systemd tests                                       */
/* ------------------------------------------------------------------ */

static void test_check_systemd_no_run_dir(void **state) {
    expect_string(__wrap_access, __name, "/run/systemd/system");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    bool result = __real_wm_control_check_systemd();

    assert_false(result);
}

static void test_check_systemd_fopen_fails(void **state) {
    expect_string(__wrap_access, __name, "/run/systemd/system");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    expect_string(__wrap_fopen, path, "/proc/1/comm");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    bool result = __real_wm_control_check_systemd();

    assert_false(result);
}

static void test_check_systemd_is_systemd(void **state) {
    FILE *fp = (FILE *)1;

    expect_string(__wrap_access, __name, "/run/systemd/system");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    expect_string(__wrap_fopen, path, "/proc/1/comm");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp);

    will_return(__wrap_fgets, "systemd\n");
    expect_value(__wrap_fgets, __stream, fp);

    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, 0);

    bool result = __real_wm_control_check_systemd();

    assert_true(result);
}

static void test_check_systemd_not_systemd(void **state) {
    FILE *fp = (FILE *)1;

    expect_string(__wrap_access, __name, "/run/systemd/system");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    expect_string(__wrap_fopen, path, "/proc/1/comm");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp);

    will_return(__wrap_fgets, "init\n");
    expect_value(__wrap_fgets, __stream, fp);

    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, 0);

    bool result = __real_wm_control_check_systemd();

    assert_false(result);
}

static void test_check_systemd_fgets_null(void **state) {
    FILE *fp = (FILE *)1;

    expect_string(__wrap_access, __name, "/run/systemd/system");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    expect_string(__wrap_fopen, path, "/proc/1/comm");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp);

    will_return(__wrap_fgets, NULL);
    expect_value(__wrap_fgets, __stream, fp);

    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, 0);

    bool result = __real_wm_control_check_systemd();

    assert_false(result);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* wm_control_dispatch */
        cmocka_unit_test_setup_teardown(test_dispatch_restart,            setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_dispatch_reload,             setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_dispatch_restart_with_args,  setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_dispatch_unknown_command,    setup_test_mode, teardown_test_mode),
        /* wm_control_execute_action */
        cmocka_unit_test_setup_teardown(test_execute_action_fork_fails,          setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_execute_action_restart_no_systemd,   setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_execute_action_restart_systemd,      setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_execute_action_reload_no_systemd,    setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_execute_action_reload_systemd,       setup_test_mode, teardown_test_mode),
        /* wm_control_check_systemd */
        cmocka_unit_test_setup_teardown(test_check_systemd_no_run_dir,    setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_check_systemd_fopen_fails,   setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_check_systemd_is_systemd,    setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_check_systemd_not_systemd,   setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_check_systemd_fgets_null,    setup_test_mode, teardown_test_mode),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
