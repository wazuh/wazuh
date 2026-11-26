/*
 * Wazuh Module for Agent control - Unit Tests of the agent build
 * Copyright (C) Wazuh Inc.
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_control_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"
#include "wm_control.h"

/* Declared in wm_control.h for agent builds only; this test project does not define CLIENT. */
extern const char *wm_control_find_config_failure(void);

/* WM_CONTROL_LOGTAG expands to ARGV0 ":control"; ARGV0 is "wazuh-modulesd" on the agent. */
#define WM_CONTROL_TEST_LOGTAG "wazuh-modulesd:control"
#define CONFIG_TEST_TIMEOUT 60

/* The order wm_control runs them in, the same as wazuh-control's testconfig. Literals, since
 * expect_string() keeps the pointer it is given. */
static char *commands[] = {
    "bin/wazuh-execd -t", "bin/wazuh-agentd -t", "bin/wazuh-syscheckd -t",
    "bin/wazuh-logcollector -t", "bin/wazuh-modulesd -t"
};
#define DAEMON_COUNT (sizeof(commands) / sizeof(commands[0]))

/* The daemons before `failing` pass; `failing` gets (exitcode, return_code); later ones are not run. */
static void expect_config_tests(size_t failing, int exitcode, int return_code) {
    for (size_t i = 0; i < DAEMON_COUNT && i <= failing; i++) {
        bool fails = (i == failing);
        // The output is collected (and dropped) so wm_exec() doesn't poll once a second
        expect_wm_exec(commands[i], CONFIG_TEST_TIMEOUT, NULL, "",
                       fails ? exitcode : 0, fails ? return_code : 0);
    }
}

static void expect_all_config_tests_pass(void) {
    expect_config_tests(DAEMON_COUNT, 0, 0);
}

/* wm_control_execute_action() calls wm_control_check_systemd() in the same file, where --wrap does not
 * reach, so the check runs for real on the calls it makes: /run/systemd/system and /proc/1/comm. */
static void expect_systemd(bool present) {
    expect_string(__wrap_access, __name, "/run/systemd/system");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, present ? 0 : -1);
    if (!present) {
        return;
    }

    FILE *fp = (FILE *)1;
    expect_string(__wrap_fopen, path, "/proc/1/comm");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp);
    will_return(__wrap_fgets, "systemd\n");
    expect_value(__wrap_fgets, __stream, fp);
    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, 0);
}

static int setup_test_mode(void **state) {
    (void)state;
    test_mode = 1;
    return 0;
}

static int teardown_test_mode(void **state) {
    (void)state;
    test_mode = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* wm_control_find_config_failure                                       */
/* ------------------------------------------------------------------ */

static void test_find_config_failure_all_pass(void **state) {
    (void)state;
    expect_all_config_tests_pass();

    assert_null(wm_control_find_config_failure());
}

static void test_find_config_failure_stops_at_failing_daemon(void **state) {
    (void)state;
    expect_config_tests(1, 1, 0);

    assert_string_equal(wm_control_find_config_failure(), "wazuh-agentd");
}

static void test_find_config_failure_when_test_cannot_run(void **state) {
    (void)state;
    expect_config_tests(0, EXECVE_ERROR, -1);
    expect_string(__wrap__mterror, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Could not run the configuration test for wazuh-execd.");

    assert_string_equal(wm_control_find_config_failure(), "wazuh-execd");
}

static void test_find_config_failure_when_test_times_out(void **state) {
    (void)state;
    expect_config_tests(1, 0, WM_ERROR_TIMEOUT);
    expect_string(__wrap__mterror, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg,
                  "Configuration test for wazuh-agentd did not finish within 60 seconds.");

    assert_string_equal(wm_control_find_config_failure(), "wazuh-agentd");
}

static void test_find_config_failure_last_daemon(void **state) {
    (void)state;
    expect_config_tests(DAEMON_COUNT - 1, 1, 0);

    assert_string_equal(wm_control_find_config_failure(), "wazuh-modulesd");
}

/* ------------------------------------------------------------------ */
/* wm_control_execute_action                                            */
/* ------------------------------------------------------------------ */

static void assert_output(char *output, size_t ret, const char *expected) {
    assert_non_null(output);
    assert_string_equal(output, expected);
    assert_int_equal(ret, strlen(expected));
    free(output);
}

static void test_restart_with_systemd_runs_after_config_test(void **state) {
    (void)state;
    char *output = NULL;

    expect_systemd(true);
    expect_all_config_tests_pass();
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'restart' on wazuh-agent using systemctl");
    will_return(__wrap_fork, 1234);

    size_t ret = wm_control_execute_action("restart", "wazuh-agent", &output);

    assert_output(output, ret, "ok ");
}

static void test_restart_with_systemd_refused_on_config_failure(void **state) {
    (void)state;
    char *output = NULL;

    expect_systemd(true);
    expect_config_tests(2, 1, 0);
    expect_string(__wrap__mterror, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg,
                  "Configuration test failed for wazuh-syscheckd; the agent was not restarted.");

    size_t ret = wm_control_execute_action("restart", "wazuh-agent", &output);

    // No fork: a fork wrapper call without a queued value would fail the test.
    assert_output(output, ret, "err Configuration test failed");
}

static void test_reload_with_systemd_skips_config_test(void **state) {
    (void)state;
    char *output = NULL;

    expect_systemd(true);
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'reload' on wazuh-agent using systemctl");
    will_return(__wrap_fork, 1234);

    size_t ret = wm_control_execute_action("reload", "wazuh-agent", &output);

    assert_output(output, ret, "ok ");
}

static void test_restart_without_systemd_skips_config_test(void **state) {
    (void)state;
    char *output = NULL;

    expect_systemd(false);
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing 'restart' on wazuh-agent using bin/wazuh-control");
    will_return(__wrap_fork, 1234);

    size_t ret = wm_control_execute_action("restart", "wazuh-agent", &output);

    assert_output(output, ret, "ok ");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_find_config_failure_all_pass, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_find_config_failure_stops_at_failing_daemon, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_find_config_failure_when_test_cannot_run, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_find_config_failure_when_test_times_out, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_find_config_failure_last_daemon, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_restart_with_systemd_runs_after_config_test, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_restart_with_systemd_refused_on_config_failure, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_reload_with_systemd_skips_config_test, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_restart_without_systemd_skips_config_test, setup_test_mode, teardown_test_mode),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
