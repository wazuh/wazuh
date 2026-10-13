/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to how wm_exec() stops a command that outlives its timeout. These tests
 * run real commands: only kill() is wrapped, to record the signals sent before delivering them.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <signal.h>
#include <time.h>

#include "shared.h"
#include "wmodules.h"

#define MAX_KILLS 8

int __real_kill(pid_t pid, int sig);

static struct {
    pid_t pid;
    int sig;
} kills[MAX_KILLS];
static size_t kills_count;

int __wrap_kill(pid_t pid, int sig) {
    // Signal 0 only probes whether the process still exists
    if (sig != 0 && kills_count < MAX_KILLS) {
        kills[kills_count].pid = pid;
        kills[kills_count].sig = sig;
        kills_count++;
    }

    return __real_kill(pid, sig);
}

static int setup(void **state) {
    (void)state;
    kills_count = 0;
    wm_kill_timeout = 1;
    return 0;
}

static int teardown(void **state) {
    (void)state;
    wm_kill_timeout = 0;
    return 0;
}

static time_t elapsed_since(time_t start) {
    return time(NULL) - start;
}

// The output may carry more than the command wrote: a coverage build dumps its counters in the
// child right before exec and can print a notice to the captured stderr. Only the last line is
// the command's own.
static const char * last_line(const char *output) {
    const size_t len = strlen(output);
    const char *end = (len > 0 && output[len - 1] == '\n') ? output + len - 1 : output + len;
    const char *line = end;

    while (line > output && line[-1] != '\n') {
        line--;
    }

    return line;
}

// Both signals must go to the command's whole process group, SIGTERM first.
static void assert_group_terminated_then_killed(void) {
    assert_int_equal(kills_count, 2);
    assert_true(kills[0].pid < 0);
    assert_int_equal(kills[0].sig, SIGTERM);
    assert_int_equal(kills[1].pid, kills[0].pid);
    assert_int_equal(kills[1].sig, SIGKILL);
}

// A command that ignores SIGTERM while holding its output pipe must be killed, not waited for.
static void test_wm_exec_kills_command_ignoring_sigterm(void **state) {
    (void)state;
    char command[] = "sh -c \"trap '' TERM; echo started; sleep 60\"";
    char *output = NULL;
    int status = 0;
    const time_t start = time(NULL);

    expect_any(__wrap__mdebug1, formatted_msg); // Did not stop after SIGTERM

    const int ret = wm_exec(command, &output, &status, 1, NULL);

    assert_int_equal(ret, WM_ERROR_TIMEOUT);
    assert_true(elapsed_since(start) < 10);
    assert_non_null(output);
    assert_string_equal(last_line(output), "started\n");
    assert_int_equal(status, 128 + SIGKILL);
    assert_group_terminated_then_killed();

    os_free(output);
}

// Same, for a command run without capturing its output.
static void test_wm_exec_kills_command_ignoring_sigterm_without_output(void **state) {
    (void)state;
    char command[] = "sh -c \"trap '' TERM; sleep 60\"";
    int status = 0;
    const time_t start = time(NULL);

    expect_any(__wrap__mdebug1, formatted_msg); // Did not stop after SIGTERM

    const int ret = wm_exec(command, NULL, &status, 1, NULL);

    assert_int_equal(ret, WM_ERROR_TIMEOUT);
    assert_true(elapsed_since(start) < 10);
    assert_int_equal(status, 128 + SIGKILL);
    assert_group_terminated_then_killed();
}

// A process that left the command's process group keeps the output pipe open after the group
// is gone. wm_exec() must stop reading and return instead of waiting for it.
static void test_wm_exec_abandons_pipe_held_outside_group(void **state) {
    (void)state;
    // setsid moves sleep to a new session, out of reach of the signals sent to the group. It
    // execs in place, so $! is the pid of the sleep that holds the pipe. w_strtok() only
    // understands double quotes, hence the quoting of every command here.
    char command[] = "sh -c \"setsid sleep 60 & echo $!\"";
    char *output = NULL;
    int status = 0;
    const time_t start = time(NULL);

    wm_kill_timeout = 0;

    expect_any(__wrap__mdebug1, formatted_msg); // Did not stop after SIGTERM
    expect_any(__wrap__mdebug1, formatted_msg); // Pipe still open: abandoning it

    const int ret = wm_exec(command, &output, &status, 1, NULL);

    assert_int_equal(ret, WM_ERROR_TIMEOUT);
    assert_true(elapsed_since(start) < 10);
    assert_non_null(output);

    const pid_t escaped = (pid_t)strtol(last_line(output), NULL, 10);
    assert_true(escaped > 0);
    __real_kill(escaped, SIGKILL);

    os_free(output);
}

// A command that finishes in time is not signalled at all.
static void test_wm_exec_does_not_signal_command_finishing_in_time(void **state) {
    (void)state;
    char command[] = "echo done";
    char *output = NULL;
    int status = -1;

    const int ret = wm_exec(command, &output, &status, 5, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(last_line(output), "done\n");
    assert_int_equal(status, 0);
    assert_int_equal(kills_count, 0);

    os_free(output);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wm_exec_kills_command_ignoring_sigterm, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_kills_command_ignoring_sigterm_without_output, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_abandons_pipe_held_outside_group, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_does_not_signal_command_finishing_in_time, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
