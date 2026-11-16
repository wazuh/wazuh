/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to how wm_exec() stops a command that outlives its timeout. These tests
 * run real commands: only kill() is wrapped, to record the signals sent before delivering them,
 * and setsid(), to make a child block before it leads its own process group.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

#include "shared.h"
#include "../../../wazuh_modules/wmodules.h"

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

pid_t __real_setsid(void);

// Locked by the test across fork(), so a child that locks it blocks forever, as one does when it
// inherits a lock that another thread was holding.
static pthread_mutex_t inherited_lock = PTHREAD_MUTEX_INITIALIZER;
static bool block_before_setsid;

pid_t __wrap_setsid(void) {
    if (block_before_setsid) {
        pthread_mutex_lock(&inherited_lock);
    }

    return __real_setsid();
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

static int setup_blocked_child(void **state) {
    block_before_setsid = true;
    pthread_mutex_lock(&inherited_lock);
    return setup(state);
}

static int teardown_blocked_child(void **state) {
    block_before_setsid = false;
    pthread_mutex_unlock(&inherited_lock);
    return teardown(state);
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

// A child without a process group of its own must get the signal itself, after the group did not exist.
static void assert_child_terminated_directly(void) {
    assert_int_equal(kills_count, 2);
    assert_true(kills[0].pid < 0);
    assert_int_equal(kills[0].sig, SIGTERM);
    assert_int_equal(kills[1].pid, -kills[0].pid);
    assert_int_equal(kills[1].sig, SIGTERM);
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

// Same, when the process holding the pipe keeps writing to it: the pipe is never idle, and
// wm_exec() must still stop reading.
static void test_wm_exec_abandons_pipe_written_outside_group(void **state) {
    (void)state;
    // The detached shell prints its own pid every 0.2 s, so the last line read is its pid.
    char command[] = "sh -c \"setsid sh -c 'while :; do echo $$; sleep 0.2; done' &\"";
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

// A command that sends its output elsewhere closes the pipe right away, and the reader sees end
// of file long before the command exits. Its timeout must still apply.
static void test_wm_exec_kills_command_that_closed_its_output(void **state) {
    (void)state;
    char command[] = "sh -c \"exec >/dev/null 2>&1; trap '' TERM; sleep 60\"";
    char *output = NULL;
    int status = 0;
    const time_t start = time(NULL);

    expect_any(__wrap__mdebug1, formatted_msg); // Did not stop after SIGTERM

    const int ret = wm_exec(command, &output, &status, 1, NULL);

    assert_int_equal(ret, WM_ERROR_TIMEOUT);
    assert_true(elapsed_since(start) < 10);
    assert_int_equal(status, 128 + SIGKILL);
    assert_group_terminated_then_killed();

    os_free(output);
}

// On timeout, SIGTERM can end the only processes holding the pipe while the command itself
// ignores it. End of file then comes without SIGKILL, and the command must not be waited for.
static void test_wm_exec_kills_command_ignoring_sigterm_after_pipe_closed(void **state) {
    (void)state;
    // The background sleep is started before the trap, so SIGTERM ends it and closes the pipe.
    char command[] = "sh -c \"sleep 60 & trap '' TERM; exec >/dev/null 2>&1; while :; do sleep 1; done\"";
    char *output = NULL;
    int status = 0;
    const time_t start = time(NULL);

    expect_any(__wrap__mdebug1, formatted_msg); // Did not stop after SIGTERM

    const int ret = wm_exec(command, &output, &status, 1, NULL);

    assert_int_equal(ret, WM_ERROR_TIMEOUT);
    assert_true(elapsed_since(start) < 10);
    assert_int_equal(status, 128 + SIGKILL);
    assert_int_equal(kills_count, 3);
    assert_true(kills[0].pid < 0);
    assert_int_equal(kills[0].sig, SIGTERM);
    assert_int_equal(kills[1].pid, kills[0].pid);
    assert_int_equal(kills[1].sig, SIGTERM);
    assert_int_equal(kills[2].pid, kills[0].pid);
    assert_int_equal(kills[2].sig, SIGKILL);

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

// A child that blocks before setsid() is not in a process group of its own, and still holds the
// write end of the output pipe. The timeout must stop it and wm_exec() must return.
static void test_wm_exec_stops_child_blocked_before_setsid(void **state) {
    (void)state;
    char command[] = "echo never";
    char *output = NULL;
    int status = 0;
    const time_t start = time(NULL);

    const int ret = wm_exec(command, &output, &status, 1, NULL);

    assert_int_equal(ret, WM_ERROR_TIMEOUT);
    assert_true(elapsed_since(start) < 10);
    assert_int_equal(status, 128 + SIGTERM);
    assert_child_terminated_directly();

    os_free(output);
}

// Same, for a command run without capturing its output.
static void test_wm_exec_stops_child_blocked_before_setsid_without_output(void **state) {
    (void)state;
    char command[] = "echo never";
    int status = 0;
    const time_t start = time(NULL);

    const int ret = wm_exec(command, NULL, &status, 1, NULL);

    assert_int_equal(ret, WM_ERROR_TIMEOUT);
    assert_true(elapsed_since(start) < 10);
    assert_int_equal(status, 128 + SIGTERM);
    assert_child_terminated_directly();
}

// The command runs from the directory it is given.
static void test_wm_exec_in_dir_runs_command_there(void **state) {
    (void)state;
    char command[] = "pwd";
    char *output = NULL;
    int status = -1;

    const int ret = wm_exec_in_dir(command, &output, &status, 5, NULL, "/");

    assert_int_equal(ret, 0);
    assert_string_equal(last_line(output), "/\n");
    assert_int_equal(status, 0);

    os_free(output);
}

// A command that cannot change to its directory is not run from another one.
static void test_wm_exec_in_dir_does_not_run_command_elsewhere(void **state) {
    (void)state;
    char command[] = "echo ran";
    char *output = NULL;
    int status = -1;

    expect_any(__wrap__mdebug1, formatted_msg); // Invalid command

    const int ret = wm_exec_in_dir(command, &output, &status, 5, NULL, "/nonexistent/wm_exec_dir");

    assert_int_equal(ret, -1);
    assert_null(output);
    assert_int_equal(status, EXECVE_ERROR);
}

// add_path goes before PATH for the command only: the caller's environment does not change.
static void test_wm_exec_add_path_only_for_command(void **state) {
    (void)state;
    char dir[] = "/tmp/wm_exec_add_path_XXXXXX";
    char script[PATH_MAX];
    char expected_path[OS_SIZE_6144];
    char expected_msg[OS_SIZE_6144 + 64];
    char command[] = "wm_exec_add_path_test";
    char *output = NULL;
    int status = -1;

    assert_non_null(mkdtemp(dir));
    snprintf(script, sizeof(script), "%s/%s", dir, command);

    FILE *fp = fopen(script, "w");
    assert_non_null(fp);
    fprintf(fp, "#!/bin/sh\necho \"$PATH\"\n");
    fclose(fp);
    assert_int_equal(chmod(script, 0755), 0);

    const char *env_path = getenv("PATH");
    char *path_before = env_path ? strdup(env_path) : NULL;

    if (path_before) {
        snprintf(expected_path, sizeof(expected_path), "%s:%s", dir, path_before);
    } else {
        snprintf(expected_path, sizeof(expected_path), "%s", dir);
    }

    snprintf(expected_msg, sizeof(expected_msg), "New 'PATH' environment variable set: '%s'", expected_path);
    expect_string(__wrap__mdebug1, formatted_msg, expected_msg);

    const int ret = wm_exec(command, &output, &status, 5, dir);

    assert_int_equal(ret, 0);
    assert_int_equal(status, 0);
    assert_non_null(output);
    assert_int_equal(strncmp(last_line(output), expected_path, strlen(expected_path)), 0);
    assert_string_equal(last_line(output) + strlen(expected_path), "\n");

    if (path_before) {
        assert_string_equal(getenv("PATH"), path_before);
    } else {
        assert_null(getenv("PATH"));
    }

    os_free(output);
    os_free(path_before);
    unlink(script);
    rmdir(dir);
}

// A PATH too large to extend is left as it is, and the command still runs.
static void test_wm_exec_add_path_keeps_environment_if_too_large(void **state) {
    (void)state;
    char command[] = "/bin/sh -c \"echo ran\"";
    char *output = NULL;
    int status = -1;
    char large_path[OS_SIZE_6144 + 1];

    const char *env_path = getenv("PATH");
    char *path_before = env_path ? strdup(env_path) : NULL;

    memset(large_path, 'a', sizeof(large_path) - 1);
    large_path[sizeof(large_path) - 1] = '\0';
    assert_int_equal(setenv("PATH", large_path, 1), 0);

    expect_string(__wrap__merror, formatted_msg, "at wm_exec(): PATH environment variable too large.");

    const int ret = wm_exec(command, &output, &status, 5, "/opt/unused");

    if (path_before) {
        setenv("PATH", path_before, 1);
    } else {
        unsetenv("PATH");
    }

    assert_int_equal(ret, 0);
    assert_int_equal(status, 0);
    assert_string_equal(last_line(output), "ran\n");

    os_free(output);
    os_free(path_before);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wm_exec_kills_command_ignoring_sigterm, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_kills_command_ignoring_sigterm_without_output, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_abandons_pipe_held_outside_group, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_abandons_pipe_written_outside_group, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_kills_command_that_closed_its_output, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_kills_command_ignoring_sigterm_after_pipe_closed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_does_not_signal_command_finishing_in_time, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_stops_child_blocked_before_setsid, setup_blocked_child, teardown_blocked_child),
        cmocka_unit_test_setup_teardown(test_wm_exec_stops_child_blocked_before_setsid_without_output, setup_blocked_child, teardown_blocked_child),
        cmocka_unit_test_setup_teardown(test_wm_exec_in_dir_runs_command_there, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_in_dir_does_not_run_command_elsewhere, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_add_path_only_for_command, setup, teardown),
        cmocka_unit_test_setup_teardown(test_wm_exec_add_path_keeps_environment_if_too_large, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
