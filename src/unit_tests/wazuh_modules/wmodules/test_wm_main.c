/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the wazuh-modulesd signal handler and shutdown sequence (plan 18, E7a)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>

#define main wm_main
#include "../../../wazuh_modules/src/main.c"
#undef main

#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Everything the sequence does is appended here, in order. */
enum event {
    EV_NANOSLEEP = 1,
    EV_BEGIN_SHUTDOWN,
    EV_STOP_A,
    EV_STOP_B,
    EV_JOIN,
    EV_RUNTIME_SHUTDOWN,
    EV_EXIT
};

#define TEST_MAX_EVENTS 32
static int events[TEST_MAX_EVENTS];
static int event_count = 0;

static void add_event(int ev) {
    assert_true(event_count < TEST_MAX_EVENTS);
    events[event_count++] = ev;
}

/* CLOCK_MONOTONIC script (milliseconds); armed when mono_script_len > 0. */
#define TEST_MAX_MONO 16
static long mono_script[TEST_MAX_MONO];
static int mono_script_len = 0;
static int mono_calls = 0;
static struct timespec realtime_value;
static int realtime_calls = 0;

/* nanosleep(): armed => never really sleeps; the first call may fail with EINTR. */
static bool sleep_armed = false;
static bool first_sleep_eintr = false;
static int nanosleep_calls = 0;
static long nanosleep_ms[4];
static int flag_at_nanosleep[4];

/* pthread_timedjoin_np() */
static bool join_armed = false;
static int join_calls = 0;
static struct timespec join_deadline[4];

/* write() to the shutdown pipe */
static int pipe_writes = 0;
static ssize_t pipe_write_len = 0;
static ssize_t pipe_write_rc = 0;
static int pipe_write_errno = 0;

/* startup_gate_wait_for_ready() */
static bool gate_armed = false;

static int stop_calls = 0;
static int exit_calls = 0;

#ifndef CLIENT
static long begin_shutdown_ms = -1;
static int begin_shutdown_calls = 0;
static int runtime_shutdown_calls = 0;
#endif

int __real_clock_gettime(clockid_t clk, struct timespec *ts);
int __real_nanosleep(const struct timespec *req, struct timespec *rem);
int __real_pthread_timedjoin_np(pthread_t th, void **ret, const struct timespec *abstime);
ssize_t __real_write(int fd, const void *buf, size_t count);
startup_gate_wait_result_t __real_startup_gate_wait_for_ready(const char *module_name);

int __wrap_clock_gettime(clockid_t clk, struct timespec *ts) {
    if (mono_script_len == 0) {
        return __real_clock_gettime(clk, ts);
    }
    if (clk == CLOCK_MONOTONIC) {
        if (mono_calls >= mono_script_len) {
            fail_msg("CLOCK_MONOTONIC read %d times, the script has %d values", mono_calls + 1, mono_script_len);
        }
        long ms = mono_script[mono_calls++];
        ts->tv_sec = ms / 1000;
        ts->tv_nsec = (ms % 1000) * 1000000L;
        return 0;
    }
    if (clk == CLOCK_REALTIME) {
        realtime_calls++;
        *ts = realtime_value;
        return 0;
    }
    return __real_clock_gettime(clk, ts);
}

int __wrap_nanosleep(const struct timespec *req, struct timespec *rem) {
    int idx = nanosleep_calls++;
    if (idx < 4) {
        nanosleep_ms[idx] = req->tv_sec * 1000 + req->tv_nsec / 1000000L;
        flag_at_nanosleep[idx] = wm_shutdown_requested;
    }
    if (!sleep_armed) {
        return __real_nanosleep(req, rem);
    }
    add_event(EV_NANOSLEEP);
    if (first_sleep_eintr && idx == 0) {
        errno = EINTR;
        return -1;
    }
    return 0;
}

// exit() is noreturn: end the sequence through expect_assert_failure(), as test_agentd.c does.
void __wrap_exit(int code) {
    exit_calls++;
    add_event(EV_EXIT);
    check_expected(code);
    mock_assert(0, "exit called", __FILE__, __LINE__);
}

int __wrap_pthread_timedjoin_np(pthread_t th, void **ret, const struct timespec *abstime) {
    if (!join_armed) {
        return __real_pthread_timedjoin_np(th, ret, abstime);
    }
    int idx = join_calls++;
    if (idx < 4) {
        join_deadline[idx] = *abstime;
    }
    add_event(EV_JOIN);
    return 0;
}

ssize_t __wrap_write(int fd, const void *buf, size_t count) {
    const bool to_pipe = fd >= 0 && fd == wm_shutdown_pipe[1];
    if (to_pipe) {
        pipe_writes++;
        pipe_write_len = (ssize_t)count;
    }
    ssize_t rc = __real_write(fd, buf, count);
    if (to_pipe) {
        pipe_write_rc = rc;
        pipe_write_errno = rc < 0 ? errno : 0;
    }
    return rc;
}

startup_gate_wait_result_t __wrap_startup_gate_wait_for_ready(const char *module_name) {
    if (!gate_armed) {
        return __real_startup_gate_wait_for_ready(module_name);
    }
    return STARTUP_GATE_SHUTDOWN_REQUESTED;
}

#ifndef CLIENT
/* wm_cleanup() */
static int kill_children_calls = 0;
static int delete_pid_calls = 0;

void __wrap_wm_kill_children(void) {
    kill_children_calls++;
}

int __wrap_DeletePID(const char *name) {
    (void)name;
    delete_pid_calls++;
    return 0;
}

void __wrap_wm_indexer_runtime_begin_shutdown(long remaining_ms) {
    begin_shutdown_calls++;
    begin_shutdown_ms = remaining_ms;
    add_event(EV_BEGIN_SHUTDOWN);
}

void __wrap_wm_indexer_runtime_shutdown(void) {
    runtime_shutdown_calls++;
    add_event(EV_RUNTIME_SHUTDOWN);
}
#endif

static void stop_a(void *data) {
    (void)data;
    stop_calls++;
    add_event(EV_STOP_A);
}

static void stop_b(void *data) {
    (void)data;
    stop_calls++;
    add_event(EV_STOP_B);
}

static const wm_context context_a = { .name = "fake-a", .stop = stop_a };
static const wm_context context_b = { .name = "fake-b", .stop = stop_b };
static wmodule module_b = { .context = &context_b, .thread = (pthread_t)2 };
static wmodule module_a = { .context = &context_a, .thread = (pthread_t)1, .next = &module_b };

static int setup_test(void **state) {
    (void)state;
    event_count = 0;
    mono_script_len = 0;
    mono_calls = 0;
    realtime_calls = 0;
    memset(&realtime_value, 0, sizeof(realtime_value));
    sleep_armed = false;
    first_sleep_eintr = false;
    nanosleep_calls = 0;
    join_armed = false;
    join_calls = 0;
    pipe_writes = 0;
    pipe_write_len = 0;
    pipe_write_rc = 0;
    pipe_write_errno = 0;
    gate_armed = false;
    stop_calls = 0;
    exit_calls = 0;
#ifndef CLIENT
    begin_shutdown_ms = -1;
    begin_shutdown_calls = 0;
    runtime_shutdown_calls = 0;
    kill_children_calls = 0;
    delete_pid_calls = 0;
#endif
    wm_shutdown_requested = 0;
    wm_shutdown_signum = 0;
    wmodules = &module_a;
    wm_signals_configure();
    return 0;
}

static int teardown_test(void **state) {
    (void)state;
    if (wm_shutdown_pipe[0] >= 0) {
        close(wm_shutdown_pipe[0]);
    }
    if (wm_shutdown_pipe[1] >= 0) {
        close(wm_shutdown_pipe[1]);
    }
    wm_shutdown_pipe[0] = wm_shutdown_pipe[1] = -1;
    wmodules = NULL;
    wm_shutdown_requested = 0;
    return 0;
}

/* The agent has no begin_shutdown step: one monotonic read fewer. */
#ifdef CLIENT
#define MONO_READS(n) ((n) - 1)
#else
#define MONO_READS(n) (n)
#endif

/* T0 = 5000.250 s on the monotonic clock; R = 1700000000.123 s on the real-time clock. */
#define T0_MS 5000250L

static void arm_clocks(const long *offsets_ms, int n) {
    assert_true(n <= TEST_MAX_MONO);
    for (int i = 0; i < n; i++) {
        mono_script[i] = T0_MS + offsets_ms[i];
    }
    mono_script_len = n;
    mono_calls = 0;
    realtime_value.tv_sec = 1700000000;
    realtime_value.tv_nsec = 123000000L;
    sleep_armed = true;
    join_armed = true;
}

/* The two log lines of the sequence; the second one carries a thread id. */
static void expect_sequence_logs(void) {
    expect_string(__wrap__mdebug1, formatted_msg, "Shutting down Wazuh modules.");
    expect_any(__wrap__mdebug1, formatted_msg);
}

// The handler only raises the flag and wakes the main thread: nothing else, errno untouched.
// The write end is closed first, so the handler's write() fails (EBADF) and would clobber errno if it were not restored.
static void handler_only_flags_and_wakes(void **state) {
    (void)state;

    close(wm_shutdown_pipe[1]);

    errno = 5;
    wm_handler(SIGTERM);
    int saved_errno = errno;

    wm_shutdown_pipe[1] = -1;   // already closed: the teardown must not close it again

    assert_int_equal(pipe_write_rc, -1);
    assert_int_equal(pipe_write_errno, EBADF);
    assert_int_equal(saved_errno, 5);
    assert_int_equal(wm_shutdown_requested, 1);
    assert_int_equal(pipe_writes, 1);
    assert_int_equal(pipe_write_len, 1);
    assert_int_equal(stop_calls, 0);
    assert_int_equal(nanosleep_calls, 0);
    assert_int_equal(exit_calls, 0);
}

// Grace 1 s, begin_shutdown(25 s - elapsed), stop() in list order, joins to T0 + 28 s, runtime shutdown after the joins.
static void shutdown_run_order(void **state) {
    (void)state;
    const long offsets[] = { 0, 0, 1000, 1000, 1000 };
    arm_clocks(offsets, 5);

    wm_handler(SIGTERM);   // the signal that started the shutdown

    expect_sequence_logs();
    expect_value(__wrap_exit, code, EXIT_SUCCESS);

    expect_assert_failure(wm_shutdown_run(SIGTERM));

    int expected[] = {
        EV_NANOSLEEP,
#ifndef CLIENT
        EV_BEGIN_SHUTDOWN,
#endif
        EV_STOP_A, EV_STOP_B, EV_JOIN, EV_JOIN,
#ifndef CLIENT
        EV_RUNTIME_SHUTDOWN,
#endif
        EV_EXIT
    };
    assert_int_equal(event_count, (int)(sizeof(expected) / sizeof(expected[0])));
    for (int i = 0; i < event_count; i++) {
        assert_int_equal(events[i], expected[i]);
    }

    assert_int_equal(nanosleep_calls, 1);
    assert_int_equal(nanosleep_ms[0], 1000);
    assert_int_equal(flag_at_nanosleep[0], 1);
    assert_int_equal(mono_calls, MONO_READS(5));
    assert_int_equal(realtime_calls, 1);

    assert_int_equal(join_calls, 2);
    for (int i = 0; i < 2; i++) {
        // R + (28000 - 1000) ms, exactly.
        assert_int_equal(join_deadline[i].tv_sec, 1700000000 + 27);
        assert_int_equal(join_deadline[i].tv_nsec, 123000000L);
    }
#ifndef CLIENT
    assert_int_equal(begin_shutdown_calls, 1);
    assert_int_equal(begin_shutdown_ms, 24000);
    assert_int_equal(runtime_shutdown_calls, 1);
#endif
}

// Two signals are one shutdown: the pipe is drained and the first signal number comes back once.
// wm_wait_shutdown_signal() hands the signal out once per process, so the case runs in a child: the other
// case that waits (gate_shutdown_runs_sequence) keeps its own, untouched, copy of that state.
static void second_signal_is_one_shutdown(void **state) {
    (void)state;

    pid_t pid = fork();
    assert_true(pid >= 0);

    if (pid == 0) {
        alarm(10);   // a wait that never returns must fail the case, not hang it
        wm_handler(SIGTERM);
        wm_handler(SIGTERM);

        int signum = wm_wait_shutdown_signal();

        char byte;
        errno = 0;
        ssize_t n = read(wm_shutdown_pipe[0], &byte, 1);
        _exit((signum == SIGTERM && pipe_writes == 2 && n == -1 && errno == EAGAIN) ? 0 : 1);
    }

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
}

// The signal is handed out once per process: after returning it, a later call keeps waiting even with a new wake-up
// in the pipe. In a child, for the same reason as above; the second wait is ended by SIGALRM after 1 s.
static void wait_signal_hands_out_once(void **state) {
    (void)state;

    pid_t pid = fork();
    assert_true(pid >= 0);

    if (pid == 0) {
        alarm(10);
        wm_handler(SIGTERM);
        if (wm_wait_shutdown_signal() != SIGTERM) {
            _exit(1);
        }

        wm_handler(SIGTERM);   // a later signal: one more byte in the pipe
        alarm(1);
        wm_wait_shutdown_signal();
        _exit(2);   // returned a second time
    }

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
    if (WIFEXITED(status)) {
        fail_msg("the child exited with %d: the signal was not handed out exactly once", WEXITSTATUS(status));
    }
    assert_true(WIFSIGNALED(status));
    assert_int_equal(WTERMSIG(status), SIGALRM);
}

#ifndef CLIENT
static void *cleanup_thread(void *arg) {
    (void)arg;
    wm_cleanup();
    return NULL;
}

// Only the owner (main) thread shuts the runtime down: an exit() from any other thread leaves it to the process
// teardown (D71). The children and the PID file are handled either way.
static void cleanup_shutdowns_only_on_main_thread(void **state) {
    (void)state;
    pthread_t other;

    wm_main_thread = pthread_self();

    assert_int_equal(pthread_create(&other, NULL, cleanup_thread, NULL), 0);
    assert_int_equal(pthread_join(other, NULL), 0);

    assert_int_equal(runtime_shutdown_calls, 0);
    assert_int_equal(kill_children_calls, 1);
    assert_int_equal(delete_pid_calls, 1);

    wm_cleanup();

    assert_int_equal(runtime_shutdown_calls, 1);
    assert_int_equal(kill_children_calls, 2);
    assert_int_equal(delete_pid_calls, 2);
}
#endif

static void unknown_signal_logs(void **state) {
    (void)state;

    expect_string(__wrap__merror, formatted_msg, "unknown signal (0)");

    wm_shutdown_run(0);

    assert_int_equal(exit_calls, 0);
    assert_int_equal(stop_calls, 0);
}

// The flag must be up during the grace wait (wm_fim_query_json() and modulesSync() read it there, #40335),
// and the stop() callbacks must still run after the wait.
static void flag_up_during_grace(void **state) {
    (void)state;
    const long offsets[] = { 0, 0, 1000, 1000, 1000 };
    arm_clocks(offsets, 5);

    // As in production: the handler raised the flag before the main thread starts the sequence.
    wm_handler(SIGTERM);
    assert_int_equal(wm_shutdown_requested, 1);

    expect_sequence_logs();
    expect_value(__wrap_exit, code, EXIT_SUCCESS);

    expect_assert_failure(wm_shutdown_run(SIGTERM));

    assert_int_equal(nanosleep_calls, 1);
    assert_int_equal(flag_at_nanosleep[0], 1);
    assert_int_equal(stop_calls, 2);
    assert_int_equal(events[0], EV_NANOSLEEP);   // no stop() before the grace wait ends
}

// A signal interrupting the grace sleep does not shorten it: the remainder is slept again.
static void grace_survives_signal(void **state) {
    (void)state;
    const long offsets[] = { 0, 0, 0, 1000, 1000, 1000 };
    arm_clocks(offsets, 6);
    first_sleep_eintr = true;

    expect_sequence_logs();
    expect_value(__wrap_exit, code, EXIT_SUCCESS);

    expect_assert_failure(wm_shutdown_run(SIGTERM));

    assert_int_equal(nanosleep_calls, 2);
    assert_int_equal(nanosleep_ms[0], 1000);
    assert_int_equal(nanosleep_ms[1], 1000);
    assert_int_equal(events[0], EV_NANOSLEEP);
    assert_int_equal(events[1], EV_NANOSLEEP);
    assert_int_equal(stop_calls, 2);
    assert_int_equal(join_calls, 2);
    assert_int_equal(mono_calls, MONO_READS(6));
}

// A shutdown request seen at the startup gate runs the whole sequence, not a bare exit(0).
static void gate_shutdown_runs_sequence(void **state) {
    (void)state;
    const long offsets[] = { 0, 0, 1000, 1000, 1000 };
    arm_clocks(offsets, 5);
    gate_armed = true;

    wm_handler(SIGTERM);

    expect_any(__wrap__mdebug1, formatted_msg);   // the gate's own message
    expect_sequence_logs();
    expect_value(__wrap_exit, code, EXIT_SUCCESS);

    expect_assert_failure(wm_after_startup_gate());

    assert_int_equal(stop_calls, 2);
    assert_int_equal(join_calls, 2);
    assert_int_equal(exit_calls, 1);
#ifndef CLIENT
    assert_int_equal(begin_shutdown_calls, 1);
    assert_int_equal(runtime_shutdown_calls, 1);
#endif
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(handler_only_flags_and_wakes, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(shutdown_run_order, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(second_signal_is_one_shutdown, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(wait_signal_hands_out_once, setup_test, teardown_test),
#ifndef CLIENT
        cmocka_unit_test_setup_teardown(cleanup_shutdowns_only_on_main_thread, setup_test, teardown_test),
#endif
        cmocka_unit_test_setup_teardown(unknown_signal_logs, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(flag_up_during_grace, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(grace_survives_signal, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(gate_shutdown_runs_sequence, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
