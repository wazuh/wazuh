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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "../headers/shared.h"

#define TEST_DAEMON "test-daemon"

/* Internals of sig_op.c exposed by WAZUH_UNIT_TESTING */
extern int sig_pipe_rd;
extern volatile int sig_pipe_wr;
extern volatile sig_atomic_t sig_received;
extern void (*volatile sig_shutdown_func)(void);
void SIGShutdown(void);
void *SIGShutdownThread(void *arg);

void __real__exit(int status);

static jmp_buf exit_jmp;
static bool real_exit = false;
static int exit_calls = 0;
static int exit_status = -1;
static int shutdown_func_calls = 0;
static int pid_file_present_in_func = 0;
static char pid_file[PATH_MAX];
static char work_dir[] = "/tmp/test_sig_op.XXXXXX";

/* Logging is irrelevant here, and the real one reads the configuration file */
void __wrap__minfo(__attribute__((unused)) const char *file, __attribute__((unused)) int line,
                   __attribute__((unused)) const char *func, __attribute__((unused)) const char *msg, ...) {}

void __wrap__merror(__attribute__((unused)) const char *file, __attribute__((unused)) int line,
                    __attribute__((unused)) const char *func, __attribute__((unused)) const char *msg, ...) {}

/* The real one reads the internal options file for the stack size */
int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    pthread_t thread;

    if (pthread_create(&thread, NULL, function_pointer, data) != 0) {
        return 0;
    }

    return pthread_detach(thread) == 0;
}

void __wrap__exit(int status) {
    if (real_exit) {
        __real__exit(status);
    }

    exit_calls++;
    exit_status = status;

    /* _exit() is noreturn: the code under test must not run past it */
    longjmp(exit_jmp, 1);
}

static void shutdown_func(void) {
    shutdown_func_calls++;
    pid_file_present_in_func = (access(pid_file, F_OK) == 0);
}

static void touch(const char *file) {
    int fd = open(file, O_CREAT | O_WRONLY, 0600);

    if (fd >= 0) {
        close(fd);
    }
}

static void child_shutdown_func(void) {
    touch("work-ran");
}

static void child_atexit(void) {
    touch("atexit-ran");
}

static bool pid_file_exists(void) {
    return access(pid_file, F_OK) == 0;
}

static int group_setup(void **state) {
    (void) state;

    if (mkdtemp(work_dir) == NULL) {
        return -1;
    }

    if (chdir(work_dir) < 0 || mkdir("var", 0700) < 0 || mkdir("var/run", 0700) < 0) {
        return -1;
    }

    snprintf(pid_file, sizeof(pid_file), "%s/%s-%d.pid", OS_PIDFILE, TEST_DAEMON, (int)getpid());

    /* Sets the PID file name HandleExit() removes */
    StartSIG(TEST_DAEMON);

    return 0;
}

static int group_teardown(void **state) {
    (void) state;
    char cmd[PATH_MAX + 16];

    snprintf(cmd, sizeof(cmd), "rm -rf %s", work_dir);
    return system(cmd);
}

static int test_setup(void **state) {
    int fds[2];

    (void) state;
    exit_calls = 0;
    exit_status = -1;
    shutdown_func_calls = 0;
    pid_file_present_in_func = 0;
    sig_received = 0;
    sig_shutdown_func = NULL;
    real_exit = false;

    if (pipe(fds) < 0) {
        return -1;
    }

    sig_pipe_rd = fds[0];
    sig_pipe_wr = fds[1];
    fcntl(sig_pipe_wr, F_SETFL, fcntl(sig_pipe_wr, F_GETFL, 0) | O_NONBLOCK);

    if (CreatePID(TEST_DAEMON, (int)getpid()) < 0) {
        return -1;
    }

    return 0;
}

static int test_teardown(void **state) {
    (void) state;

    close(sig_pipe_rd);
    close(sig_pipe_wr);
    sig_pipe_rd = -1;
    sig_pipe_wr = -1;
    unlink(pid_file);

    return 0;
}

void test_handler_only_signals(void **state) {
    char buf[4];

    (void) state;
    sig_shutdown_func = shutdown_func;

    HandleSIG(SIGTERM);

    assert_int_equal(sig_received, SIGTERM);
    assert_int_equal(read(sig_pipe_rd, buf, sizeof(buf)), 1);
    assert_int_equal(shutdown_func_calls, 0);
    assert_int_equal(exit_calls, 0);
    assert_true(pid_file_exists());
}

void test_handler_keeps_errno(void **state) {
    (void) state;
    errno = EAGAIN;

    HandleSIG(SIGINT);

    assert_int_equal(errno, EAGAIN);
}

void test_handler_ignores_second_signal(void **state) {
    char buf[4];

    (void) state;

    HandleSIG(SIGTERM);
    HandleSIG(SIGINT);

    assert_int_equal(sig_received, SIGTERM);
    assert_int_equal(read(sig_pipe_rd, buf, sizeof(buf)), 1);
    assert_int_equal(exit_calls, 0);
}

void test_shutdown_runs_work_then_removes_pid_file_and_exits(void **state) {
    (void) state;
    sig_received = SIGTERM;
    sig_shutdown_func = shutdown_func;

    if (setjmp(exit_jmp) == 0) {
        SIGShutdown();
    }

    assert_int_equal(shutdown_func_calls, 1);
    assert_true(pid_file_present_in_func);
    assert_false(pid_file_exists());
    assert_int_equal(exit_calls, 1);
    assert_int_equal(exit_status, 1);
}

void test_shutdown_without_registered_work(void **state) {
    (void) state;
    sig_received = SIGTERM;

    if (setjmp(exit_jmp) == 0) {
        SIGShutdown();
    }

    assert_int_equal(shutdown_func_calls, 0);
    assert_false(pid_file_exists());
    assert_int_equal(exit_calls, 1);
    assert_int_equal(exit_status, 1);
}

void test_thread_runs_shutdown_work_once(void **state) {
    (void) state;
    sig_shutdown_func = shutdown_func;

    /* Two wake-ups queued: the work must still run a single time */
    HandleSIG(SIGTERM);
    assert_int_equal(write(sig_pipe_wr, "", 1), 1);

    if (setjmp(exit_jmp) == 0) {
        SIGShutdownThread(NULL);
    }

    assert_int_equal(shutdown_func_calls, 1);
    assert_int_equal(exit_calls, 1);
    assert_false(pid_file_exists());
}

/* The real thread, signal and _exit() in a child: the atexit handlers must not run, the registered work and the PID file removal must */
void test_signal_ends_process_from_thread(void **state) {
    (void) state;
    int status = 0;
    pid_t pid;
    char child_pid_file[PATH_MAX];

    fflush(NULL);
    pid = fork();
    assert_true(pid >= 0);

    if (pid == 0) {
        real_exit = true;
        sig_pipe_rd = -1;
        sig_pipe_wr = -1;
        sig_received = 0;
        atexit(child_atexit);
        CreatePID(TEST_DAEMON, (int)getpid());
        StartSIGShutdownThread();
        SetSIGShutdownFunc(child_shutdown_func);
        kill(getpid(), SIGTERM);
        sleep(10);
        __real__exit(99);
    }

    assert_int_equal(waitpid(pid, &status, 0), pid);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 1);

    snprintf(child_pid_file, sizeof(child_pid_file), "%s/%s-%d.pid", OS_PIDFILE, TEST_DAEMON, (int)pid);
    assert_int_equal(access("work-ran", F_OK), 0);
    assert_int_not_equal(access("atexit-ran", F_OK), 0);
    assert_int_not_equal(access(child_pid_file, F_OK), 0);
    unlink("work-ran");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_handler_only_signals, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_handler_keeps_errno, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_handler_ignores_second_signal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_shutdown_runs_work_then_removes_pid_file_and_exits, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_shutdown_without_registered_work, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_thread_runs_shutdown_work_once, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_signal_ends_process_from_thread, test_setup, test_teardown)
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
