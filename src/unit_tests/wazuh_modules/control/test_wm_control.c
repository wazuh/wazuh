/*
 * Wazuh Module for Agent control - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <poll.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_control_wrappers.h"
#include "wm_control.h"

/* WM_CONTROL_LOGTAG expands to ARGV0 ":control".
 * For the manager build ARGV0 is "wazuh-manager-modulesd". */
#define WM_CONTROL_TEST_LOGTAG "wazuh-manager-modulesd:control"
#define WM_CONTROL_TEST_PROCESS_UID 1000

static int received_commands;
static int sent_responses;
static int closed_fds[2];
static size_t closed_fds_count;
static bool shutdown_after_credentials;

/* ------------------------------------------------------------------ */
/* Setup / teardown                                                     */
/* ------------------------------------------------------------------ */

static int setup_test_mode(void **state) {
    test_mode = 1;
    wm_shutdown_requested = 0;
    received_commands = 0;
    sent_responses = 0;
    closed_fds_count = 0;
    shutdown_after_credentials = false;
    return 0;
}

static int teardown_test_mode(void **state) {
    test_mode = 0;
    wm_shutdown_requested = 0;
    return 0;
}

int __wrap_OS_BindUnixDomainWithPerms(const char *path, int type, int max_msg_size, uid_t uid, gid_t gid, mode_t perm) {
    check_expected(path);
    check_expected(type);
    check_expected(max_msg_size);
    check_expected(uid);
    check_expected(gid);
    check_expected(perm);
    return mock_type(int);
}

uid_t __wrap_getuid(void) {
    return WM_CONTROL_TEST_PROCESS_UID;
}

int __wrap_wm_select_interruptible(int sock, fd_set *fdset) {
    check_expected(sock);
    assert_non_null(fdset);
    return mock_type(int);
}

int __wrap_accept(int sock, struct sockaddr *address, socklen_t *address_len) {
    check_expected(sock);
    assert_null(address);
    assert_null(address_len);
    return mock_type(int);
}

int __wrap_getsockopt(int socket, int level, int option, void *value, socklen_t *value_size) {
    check_expected(socket);
    check_expected(level);
    check_expected(option);
    assert_int_equal(*value_size, sizeof(struct ucred));

    struct ucred *credentials = value;
    credentials->uid = mock_type(uid_t);

    if (shutdown_after_credentials) {
        wm_shutdown_requested = 1;
    }

    return mock_type(int);
}

int __wrap_OS_RecvUnix(int socket, int size, char *buffer) {
    check_expected(socket);
    check_expected(size);

    const char *message = mock_type(const char *);
    const int length = mock_type(int);
    memcpy(buffer, message, length);
    received_commands++;
    wm_shutdown_requested = 1;
    return length;
}

int __wrap_OS_SendUnix(int socket, const char *message, int size) {
    check_expected(socket);
    check_expected(message);
    check_expected(size);
    sent_responses++;
    return mock_type(int);
}

int __wrap_close(int fd) {
    if (closed_fds_count < sizeof(closed_fds) / sizeof(closed_fds[0])) {
        closed_fds[closed_fds_count++] = fd;
    }
    return 0;
}

int __wrap_pipe(int pipefd[2]) {
    pipefd[0] = mock_type(int);
    pipefd[1] = mock_type(int);
    return mock_type(int);
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    check_expected(fds[0].fd);
    check_expected(fds[0].events);
    check_expected(nfds);
    check_expected(timeout);
    return mock_type(int);
}

int __wrap_CreateThread(void *(*function_pointer)(void *), void *data) {
    const int outcome = mock_type(int);
    if (outcome != 0) {
        function_pointer(data);
    }
    return outcome == 1;
}

static void expect_service_control_accepted(pid_t pid, int thread_outcome) {
    will_return(__wrap_pipe, 10);
    will_return(__wrap_pipe, 11);
    will_return(__wrap_pipe, 0);
    will_return(__wrap_fork, pid);

    expect_value(__wrap_poll, fds[0].fd, 10);
    expect_value(__wrap_poll, fds[0].events, POLLIN | POLLHUP);
    expect_value(__wrap_poll, nfds, 1);
    expect_value(__wrap_poll, timeout, 5000);
    will_return(__wrap_poll, 1);
    will_return(__wrap_read, "1");
    will_return(__wrap_read, 1);
    will_return(__wrap_CreateThread, thread_outcome);

    if (thread_outcome != 0) {
        expect_value(__wrap_waitpid, __pid, pid);
        expect_value(__wrap_waitpid, __options, 0);
        will_return(__wrap_waitpid, 0);
        will_return(__wrap_waitpid, pid);
    }

    if (thread_outcome != 1) {
        expect_value(__wrap_waitpid, __pid, pid);
        expect_value(__wrap_waitpid, __options, WNOHANG);
        will_return(__wrap_waitpid, 0);
        will_return(__wrap_waitpid, thread_outcome == 0 ? 0 : -1);
    }
}

static void expect_control_peer(uid_t peer_uid, int socket, int peer) {
    expect_string(__wrap__mtinfo, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Starting control thread.");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, CONTROL_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value(__wrap_wm_select_interruptible, sock, socket);
    will_return(__wrap_wm_select_interruptible, 1);

    expect_value(__wrap_accept, sock, socket);
    will_return(__wrap_accept, peer);

    expect_value(__wrap_getsockopt, socket, peer);
    expect_value(__wrap_getsockopt, level, SOL_SOCKET);
    expect_value(__wrap_getsockopt, option, SO_PEERCRED);
    will_return(__wrap_getsockopt, peer_uid);
    will_return(__wrap_getsockopt, 0);
}

/* ------------------------------------------------------------------ */
/* process_control peer authorization tests                            */
/* ------------------------------------------------------------------ */

static void test_control_peer_uid_matches_process_uid(void **state) {
    const int socket = 100;
    const int peer = 101;
    const char command[] = "unknown";

    expect_control_peer(getuid(), socket, peer);

    expect_value(__wrap_OS_RecvUnix, socket, peer);
    expect_value(__wrap_OS_RecvUnix, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, command);
    will_return(__wrap_OS_RecvUnix, strlen(command));

    expect_string(__wrap__mtdebug2, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Dispatching command: 'unknown'");
    expect_string(__wrap__mterror, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Unknown command: 'unknown'");

    expect_value(__wrap_OS_SendUnix, socket, peer);
    expect_string(__wrap_OS_SendUnix, message, "Err");
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 0);

    WM_CONTROL_CONTEXT.start(NULL);

    assert_int_equal(received_commands, 1);
    assert_int_equal(sent_responses, 1);
    assert_int_equal(closed_fds_count, 2);
    assert_int_equal(closed_fds[0], peer);
    assert_int_equal(closed_fds[1], socket);
}

static void test_control_peer_unrelated_uid_is_rejected(void **state) {
    const int socket = 100;
    const int peer = 101;

    shutdown_after_credentials = true;
    expect_control_peer(getuid() + 1, socket, peer);

    expect_string(__wrap__mtwarn, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Rejected unauthorized control socket peer.");

    WM_CONTROL_CONTEXT.start(NULL);

    assert_int_equal(received_commands, 0);
    assert_int_equal(sent_responses, 0);
    assert_int_equal(closed_fds_count, 2);
    assert_int_equal(closed_fds[0], peer);
    assert_int_equal(closed_fds[1], socket);
}

/* ------------------------------------------------------------------ */
/* wm_control_dispatch tests                                            */
/* ------------------------------------------------------------------ */

static void test_dispatch_restart(void **state) {
    char command[] = "restart";
    char *output = NULL;

    expect_string(__wrap__mtdebug2, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Dispatching command: 'restart'");
    expect_service_control_accepted(1234, true);

    size_t ret = wm_control_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok accepted");
    assert_int_equal(ret, strlen("ok accepted"));

    free(output);
}

static void test_dispatch_reload(void **state) {
    char command[] = "reload";
    char *output = NULL;

    expect_string(__wrap__mtdebug2, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Dispatching command: 'reload'");
    expect_service_control_accepted(5678, true);

    size_t ret = wm_control_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok accepted");
    assert_int_equal(ret, strlen("ok accepted"));

    free(output);
}

static void test_dispatch_restart_with_args(void **state) {
    /* Manager commands must contain only the allowlisted action. */
    char command[] = "restart somearg";
    char *output = NULL;

    expect_string(__wrap__mtwarn, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Unexpected arguments for command: 'restart'");

    size_t ret = wm_control_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err Unexpected arguments");
    assert_int_equal(ret, strlen("err Unexpected arguments"));

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

    will_return(__wrap_pipe, 10);
    will_return(__wrap_pipe, 11);
    will_return(__wrap_pipe, 0);
    will_return(__wrap_fork, -1);
    expect_string(__wrap__mterror, tag, WM_CONTROL_TEST_LOGTAG);
    expect_any(__wrap__mterror, formatted_msg);

    size_t ret = __real_wm_control_execute_action("restart", "wazuh-manager", &output);

    assert_non_null(output);
    assert_string_equal(output, "err Cannot fork");
    assert_int_equal(ret, strlen("err Cannot fork"));

    free(output);
}

static void test_execute_action_restart_accepted(void **state) {
    char *output = NULL;

    expect_service_control_accepted(1234, true);

    size_t ret = __real_wm_control_execute_action("restart", "wazuh-manager", &output);

    assert_non_null(output);
    assert_string_equal(output, "ok accepted");
    assert_int_equal(ret, strlen("ok accepted"));

    free(output);
}

static void test_execute_action_reload_accepted(void **state) {
    char *output = NULL;

    expect_service_control_accepted(5678, true);

    size_t ret = __real_wm_control_execute_action("reload", "wazuh-manager", &output);

    assert_non_null(output);
    assert_string_equal(output, "ok accepted");
    assert_int_equal(ret, strlen("ok accepted"));

    free(output);
}

static void test_execute_action_reaper_thread_fails(void **state) {
    char *output = NULL;

    expect_service_control_accepted(9012, false);
    expect_string(__wrap__mtwarn, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Cannot create service control reaper thread for PID '9012'");

    size_t ret = __real_wm_control_execute_action("restart", "wazuh-manager", &output);

    assert_non_null(output);
    assert_string_equal(output, "ok accepted");
    assert_int_equal(ret, strlen("ok accepted"));

    free(output);
}

static void test_execute_action_reaper_detach_fails(void **state) {
    char *output = NULL;

    /* Outcome 2 models a thread that ran even though CreateThread returned 0. */
    expect_service_control_accepted(3456, 2);
    expect_string(__wrap__mtwarn, tag, WM_CONTROL_TEST_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Cannot create service control reaper thread for PID '3456'");

    size_t ret = __real_wm_control_execute_action("restart", "wazuh-manager", &output);

    assert_non_null(output);
    assert_string_equal(output, "ok accepted");
    assert_int_equal(ret, strlen("ok accepted"));

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
        /* process_control peer authorization */
        cmocka_unit_test_setup_teardown(test_control_peer_uid_matches_process_uid,       setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_control_peer_unrelated_uid_is_rejected,     setup_test_mode, teardown_test_mode),
        /* wm_control_dispatch */
        cmocka_unit_test_setup_teardown(test_dispatch_restart,            setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_dispatch_reload,             setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_dispatch_restart_with_args,  setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_dispatch_unknown_command,    setup_test_mode, teardown_test_mode),
        /* wm_control_execute_action */
        cmocka_unit_test_setup_teardown(test_execute_action_fork_fails,          setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_execute_action_restart_accepted,     setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_execute_action_reload_accepted,      setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_execute_action_reaper_thread_fails,  setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_execute_action_reaper_detach_fails,  setup_test_mode, teardown_test_mode),
        /* wm_control_check_systemd */
        cmocka_unit_test_setup_teardown(test_check_systemd_no_run_dir,    setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_check_systemd_fopen_fails,   setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_check_systemd_is_systemd,    setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_check_systemd_not_systemd,   setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_check_systemd_fgets_null,    setup_test_mode, teardown_test_mode),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
