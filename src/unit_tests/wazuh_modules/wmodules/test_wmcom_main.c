/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the wazuh-modulesd local request listener (wmcom_main)
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>

#include "../../../wazuh_modules/wmodules.h"

#define TEST_SOCKET 100
#define TEST_PEER   101

static int closed_fds[2];
static size_t closed_fds_count;

// Counts every close, so an extra one fails the assertion; only the first two are kept.
int __wrap_close(int fd) {
    if (closed_fds_count < sizeof(closed_fds) / sizeof(closed_fds[0])) {
        closed_fds[closed_fds_count] = fd;
    }

    closed_fds_count++;
    return 0;
}

int __wrap_OS_BindUnixDomainWithPerms(__attribute__((unused)) const char *path,
                                      __attribute__((unused)) int type,
                                      __attribute__((unused)) int max_msg_size,
                                      __attribute__((unused)) uid_t uid,
                                      __attribute__((unused)) gid_t gid,
                                      __attribute__((unused)) mode_t perm) {
    return TEST_SOCKET;
}

int __wrap_select(__attribute__((unused)) int nfds,
                  __attribute__((unused)) fd_set *readfds,
                  __attribute__((unused)) fd_set *writefds,
                  __attribute__((unused)) fd_set *errorfds,
                  __attribute__((unused)) struct timeval *timeout) {
    return 1;
}

int __wrap_accept(int sock, __attribute__((unused)) struct sockaddr *address,
                  __attribute__((unused)) socklen_t *address_len) {
    check_expected(sock);
    return TEST_PEER;
}

int __wrap_OS_RecvSecureTCP(int sock, char *ret, uint32_t size) {
    check_expected(sock);

    const char *data = mock_type(const char *);
    if (data) {
        strncpy(ret, data, size);
    }

    const int result = mock_type(int);
    if (result == -1) {
        errno = ECONNRESET;
    }

    return result;
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void *msg) {
    check_expected(sock);
    check_expected(size);
    check_expected(msg);
    return 0;
}

static int setup(void **state) {
    (void)state;
    closed_fds_count = 0;
    return 0;
}

// The listener runs one iteration.
static void expect_client_accepted(void) {
    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");
    expect_value(__wrap_accept, sock, TEST_SOCKET);
    expect_value(__wrap_OS_RecvSecureTCP, sock, TEST_PEER);
}

static void assert_client_and_socket_closed(void) {
    assert_int_equal(closed_fds_count, 2);
    assert_int_equal(closed_fds[0], TEST_PEER);
    assert_int_equal(closed_fds[1], TEST_SOCKET);
}

static void test_wmcom_main_closes_client_on_oversize_request(void **state) {
    (void)state;

    expect_client_accepted();
    will_return(__wrap_OS_RecvSecureTCP, NULL);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg,
                  "At wmcom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
    expect_string(__wrap__mdebug1, formatted_msg, "Local server thread finished.");

    wmcom_main(NULL);

    assert_client_and_socket_closed();
}

static void test_wmcom_main_closes_client_on_receive_error(void **state) {
    (void)state;
    char expected[OS_SIZE_256];

    expect_client_accepted();
    will_return(__wrap_OS_RecvSecureTCP, NULL);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    snprintf(expected, sizeof(expected), "At wmcom_main(): OS_RecvSecureTCP(): %s", strerror(ECONNRESET));
    expect_string(__wrap__merror, formatted_msg, expected);
    expect_string(__wrap__mdebug1, formatted_msg, "Local server thread finished.");

    wmcom_main(NULL);

    assert_client_and_socket_closed();
}

static void test_wmcom_main_closes_client_on_empty_request(void **state) {
    (void)state;

    expect_client_accepted();
    will_return(__wrap_OS_RecvSecureTCP, NULL);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Empty message from local client.");
    expect_string(__wrap__mdebug1, formatted_msg, "Local server thread finished.");

    wmcom_main(NULL);

    assert_client_and_socket_closed();
}

static void test_wmcom_main_answers_and_closes_client(void **state) {
    (void)state;
    static const char EXPECTED_REPLY[] = "err Unrecognized command";

    expect_client_accepted();
    will_return(__wrap_OS_RecvSecureTCP, "bogus");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    // An unknown command falls through to the sync dispatcher, which finds no module.
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 1");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 2");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 3");
    expect_string(__wrap__merror, formatted_msg, "At modulesSync(): Unable to sync module '': (-1)");
    expect_string(__wrap__mdebug1, formatted_msg, "At WMCOM sync: Could not sync 'bogus' buffer");
    expect_string(__wrap__mdebug1, formatted_msg, "WMCOM Unrecognized command 'bogus'.");

    expect_value(__wrap_OS_SendSecureTCP, sock, TEST_PEER);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(EXPECTED_REPLY));
    expect_string(__wrap_OS_SendSecureTCP, msg, EXPECTED_REPLY);

    expect_string(__wrap__mdebug1, formatted_msg, "Local server thread finished.");

    wmcom_main(NULL);

    assert_client_and_socket_closed();
}

static void test_wmcom_main_terminates_a_full_size_request(void **state) {
    (void)state;
    static const char EXPECTED_REPLY[] = "err Unrecognized command";
    char *request = NULL;
    char *expected_sync = NULL;
    char *expected_unrecognized = NULL;
    os_calloc(OS_MAXSTR + 1, sizeof(char), request);
    os_calloc(OS_MAXSTR, sizeof(char), expected_sync);
    os_calloc(OS_MAXSTR, sizeof(char), expected_unrecognized);
    memset(request, 'x', OS_MAXSTR);

    expect_client_accepted();
    will_return(__wrap_OS_RecvSecureTCP, request);
    will_return(__wrap_OS_RecvSecureTCP, OS_MAXSTR);

    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 1");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 2");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 3");
    expect_string(__wrap__merror, formatted_msg, "At modulesSync(): Unable to sync module '': (-1)");
    // expect_string() keeps the pointer, so each expected message needs its own buffer.
    snprintf(expected_sync, OS_MAXSTR, "At WMCOM sync: Could not sync '%s' buffer", request);
    expect_string(__wrap__mdebug1, formatted_msg, expected_sync);
    snprintf(expected_unrecognized, OS_MAXSTR, "WMCOM Unrecognized command '%s'.", request);
    expect_string(__wrap__mdebug1, formatted_msg, expected_unrecognized);

    expect_value(__wrap_OS_SendSecureTCP, sock, TEST_PEER);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(EXPECTED_REPLY));
    expect_string(__wrap_OS_SendSecureTCP, msg, EXPECTED_REPLY);

    expect_string(__wrap__mdebug1, formatted_msg, "Local server thread finished.");

    wmcom_main(NULL);

    assert_client_and_socket_closed();
    os_free(expected_unrecognized);
    os_free(expected_sync);
    os_free(request);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_wmcom_main_closes_client_on_oversize_request, setup),
        cmocka_unit_test_setup(test_wmcom_main_closes_client_on_receive_error, setup),
        cmocka_unit_test_setup(test_wmcom_main_closes_client_on_empty_request, setup),
        cmocka_unit_test_setup(test_wmcom_main_answers_and_closes_client, setup),
        cmocka_unit_test_setup(test_wmcom_main_terminates_a_full_size_request, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
