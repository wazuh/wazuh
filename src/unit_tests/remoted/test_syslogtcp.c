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
#include <errno.h>
#include <string.h>

#include "../../remoted/remoted.h"
#include "../../headers/shared.h"
#include "../../os_net/os_net.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"


/* Forward declarations */
size_t w_get_pri_header_len(const char * syslog_msg);
void HandleClient(int client_socket, char * srcip);

#define TEST_SRCIP "1.2.3.4"

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* Wrappers */

/* Buffer HandleClient() passes to recv(), and its first bytes as they were right before it is released */
static char * recv_buffer;
static char buffer_at_exit[16];

ssize_t __wrap_recv(int sockfd, void * buf, size_t len, int flags) {
    const ssize_t ret = mock();
    const char * data = mock_type(const char *);

    check_expected(len);
    if (recv_buffer == NULL) {
        recv_buffer = buf; /* The first read starts at the beginning of the buffer */
    }

    if (ret > 0) {
        memcpy(buf, data, ret);
    } else if (ret < 0) {
        errno = mock_type(int);
    }

    return ret;
}

int __wrap_CreatePID(const char * name, int pid) {
    return 0;
}

int __wrap_DeletePID(const char * name) {
    /* HandleClient() frees its buffer right after this call, so this is the last chance to read it */
    memcpy(buffer_at_exit, recv_buffer, sizeof(buffer_at_exit));
    return 0;
}

static void expect_recv(ssize_t ret, const char * data, int err, size_t expected_len) {
    will_return(__wrap_recv, ret);
    will_return(__wrap_recv, data);
    if (ret < 0) {
        will_return(__wrap_recv, err);
    }
    expect_value(__wrap_recv, len, expected_len);
}

static int test_setup(void ** state) {
    recv_buffer = NULL;
    memset(buffer_at_exit, 0, sizeof(buffer_at_exit));
    return 0;
}

/* Tests */

// w_get_pri_header_len

void test_w_get_pri_header_len_null(void ** state) {

    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len(NULL);

    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_no_pri(void ** state) {

    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len("test log");

    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_w_pri(void ** state) {

    const ssize_t expected_retval = 4;
    ssize_t retval = w_get_pri_header_len("<18>test log");

    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_not_end(void ** state) {

    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len("<18 test log");

    assert_int_equal(retval, expected_retval);
}

// HandleClient

void test_HandleClient_recv_error_first_read(void ** state) {
    char expected[OS_MAXSTR];

    /* A failed recv() must not move the buffer length: the next write used to land before the buffer */
    expect_recv(-1, NULL, ECONNRESET, OS_MAXSTR);
    snprintf(expected, sizeof(expected), RECV_ERROR, strerror(ECONNRESET), ECONNRESET);
    expect_string(__wrap__merror, formatted_msg, expected);

    HandleClient(-1, TEST_SRCIP);
}

void test_HandleClient_recv_error_keeps_received_data(void ** state) {
    char expected[OS_MAXSTR];

    expect_recv(5, "abcde", 0, OS_MAXSTR);
    expect_string(__wrap__mdebug2, formatted_msg, "Received 5 bytes from '" TEST_SRCIP "'");
    /* The second read must be offered the space left after the 5 bytes already stored */
    expect_recv(-1, NULL, ECONNRESET, OS_MAXSTR - 5);
    snprintf(expected, sizeof(expected), RECV_ERROR, strerror(ECONNRESET), ECONNRESET);
    expect_string(__wrap__merror, formatted_msg, expected);

    HandleClient(-1, TEST_SRCIP);

    /* The error used to shorten data_len and the terminator overwrote the last received byte */
    assert_memory_equal(buffer_at_exit, "abcde", 5);
}

void test_HandleClient_connection_closed(void ** state) {
    expect_recv(5, "abcde", 0, OS_MAXSTR);
    expect_string(__wrap__mdebug2, formatted_msg, "Received 5 bytes from '" TEST_SRCIP "'");
    expect_recv(0, NULL, 0, OS_MAXSTR - 5);

    HandleClient(-1, TEST_SRCIP);

    assert_memory_equal(buffer_at_exit, "abcde", 5);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_get_pri_header_len
        cmocka_unit_test(test_w_get_pri_header_len_null),
        cmocka_unit_test(test_w_get_pri_header_len_no_pri),
        cmocka_unit_test(test_w_get_pri_header_len_w_pri),
        cmocka_unit_test(test_w_get_pri_header_len_not_end),

        // Test HandleClient
        cmocka_unit_test_setup(test_HandleClient_recv_error_first_read, test_setup),
        cmocka_unit_test_setup(test_HandleClient_recv_error_keeps_received_data, test_setup),
        cmocka_unit_test_setup(test_HandleClient_connection_closed, test_setup),

    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
