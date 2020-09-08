/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../headers/shared.h"

#include "../wrappers/common.h"

/* Define values may be changed */

#define MAX_ATTEMPTS 100
#define SOCKET_SIZE 1
#define ERRNO ENOTSOCK

/* Redefinitons/wrapping */

void __wrap__merror(const char * file, int line, const char * func, const char * msg, ...){
    char formatted_msg[OS_SIZE_64];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_SIZE_64, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char * msg, ...){
    char formatted_msg[OS_SIZE_1024];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, sizeof(formatted_msg), msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_OS_getsocketsize(int ossock) {
    return SOCKET_SIZE;
}

void __wrap_sleep(unsigned int seconds){};

int __wrap_OS_BindUnixDomain(const char * path, int type, int max_msg_size){
    return (int) mock();
}

int __wrap_OS_ConnectUnixDomain(const char * path, int type, int max_msg_size){
    return (int) mock();
}

/* Tests */

void test_start_mq_read_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = READ;
    char * path = "/test";

    int ret = 0;

    will_return(__wrap_OS_BindUnixDomain, 0);

    ret = StartMQ(path, type, n_attempts);
    assert_false(ret);
}

void test_start_mq_read_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = READ;
    char * path = "/test";

    int ret = 0;

    will_return(__wrap_OS_BindUnixDomain, -1);

    ret = StartMQ(path, type, n_attempts);
    assert_int_equal(ret, -1);

}

void test_start_mq_write_simple_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 1;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[2][OS_SIZE_64];

    will_return(__wrap_OS_ConnectUnixDomain, 0);

    snprintf(messages[0], OS_SIZE_64,"Connected succesfully to '%s' after %d attempts", path, 0);
    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);

    snprintf(messages[1], OS_SIZE_64, "(unix_domain) Maximum send buffer set to: '%d'.",SOCKET_SIZE);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);

    ret = StartMQ(path, type, n_attempts);
    assert_false(ret);
}

void test_start_mq_write_simple_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 1;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char expected_str[OS_SIZE_64];
    errno = ERRNO;

    will_return(__wrap_OS_ConnectUnixDomain, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Can't connect to '/test': Socket operation on non-socket (88). Attempt: 1");

    snprintf(expected_str, OS_SIZE_64, "(1210): Queue '%s' not accessible: '%s'", path,strerror(errno));
    expect_string(__wrap__merror, formatted_msg, expected_str);

    ret = StartMQ(path, type, n_attempts);
    assert_int_equal(ret, -1);
}

void test_start_mq_write_multiple_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 5;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[n_attempts+1][OS_SIZE_1024];

    errno = ERRNO;

    for (int i = 0; i < n_attempts - 1; i++) {
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        snprintf(messages[i], OS_SIZE_1024, "Can't connect to '/test': Socket operation on non-socket (88). Attempt: %d", i + 1);
        expect_string(__wrap__mdebug1, formatted_msg, messages[i]);
    }
    will_return(__wrap_OS_ConnectUnixDomain, 0);

    snprintf(messages[n_attempts - 1], OS_SIZE_1024,"Connected succesfully to '%s' after %d attempts", path, n_attempts - 1);
    expect_string(__wrap__mdebug1, formatted_msg, messages[n_attempts - 1]);

    snprintf(messages[n_attempts], OS_SIZE_1024,"(unix_domain) Maximum send buffer set to: '%d'.", SOCKET_SIZE);
    expect_string(__wrap__mdebug1, formatted_msg, messages[n_attempts]);

    ret = StartMQ(path, type, n_attempts);
    assert_false(ret);
}

void test_start_mq_write_multiple_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 10;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[n_attempts][OS_SIZE_1024];
    char expected_str[OS_SIZE_64];

    for (int i = 0; i <= n_attempts - 1; i++) {
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        snprintf(messages[i], OS_SIZE_1024, "Can't connect to '/test': Socket operation on non-socket (88). Attempt: %d", i + 1);
        expect_string(__wrap__mdebug1, formatted_msg, messages[i]);
    }

    snprintf(expected_str, OS_SIZE_64, "(1210): Queue '%s' not accessible: '%s'", path,strerror(errno));
    expect_string(__wrap__merror, formatted_msg, expected_str);

    ret = StartMQ(path, type, n_attempts);
    assert_int_equal(ret, -1);
}

void test_start_mq_write_inf_success(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[MAX_ATTEMPTS + 1][OS_SIZE_1024];

    for (int i = 0; i < MAX_ATTEMPTS - 1; i++) {
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        sprintf(messages[i], "Can't connect to '/test': Socket operation on non-socket (88). Attempt: %d", i + 1);
        expect_string(__wrap__mdebug1, formatted_msg, messages[i]);
    }
    will_return(__wrap_OS_ConnectUnixDomain, 0);

    snprintf(messages[MAX_ATTEMPTS - 1], OS_SIZE_1024,"Connected succesfully to '%s' after %d attempts", path, MAX_ATTEMPTS - 1);
    expect_string(__wrap__mdebug1, formatted_msg, messages[MAX_ATTEMPTS - 1]);

    snprintf(messages[MAX_ATTEMPTS], OS_SIZE_1024,"(unix_domain) Maximum send buffer set to: '%d'.", SOCKET_SIZE);
    expect_string(__wrap__mdebug1, formatted_msg, messages[MAX_ATTEMPTS]);

    ret = StartMQ(path, type, n_attempts);
    assert_false(ret);
}

void test_start_mq_write_inf_fail(void ** state){
    (void)state; // Unused

    /* Function parameters */
    short int n_attempts = 0;
    short int type = WRITE;
    char * path = "/test";

    int ret = 0;
    char messages[MAX_ATTEMPTS][OS_SIZE_1024];

    for (int i = 0; i <= MAX_ATTEMPTS - 1; i++) {
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        snprintf(messages[i], OS_SIZE_1024, "Can't connect to '/test': Socket operation on non-socket (88). Attempt: %d", i + 1);
        expect_string(__wrap__mdebug1, formatted_msg, messages[i]);
    }
    /* Breaking the infinite loop */
    will_return(__wrap_OS_ConnectUnixDomain, 0);
    /* Ignoring output */
    expect_any_always(__wrap__mdebug1, formatted_msg);

    ret = StartMQ(path, type, n_attempts);
}

// Main test function

int main(void){
    const struct CMUnitTest tests[] = {
       cmocka_unit_test(test_start_mq_read_success),
       cmocka_unit_test(test_start_mq_read_fail),
       cmocka_unit_test(test_start_mq_write_simple_success),
       cmocka_unit_test(test_start_mq_write_simple_fail),
       cmocka_unit_test(test_start_mq_write_multiple_success),
       cmocka_unit_test(test_start_mq_write_multiple_fail),
       cmocka_unit_test(test_start_mq_write_inf_success),
       cmocka_unit_test(test_start_mq_write_inf_fail)
       };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
