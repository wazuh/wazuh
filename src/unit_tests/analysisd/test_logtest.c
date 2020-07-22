/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../../headers/shared.h"
#include "../../analysisd/logtest.h"

int w_logtest_init_parameters();
void *w_logtest_init();

int logtest_enabled = 1;

/* setup/teardown */



/* wraps */

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size) {
    return mock();
}

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {
    return mock();
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_pthread_mutex_init() {
    return mock();
}

int __wrap_pthread_mutex_lock() {
    return mock();
}

int __wrap_pthread_mutex_unlock() {
    return mock();
}

int __wrap_pthread_mutex_destroy() {
    return mock();
}

int __wrap_ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) {
    if (!logtest_enabled) {
        w_logtest_conf.enabled = false;
    }
    return mock();
}

OSHash *__wrap_OSHash_Create() {
    return mock_type(OSHash *);
}

int __wrap_OSHash_setSize() {
    return mock();
}

OSList *__wrap_OSList_Create() {
    return mock_type(OSList *);
}

int __wrap_OSList_SetMaxSize() {
    return mock();
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap_w_mutex_init() {
    return;
}

void __wrap_w_mutex_destroy() {
    return;
}

void __wrap_w_create_thread() {
    return;
}

int __wrap_close (int __fd) {
    return mock();
}

int __wrap_getDefine_Int() {
    return mock();
}

/* tests */

/* w_logtest_init_parameters */

void test_w_logtest_init_parameters_invalid(void **state)
{
    will_return(__wrap_ReadConfig, OS_INVALID);

    int ret = w_logtest_init_parameters();
    assert_int_equal(ret, OS_INVALID);
}

void test_w_logtest_init_parameters_done(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    int ret = w_logtest_init_parameters();
    assert_int_equal(ret, OS_SUCCESS);
}

/* w_logtest_init */
void test_w_logtest_init_error_parameters(void **state)
{
    will_return(__wrap_ReadConfig, OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "(7304): Invalid wazuh-logtest configuration");

    w_logtest_init();
}


void test_w_logtest_init_logtest_disabled(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    logtest_enabled = 0;

    expect_string(__wrap__minfo, formatted_msg, "(7201): Logtest disabled");

    w_logtest_init();

    logtest_enabled = 1;
}

void test_w_logtest_init_conection_fail(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "(7300): Unable to bind to socket '/queue/ossec/logtest'. Errno: (0) Success");

    w_logtest_init();
}

void test_w_logtest_init_OSHash_create_fail(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(7303): Failure to initialize all_sesssions hash");

    w_logtest_init();
}

// void test_w_logtest_init_done(void **state) -> Needs to implement w_logtest_main


/* w_logtest_fts_init */
void test_w_logtest_fts_init_create_list_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1290): Unable to create a new list (calloc).");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);
}

void test_w_logtest_fts_init_SetMaxSize_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 0);

    expect_string(__wrap__merror, formatted_msg, "(1292): Error setting error size.");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);
}

void test_w_logtest_fts_init_create_hash_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1295): Unable to create a new hash (calloc).");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);
}

void test_w_logtest_fts_init_setSize_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;
    OSHash *hash = (OSHash *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, hash);

    will_return(__wrap_OSHash_setSize, 0);

    expect_string(__wrap__merror, formatted_msg, "(1292): Error setting error size.");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);
}

void test_w_logtest_fts_init_success(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;
    OSHash *hash = (OSHash *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, hash);

    will_return(__wrap_OSHash_setSize, 1);

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 1);
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests w_logtest_init_parameters
        cmocka_unit_test(test_w_logtest_init_parameters_invalid),
        cmocka_unit_test(test_w_logtest_init_parameters_done),
        // Tests w_logtest_init
        cmocka_unit_test(test_w_logtest_init_error_parameters),
        cmocka_unit_test(test_w_logtest_init_logtest_disabled),
        cmocka_unit_test(test_w_logtest_init_conection_fail),
        cmocka_unit_test(test_w_logtest_init_OSHash_create_fail),
        // Tests w_logtest_fts_init
        cmocka_unit_test(test_w_logtest_fts_init_create_list_failure),
        cmocka_unit_test(test_w_logtest_fts_init_SetMaxSize_failure),
        cmocka_unit_test(test_w_logtest_fts_init_create_hash_failure),
        cmocka_unit_test(test_w_logtest_fts_init_setSize_failure),
        cmocka_unit_test(test_w_logtest_fts_init_success),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
