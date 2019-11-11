/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"


/* redefinitons/wrapping */


cJSON * __wrap_getSyscheckConfig() {
    int option = mock_type(int);
    if (option) {
        cJSON * root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "test", "syscheck");
        return root;
    } else {
        return NULL;
    }
}


cJSON * __wrap_getRootcheckConfig() {
    int option = mock_type(int);
    if (option) {
        cJSON * root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "test", "rootcheck");
        return root;
    } else {
        return NULL;
    }
}


cJSON * __wrap_getSyscheckInternalOptions() {
    int option = mock_type(int);
    if (option) {
        cJSON * root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "test", "internal");
        return root;
    } else {
        return NULL;
    }
}

int __wrap__mwarn()
{
    return 0;
}

static int delete_string(void **state)
{
    char *data = *state;
    free(data);
    return 0;
}


/* tests */


void test_syscom_dispatch_getconfig(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "getconfig args";
    char * output;

    ret = syscom_dispatch(command, &output);
    *state = output;

    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal(ret, 35);
}


void test_syscom_dispatch_getconfig_noargs(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "getconfig";
    char * output;

    ret = syscom_dispatch(command, &output);
    *state = output;

    assert_string_equal(output, "err SYSCOM getconfig needs arguments");
    assert_int_equal(ret, 36);
}


void test_syscom_dispatch_dbsync(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "dbsync args";

    ret = syscom_dispatch(command, NULL);

    assert_int_equal(ret, 0);
}


void test_syscom_dispatch_dbsync_noargs(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "dbsync";

    ret = syscom_dispatch(command, NULL);

    assert_int_equal(ret, 0);
}


void test_syscom_dispatch_restart(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "restart";

    ret = syscom_dispatch(command, NULL);

    assert_int_equal(ret, 0);
}


void test_syscom_dispatch_getconfig_unrecognized(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "invalid";
    char * output;

    ret = syscom_dispatch(command, &output);
    *state = output;

    assert_string_equal(output, "err Unrecognized command");
    assert_int_equal(ret, 24);
}


void test_syscom_getconfig_syscheck(void **state)
{
    (void) state;
    size_t ret;

    char * section = "syscheck";
    char * output;

    will_return(__wrap_getSyscheckConfig, 1);
    ret = syscom_getconfig(section, &output);
    *state = output;

    assert_string_equal(output, "ok {\"test\":\"syscheck\"}");
    assert_int_equal(ret, 22);
}


void test_syscom_getconfig_syscheck_failure(void **state)
{
    (void) state;
    size_t ret;

    char * section = "syscheck";
    char * output;

    will_return(__wrap_getSyscheckConfig, 0);
    ret = syscom_getconfig(section, &output);
    *state = output;

    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal(ret, 35);
}


void test_syscom_getconfig_rootcheck(void **state)
{
    (void) state;
    size_t ret;

    char * section = "rootcheck";
    char * output;

    will_return(__wrap_getRootcheckConfig, 1);
    ret = syscom_getconfig(section, &output);
    *state = output;

    assert_string_equal(output, "ok {\"test\":\"rootcheck\"}");
    assert_int_equal(ret, 23);
}


void test_syscom_getconfig_rootcheck_failure(void **state)
{
    (void) state;
    size_t ret;

    char * section = "rootcheck";
    char * output;

    will_return(__wrap_getRootcheckConfig, 0);
    ret = syscom_getconfig(section, &output);
    *state = output;

    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal(ret, 35);
}


void test_syscom_getconfig_internal(void **state)
{
    (void) state;
    size_t ret;

    char * section = "internal";
    char * output;

    will_return(__wrap_getSyscheckInternalOptions, 1);
    ret = syscom_getconfig(section, &output);
    *state = output;

    assert_string_equal(output, "ok {\"test\":\"internal\"}");
    assert_int_equal(ret, 22);
}


void test_syscom_getconfig_internal_failure(void **state)
{
    (void) state;
    size_t ret;

    char * section = "internal";
    char * output;

    will_return(__wrap_getSyscheckInternalOptions, 0);
    ret = syscom_getconfig(section, &output);
    *state = output;

    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal(ret, 35);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_noargs, delete_string),
        cmocka_unit_test(test_syscom_dispatch_dbsync),
        cmocka_unit_test(test_syscom_dispatch_dbsync_noargs),
        cmocka_unit_test(test_syscom_dispatch_restart),
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_unrecognized, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_syscheck, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_syscheck_failure, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_rootcheck, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_rootcheck_failure, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_internal, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_internal_failure, delete_string),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
