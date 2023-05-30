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
#include <string.h>

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/syscheckd/config_wrappers.h"
#include "../wrappers/wazuh/syscheckd/fim_sync_wrappers.h"
#include "../../syscheckd/include/syscheck.h"
#include "../../config/syscheck-config.h"


/* redefinitons/wrapping */

static int delete_string(void **state)
{
    char *data = *state;
    free(data);
    return 0;
}


/* tests */


void test_syscom_dispatch_getconfig_agent(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "syscheck getconfig args";
    char * output;

    expect_string(__wrap__mdebug1, formatted_msg, "(6283): At SYSCOM getconfig: Could not get 'args' section.");

    ret = syscom_dispatch(command, &output);
    *state = output;

    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal(ret, 35);
}

void test_syscom_dispatch_getconfig_manager(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "getconfig args";
    char * output;

    expect_string(__wrap__mdebug1, formatted_msg, "(6283): At SYSCOM getconfig: Could not get 'args' section.");

    ret = syscom_dispatch(command, &output);
    *state = output;

    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal(ret, 35);
}


void test_syscom_dispatch_getconfig_noargs(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "syscheck getconfig";
    char * output;

    expect_string(__wrap__mdebug1, formatted_msg, "(6281): SYSCOM getconfig needs arguments.");

    ret = syscom_dispatch(command, &output);
    *state = output;

    assert_string_equal(output, "err SYSCOM getconfig needs arguments");
    assert_int_equal(ret, 36);
}


void test_syscom_dispatch_dbsync(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "fim_file dbsync args";
    char *output;

    expect_string(__wrap_fim_sync_push_msg, msg, "fim_file dbsync args");

    ret = syscom_dispatch(command, &output);

    assert_int_equal(ret, 0);
}


void test_syscom_dispatch_dbsync_noargs(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "fim_file dbsync";
    char *output;

    expect_string(__wrap_fim_sync_push_msg, msg, "fim_file dbsync");

    ret = syscom_dispatch(command, &output);

    assert_int_equal(ret, 0);
}


void test_syscom_dispatch_restart_agent(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "syscheck restart";
    char *output;

    ret = syscom_dispatch(command, &output);

    assert_int_equal(ret, 0);
}

void test_syscom_dispatch_restart_manager(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "restart";
    char *output;

    ret = syscom_dispatch(command, &output);

    assert_int_equal(ret, 0);
}


void test_syscom_dispatch_getconfig_unrecognized(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "invalid";
    char * output;

    expect_string(__wrap__mdebug1, formatted_msg, "(6282): SYSCOM Unrecognized command 'invalid'");

    ret = syscom_dispatch(command, &output);
    *state = output;

    assert_string_equal(output, "err Unrecognized command");
    assert_int_equal(ret, 24);
}

void test_syscom_dispatch_null_command(void **state)
{
    char * output;

    expect_assert_failure(syscom_dispatch(NULL, &output));
}

void test_syscom_dispatch_null_output(void **state)
{
    char command[] = "invalid";

    expect_assert_failure(syscom_dispatch(command, NULL));
}

void test_syscom_getconfig_syscheck(void **state)
{
    (void) state;
    size_t ret;

    char * section = "syscheck";
    char * output;

    cJSON * root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "test", "syscheck");

    will_return(__wrap_getSyscheckConfig, root);
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

    will_return(__wrap_getSyscheckConfig, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "(6283): At SYSCOM getconfig: Could not get 'syscheck' section.");

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

    cJSON * root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "test", "rootcheck");

    will_return(__wrap_getRootcheckConfig, root);
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

    will_return(__wrap_getRootcheckConfig, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "(6283): At SYSCOM getconfig: Could not get 'rootcheck' section.");

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

    cJSON * root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "test", "internal");

    will_return(__wrap_getSyscheckInternalOptions, root);
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

    will_return(__wrap_getSyscheckInternalOptions, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "(6283): At SYSCOM getconfig: Could not get 'internal' section.");

    ret = syscom_getconfig(section, &output);
    *state = output;

    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal(ret, 35);
}

void test_syscom_getconfig_null_section(void **state)
{
    char * output;

    expect_assert_failure(syscom_getconfig(NULL, &output));
}

void test_syscom_getconfig_null_output(void **state)
{
    char * section = "internal";

    expect_assert_failure(syscom_getconfig(section, NULL));
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_agent, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_manager, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_noargs, delete_string),
        cmocka_unit_test(test_syscom_dispatch_dbsync),
        cmocka_unit_test(test_syscom_dispatch_dbsync_noargs),
        cmocka_unit_test(test_syscom_dispatch_restart_agent),
        cmocka_unit_test(test_syscom_dispatch_restart_manager),
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_unrecognized, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_null_command, delete_string),
        cmocka_unit_test(test_syscom_dispatch_null_output),
        cmocka_unit_test_teardown(test_syscom_getconfig_syscheck, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_syscheck_failure, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_rootcheck, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_rootcheck_failure, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_internal, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_internal_failure, delete_string),
        cmocka_unit_test(test_syscom_getconfig_null_section),
        cmocka_unit_test(test_syscom_getconfig_null_output),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
