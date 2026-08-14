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
#include "../wrappers/wazuh/shared_modules/agent_sync_protocol_wrappers.h"
#include "syscheck.h"
#include "syscheck-config.h"


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

    ret = syscom_dispatch(command, strlen(command), &output);
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

    ret = syscom_dispatch(command, strlen(command), &output);
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

    ret = syscom_dispatch(command, strlen(command), &output);
    *state = output;

    assert_string_equal(output, "err SYSCOM getconfig needs arguments");
    assert_int_equal(ret, 36);
}


void test_syscom_dispatch_getconfig_unrecognized(void **state)
{
    (void) state;
    size_t ret;

    char command[] = "invalid";
    char * output;

    expect_string(__wrap__mdebug1, formatted_msg, "(6282): SYSCOM Unrecognized command 'invalid'");

    ret = syscom_dispatch(command, strlen(command), &output);
    *state = output;

    assert_string_equal(output, "err Unrecognized command");
    assert_int_equal(ret, 24);
}

void test_syscom_dispatch_null_command(void **state)
{
    char * output;

    expect_assert_failure(syscom_dispatch(NULL, 0, &output));
}

void test_syscom_dispatch_null_output(void **state)
{
    char command[] = "invalid";

    expect_assert_failure(syscom_dispatch(command, strlen(command), NULL));
}

void test_syscom_dispatch_sync_success(void **state)
{
    (void) state;
    size_t ret;
    char command[] = "fim_sync test-data";
    char *output;

    syscheck.enable_synchronization = 1;
    syscheck.sync_handle = (AgentSyncProtocolHandle*)0x1234;

    expect_value(__wrap_asp_parse_response_buffer, handle, syscheck.sync_handle);
    expect_memory(__wrap_asp_parse_response_buffer, data, "test-data", strlen("test-data"));
    expect_value(__wrap_asp_parse_response_buffer, length, strlen("test-data"));
    will_return(__wrap_asp_parse_response_buffer, true);

    ret = syscom_dispatch(command, strlen(command), &output);

    assert_int_equal(ret, 0);
}

void test_syscom_dispatch_sync_disabled(void **state)
{
    (void) state;
    size_t ret;
    char command[] = "fim_sync something";
    char *output;

    syscheck.enable_synchronization = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "FIM synchronization is disabled");

    ret = syscom_dispatch(command, strlen(command), &output);
    *state = output;

    assert_string_equal(output, "err FIM synchronization is disabled");
    assert_int_equal(ret, 35);
}

void test_syscom_dispatch_sync_error(void **state)
{
    (void) state;
    size_t ret;
    char command[] = "fim_sync test-data";
    char *output;

    syscheck.enable_synchronization = 1;
    syscheck.sync_handle = (AgentSyncProtocolHandle*)0x1234;

    expect_value(__wrap_asp_parse_response_buffer, handle, syscheck.sync_handle);
    expect_memory(__wrap_asp_parse_response_buffer, data, "test-data", strlen("test-data"));
    expect_value(__wrap_asp_parse_response_buffer, length, strlen("test-data"));
    will_return(__wrap_asp_parse_response_buffer, false);

    expect_string(__wrap__mdebug1, formatted_msg, "WMCOM Error syncing module");

    ret = syscom_dispatch(command, strlen(command), &output);
    *state = output;

    assert_string_equal(output, "err Error syncing module");
    assert_int_equal(ret, 24);
}

void test_syscom_dispatch_sync_destroyed_handle(void **state)
{
    (void) state;
    size_t ret;
    char command[] = "fim_sync test-data";
    char *output;

    syscheck.enable_synchronization = 1;
    // The shutdown teardown destroyed the handle: the response must be dropped
    // without touching the sync protocol (asp_parse_response_buffer is not called).
    syscheck.sync_handle = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "WMCOM Error syncing module");

    ret = syscom_dispatch(command, strlen(command), &output);
    *state = output;

    assert_string_equal(output, "err Error syncing module");
    assert_int_equal(ret, 24);
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



void test_syscom_dispatch_getallconfig(void **state)
{
    (void) state;
    size_t ret;

    /* "getallconfig" does not start with HC_GETCONFIG, so the outer prefix
     * guard in syscom_dispatch has to name it explicitly. When it did not, the
     * whole daemon answered "err Unrecognized command" and fim went missing
     * from every /config document the agent pushed (#37843). */
    char command[] = "getallconfig";
    char * output = NULL;

    will_return(__wrap_getSyscheckConfig, NULL);
    will_return(__wrap_getRootcheckConfig, NULL);
    will_return(__wrap_getSyscheckInternalOptions, NULL);

    ret = syscom_dispatch(command, strlen(command), &output);
    *state = output;

    /* Every getter empty still has to be a report, not a rejection: the caller
     * tells "this daemon reported nothing" from "this daemon is unreachable". */
    assert_string_equal(output, "ok {}");
    assert_int_equal(ret, strlen(output));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_agent, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_manager, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_noargs, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_getconfig_unrecognized, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_null_command, delete_string),
        cmocka_unit_test(test_syscom_dispatch_null_output),
        cmocka_unit_test_teardown(test_syscom_dispatch_sync_success, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_sync_disabled, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_sync_error, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_sync_destroyed_handle, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_syscheck, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_syscheck_failure, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_rootcheck, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_rootcheck_failure, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_internal, delete_string),
        cmocka_unit_test_teardown(test_syscom_getconfig_internal_failure, delete_string),
        cmocka_unit_test_teardown(test_syscom_dispatch_getallconfig, delete_string),
        cmocka_unit_test(test_syscom_getconfig_null_section),
        cmocka_unit_test(test_syscom_getconfig_null_output),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
