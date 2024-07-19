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

#include "../../headers/shared.h"
#include "../../logcollector/state.h"
#include "../../logcollector/logcollector.h"
#include "../../wazuh_modules/wmodules.h"
#include "../../os_net/os_net.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"

#include "json_data.h"

size_t lccom_getstate(char ** output, bool getNextPage);
uint16_t getJsonStr64kBlockFromLatestIndex(char **output, bool getNextPage);
void addStartandEndTagsToJsonStrBlock(char *buffJson, char *headerGlobal, char *headerInterval, char *headerData, size_t LenHeaderInterval, size_t LenHeaderData, size_t LenHeaderGlobal, size_t counter, bool getNextPage);
bool isJsonUpdated(void);

/* setup/teardown */

static int setup_group(void ** state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void ** state) {
    test_mode = 0;
    return 0;
}

/* wraps */

cJSON * __wrap_w_logcollector_state_get() {
    return mock_type(cJSON *);
}

double __wrap_difftime (time_t __time1, time_t __time0) {
    return mock();
}

/* tests */

/* lccom_getstate */

void test_lccom_getstate_ok(void ** state) {

    char * output = NULL;
    char json[] = "test json";
    state_interval = true;

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 2);
    will_return(__wrap_w_logcollector_state_get, (cJSON *) 3);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_string(__wrap_cJSON_AddFalseToObject, name, "remaining");
    will_return(__wrap_cJSON_AddFalseToObject, NULL);

    expect_string(__wrap_cJSON_AddFalseToObject, name, "json_updated");
    will_return(__wrap_cJSON_AddFalseToObject, NULL);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, 0);

    will_return(__wrap_cJSON_PrintUnformatted, json);
    expect_function_call(__wrap_cJSON_Delete);

    size_t retval = lccom_getstate(&output, false);

    assert_int_equal(strlen(json), retval);
    assert_string_equal(json, output);
}

void test_lccom_getstate_null(void ** state) {

    char * output = NULL;
    char json[] = "test json";
    state_interval = true;

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 2);
    will_return(__wrap_w_logcollector_state_get, NULL);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_string(__wrap_cJSON_AddObjectToObject, name, "data");
    expect_value(__wrap_cJSON_AddObjectToObject, object, (cJSON *) 2);
    will_return(__wrap_cJSON_AddObjectToObject, NULL);

    expect_string(__wrap_cJSON_AddStringToObject, name, "message");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Statistics unavailable");
    will_return(__wrap_cJSON_AddStringToObject, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "At LCCOM getstate: Statistics unavailable");

    will_return(__wrap_cJSON_PrintUnformatted, json);
    expect_function_call(__wrap_cJSON_Delete);

    size_t retval = lccom_getstate(&output, false);

    assert_int_equal(strlen(json), retval);
    assert_string_equal(json, output);
}


void _test_lccom_getstate_tmp (char *fullJson, char *ExpectedBlock, bool getNextPage){
    char * output = NULL;
    char *json = NULL;
    os_strdup(fullJson, json);
    state_interval = true;
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 2);
    will_return(__wrap_w_logcollector_state_get, (cJSON *) 3);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_string(__wrap_cJSON_AddFalseToObject, name, "remaining");
    will_return(__wrap_cJSON_AddFalseToObject, NULL);

    expect_string(__wrap_cJSON_AddFalseToObject, name, "json_updated");
    will_return(__wrap_cJSON_AddFalseToObject, NULL);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, 0);

    will_return(__wrap_cJSON_PrintUnformatted, json);
    expect_function_call(__wrap_cJSON_Delete);

    if (strstr(fullJson, outjson2) == NULL) {
        expect_string(__wrap_stat, __file, "var/run/wazuh-logcollector.state");
        will_return(__wrap_stat, &stat_buf);
        will_return(__wrap_stat, 0);
        will_return(__wrap_difftime, 10);
        will_return(__wrap_strftime,"Wed Dec 31 19:00:00 1969");
        will_return(__wrap_strftime, 20);
        expect_string(__wrap__mdebug2, formatted_msg, " Wed Dec 31 19:00:00 1969 var/run/wazuh-logcollector.state");
    }

    size_t retval = lccom_getstate(&output, getNextPage);
    assert_int_equal(strlen(output), retval);
    assert_string_equal(ExpectedBlock, output);
    os_free(output);
}


void test_lccom_getstate_first_json_block_greather_than_64k(void ** state) {
    _test_lccom_getstate_tmp (global_outjson, outjson_block1, false);
}

void test_lccom_getstate_second_json_block_greather_than_64k(void ** state) {
    _test_lccom_getstate_tmp (global_outjson, outjson_block2, true);
}

void test_lccom_getstate_third_json_block_greather_than_64k(void ** state) {
    _test_lccom_getstate_tmp (global_outjson, outjson_block3, true);
}

void test_lccom_getstate_end_json_block_lower_than_64k(void ** state) {
   _test_lccom_getstate_tmp (global_outjson, outjson_block4, true);
}

void test_lccom_getstate_first_json_block_greather_than_64k_case1(void ** state) {
   _test_lccom_getstate_tmp (outjson1, outjson_block_case_1, false);
}

void test_lccom_getstate_first_json_block_lower_than_64k_case2(void ** state) {
   _test_lccom_getstate_tmp (outjson2, outjson_block_case_2, false);
}

void test_lccom_getstate_first_json_block_lower_than_64k_case5(void ** state) {
   _test_lccom_getstate_tmp (outjson5, outjson_block_case_5, false);
}

void test_lccom_getstate_first_json_block_lower_than_64k_case5_block1(void ** state) {
   _test_lccom_getstate_tmp (outjson5, outjson_block_case_5_1, true);
}

void test_lccom_getstate_first_json_block_lower_than_64k_case6(void ** state) {
   _test_lccom_getstate_tmp (outjson6, outjson_block_case_6, false);
}

void test_lccom_getstate_first_json_block_lower_than_64k_case6_block1(void ** state) {
   _test_lccom_getstate_tmp (outjson6, outjson_block_case_6_1, true);
}

void test_lccom_getstate_first_json_block_no_global(void ** state) {
    expect_string(__wrap__mwarn, formatted_msg, "'global' tag no found in logcollector JSON stats");
    addStartandEndTagsToJsonStrBlock(outjson_no_global, "{\"global\":{\"start\":", "\"interval\":{\"start\":", "{\"error\":0,\"data\":{\"global\":{\"start\":", 0, 0, 0, 0, false);
    assert_string_equal(outjson_no_global, outjson_no_global);
}

void test_lccom_getJsonStr64kBlockFromLatestIndex(void ** state) {
    char * output = NULL;
    char *json = NULL;
    os_strdup(outjson2, json);

    size_t retval = getJsonStr64kBlockFromLatestIndex(&json, false);
    assert_int_equal(strlen(json), retval);
    assert_string_equal(outjson2, json);
    os_free(json);
}

void test_lccom_isJsonUpdated(void ** state) {
    struct stat stat_buf = { .st_mode = 0040000 };
    expect_string(__wrap_stat, __file, "var/run/wazuh-logcollector.state");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);
    will_return(__wrap_difftime, 10);
    will_return(__wrap_strftime,"Wed Dec 31 19:00:00 1969");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mdebug2, formatted_msg, " Wed Dec 31 19:00:00 1969 var/run/wazuh-logcollector.state");
    size_t retval = isJsonUpdated();
}

void test_lccom_dispatch_getconfig_ok() {
    char * command = NULL;
    char * output = NULL;

    os_strdup("getconfig test", command);

    expect_string(__wrap__mdebug1, formatted_msg, "At LCCOM getconfig: Could not get 'test' section");

    size_t retval = lccom_dispatch(command, &output);

    assert_int_equal(retval, 35);
    assert_string_equal(output, "err Could not get requested section");

    os_free(command);
    os_free(output);
}

void test_lccom_dispatch_getconfig_err() {
    char * command = NULL;
    char * output = NULL;

    os_strdup("getconfig", command);

    expect_string(__wrap__mdebug1, formatted_msg, "LCCOM getconfig needs arguments.");

    size_t retval = lccom_dispatch(command, &output);

    assert_int_equal(retval, 35);
    assert_string_equal(output, "err LCCOM getconfig needs arguments");

    os_free(command);
    os_free(output);
}

void test_lccom_dispatch_getstate() {
    char * command = NULL;
    char * output = NULL;
    char json[] = "test json";
    state_interval = true;

    os_strdup("getstate", command);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 2);
    will_return(__wrap_w_logcollector_state_get, (cJSON *) 3);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_string(__wrap_cJSON_AddFalseToObject, name, "remaining");
    will_return(__wrap_cJSON_AddFalseToObject, NULL);

    expect_string(__wrap_cJSON_AddFalseToObject, name, "json_updated");
    will_return(__wrap_cJSON_AddFalseToObject, NULL);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, 0);

    will_return(__wrap_cJSON_PrintUnformatted, strdup(json));
    expect_function_call(__wrap_cJSON_Delete);

    size_t retval = lccom_dispatch(command, &output);

    assert_int_equal(retval, 9);
    assert_string_equal(output, "test json");

    os_free(command);
    os_free(output);
}

void test_lccom_dispatch_getstate_next() {
    char * command = NULL;
    char * output = NULL;
    char json[] = "test json";
    state_interval = true;

    os_strdup("getstate next", command);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 2);
    will_return(__wrap_w_logcollector_state_get, (cJSON *) 3);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_string(__wrap_cJSON_AddFalseToObject, name, "remaining");
    will_return(__wrap_cJSON_AddFalseToObject, NULL);

    expect_string(__wrap_cJSON_AddFalseToObject, name, "json_updated");
    will_return(__wrap_cJSON_AddFalseToObject, NULL);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, 0);

    will_return(__wrap_cJSON_PrintUnformatted, strdup(json));
    expect_function_call(__wrap_cJSON_Delete);

    size_t retval = lccom_dispatch(command, &output);

    assert_int_equal(retval, 9);
    assert_string_equal(output, "test json");

    os_free(command);
    os_free(output);
}

void test_lccom_dispatch_err() {
    char * command = NULL;
    char * output = NULL;

    os_strdup("test", command);

    expect_string(__wrap__mdebug1, formatted_msg, "LCCOM Unrecognized command 'test'.");

    size_t retval = lccom_dispatch(command, &output);

    assert_int_equal(retval, 24);
    assert_string_equal(output, "err Unrecognized command");

    os_free(command);
    os_free(output);
}

int main(void) {
    const struct CMUnitTest tests[] = {

        // Tests lccom_getstate
        cmocka_unit_test(test_lccom_getstate_ok),
        cmocka_unit_test(test_lccom_getstate_null),
        cmocka_unit_test(test_lccom_getstate_first_json_block_greather_than_64k),
        cmocka_unit_test(test_lccom_getstate_second_json_block_greather_than_64k),
        cmocka_unit_test(test_lccom_getstate_third_json_block_greather_than_64k),
        cmocka_unit_test(test_lccom_getstate_end_json_block_lower_than_64k),
        cmocka_unit_test(test_lccom_getstate_first_json_block_greather_than_64k_case1),
        cmocka_unit_test(test_lccom_getstate_first_json_block_lower_than_64k_case2),
        cmocka_unit_test(test_lccom_getstate_first_json_block_lower_than_64k_case5),
        cmocka_unit_test(test_lccom_getstate_first_json_block_lower_than_64k_case5_block1),
        cmocka_unit_test(test_lccom_getstate_first_json_block_lower_than_64k_case6),
        cmocka_unit_test(test_lccom_getstate_first_json_block_lower_than_64k_case6_block1),
        cmocka_unit_test(test_lccom_getstate_first_json_block_no_global),
        cmocka_unit_test(test_lccom_getJsonStr64kBlockFromLatestIndex),
        cmocka_unit_test(test_lccom_isJsonUpdated),
        cmocka_unit_test(test_lccom_dispatch_getconfig_ok),
        cmocka_unit_test(test_lccom_dispatch_getconfig_err),
        cmocka_unit_test(test_lccom_dispatch_getstate),
        cmocka_unit_test(test_lccom_dispatch_getstate_next),
        cmocka_unit_test(test_lccom_dispatch_err),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
