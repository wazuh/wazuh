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


void _test_lccom_getstate_tmp (char *ExpectedBlock){
    char * output = NULL;
    char *json = NULL;
    os_strdup(global_outjson, json);
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

    size_t retval = lccom_getstate(&output, true);

    assert_int_equal(strlen(output), retval);
    assert_string_equal(ExpectedBlock, output);
    os_free(output);
}


void test_lccom_getstate_first_json_block_greather_than_64k(void ** state) {
    _test_lccom_getstate_tmp (outjson_block1);
}

void test_lccom_getstate_second_json_block_greather_than_64k(void ** state) {
    _test_lccom_getstate_tmp (outjson_block2);
}

void test_lccom_getstate_third_json_block_greather_than_64k(void ** state) {
    _test_lccom_getstate_tmp (outjson_block3);
}

void test_lccom_getstate_end_json_block_lower_than_64k(void ** state) {
   _test_lccom_getstate_tmp (outjson_block4);
}

int main(void) {
    const struct CMUnitTest tests[] = {

        // Tests lccom_getstate
        cmocka_unit_test(test_lccom_getstate_ok),
        cmocka_unit_test(test_lccom_getstate_null),
        cmocka_unit_test(test_lccom_getstate_first_json_block_greather_than_64k),
        cmocka_unit_test(test_lccom_getstate_second_json_block_greather_than_64k),
        cmocka_unit_test(test_lccom_getstate_third_json_block_greather_than_64k),
        cmocka_unit_test(test_lccom_getstate_end_json_block_lower_than_64k)

    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
