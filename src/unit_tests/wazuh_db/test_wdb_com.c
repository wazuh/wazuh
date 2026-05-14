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

#include "../wrappers/wazuh/wazuh_db/wdb_state_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

#include "../wazuh_db/wdb.h"

char* wdbcom_output_builder(int error_code, const char* message, cJSON* data_json);
cJSON* wdbcom_getconfig(char* section);

static int test_teardown(void ** state) {
    char* string = *state;
    os_free(string);
    return 0;
}

void test_wdbcom_output_builder(void ** state) {
    int error_code = 5;
    const char* message = "test msg";

    cJSON* data_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(data_json, "test1", 18);
    cJSON_AddStringToObject(data_json, "test2", "wazuhdb");

    char* msg = wdbcom_output_builder(error_code, message, data_json);

    *state = msg;

    assert_non_null(msg);
    assert_string_equal(msg, "{\"error\":5,\"message\":\"test msg\",\"data\":{\"test1\":18,\"test2\":\"wazuhdb\"}}");
}

void test_wdbcom_dispatch_getstats(void ** state) {
    char* request = "{\"command\":\"getstats\"}";
    char response[OS_MAXSTR + 1];
    *response = '\0';

    cJSON* data_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(data_json, "test1", 18);
    cJSON_AddStringToObject(data_json, "test2", "wazuhdb");

    will_return(__wrap_wdb_create_state_json, data_json);

    wdbcom_dispatch(request, response);

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":0,\"message\":\"ok\",\"data\":{\"test1\":18,\"test2\":\"wazuhdb\"}}");
}

void test_wdbcom_dispatch_getconfig(void ** state) {
    char* request = "{\"command\":\"getconfig\",\"parameters\":{\"section\":\"internal\"}}";
    char response[OS_MAXSTR + 1];
    *response = '\0';

    cJSON* data_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(data_json, "test1", 12);
    cJSON_AddStringToObject(data_json, "test2", "wazuhdb");

    will_return(__wrap_wdb_get_internal_config, data_json);

    wdbcom_dispatch(request, response);

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":0,\"message\":\"ok\",\"data\":{\"test1\":12,\"test2\":\"wazuhdb\"}}");
}

void test_wdbcom_dispatch_getconfig_unknown_section(void ** state) {
    char* request = "{\"command\":\"getconfig\",\"parameters\":{\"section\":\"testtest\"}}";
    char response[OS_MAXSTR + 1];
    *response = '\0';

    wdbcom_dispatch(request, response);

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":6,\"message\":\"Unrecognized or not configured section\",\"data\":{}}");
}

void test_wdbcom_dispatch_getconfig_empty_section(void ** state) {
    char* request = "{\"command\":\"getconfig\",\"parameters\":{}}";
    char response[OS_MAXSTR + 1];
    *response = '\0';

    wdbcom_dispatch(request, response);

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":5,\"message\":\"Empty section\",\"data\":{}}");
}

void test_wdbcom_dispatch_getconfig_empty_parameters(void ** state) {
    char* request = "{\"command\":\"getconfig\"}";
    char response[OS_MAXSTR + 1];
    *response = '\0';

    wdbcom_dispatch(request, response);

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":4,\"message\":\"Empty parameters\",\"data\":{}}");
}

void test_wdbcom_dispatch_unknown_command(void ** state) {
    char* request = "{\"command\":\"unknown\"}";
    char response[OS_MAXSTR + 1];
    *response = '\0';

    wdbcom_dispatch(request, response);

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":3,\"message\":\"Unrecognized command\",\"data\":{}}");
}

void test_wdbcom_dispatch_empty_command(void ** state) {
    char* request = "{}";
    char response[OS_MAXSTR + 1];
    *response = '\0';

    wdbcom_dispatch(request, response);

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":2,\"message\":\"Empty command\",\"data\":{}}");
}

void test_wdbcom_dispatch_invalid_json(void ** state) {
    char* request = "unknown";
    char response[OS_MAXSTR + 1];
    *response = '\0';

    wdbcom_dispatch(request, response);

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":1,\"message\":\"Invalid JSON input\",\"data\":{}}");
}

/* Tests wdbcom_getconfig */

void test_wdb_parse_get_config_internal() {
    will_return(__wrap_wdb_get_internal_config, 1);
    cJSON *ret = wdbcom_getconfig("internal");
    assert_int_equal(ret, 1);
}

void test_wdb_parse_get_config_wdb() {
    will_return(__wrap_wdb_get_config, 1);
    cJSON *ret = wdbcom_getconfig("wdb");
    assert_int_equal(ret, 1);
}

void test_wdb_parse_get_config_arg_null() {
    cJSON *ret = wdbcom_getconfig("unknown");
    assert_int_equal(ret, NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test wdbcom_output_builder
        cmocka_unit_test_teardown(test_wdbcom_output_builder, test_teardown),
        // Test wdbcom_dispatch
        cmocka_unit_test(test_wdbcom_dispatch_getstats),
        cmocka_unit_test(test_wdbcom_dispatch_getconfig),
        cmocka_unit_test(test_wdbcom_dispatch_getconfig_unknown_section),
        cmocka_unit_test(test_wdbcom_dispatch_getconfig_empty_section),
        cmocka_unit_test(test_wdbcom_dispatch_getconfig_empty_parameters),
        cmocka_unit_test(test_wdbcom_dispatch_unknown_command),
        cmocka_unit_test(test_wdbcom_dispatch_empty_command),
        cmocka_unit_test(test_wdbcom_dispatch_invalid_json),
        /* Tests wdbcom_getconfig */
        cmocka_unit_test(test_wdb_parse_get_config_wdb),
        cmocka_unit_test(test_wdb_parse_get_config_internal),
        cmocka_unit_test(test_wdb_parse_get_config_arg_null),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
