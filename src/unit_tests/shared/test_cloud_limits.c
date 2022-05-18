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

#include "../wrappers/libc/stdio_wrappers.h"
#include "../headers/cloud_limits.h"


/* setup / teardown */
int test_setup_ok(void **state) {
    test_mode = 1;
    return 0;
}

int test_teardown_ok(void **state) {
    test_mode = 0;
    return 0;
}

void test_load_limits_file_object_null(void **state) {
    cJSON* objet = NULL;
    expect_string(__wrap__mdebug2, formatted_msg, "Invalid daemon name is null");
    int value = load_limits_file(NULL, &objet);
    assert_null(objet);
    assert_int_equal(value, LIMITS_NULL_NAME);
}

void test_load_limits_file_not_foud(void **state) {
    cJSON* objet = NULL;

    expect_string(__wrap_File_DateofChange, file, OSSEC_LIMITS);
    will_return(__wrap_File_DateofChange, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "File './limits.conf' not found");
    int value = load_limits_file("wazuh-analysisd", &objet);
    assert_null(objet);
    assert_int_equal(value, LIMITS_FILE_NOT_FOUND);
}

void test_load_limits_file_hasnt_changed(void **state) {
    cJSON* objet = NULL;

    expect_string(__wrap_File_DateofChange, file, OSSEC_LIMITS);
    will_return(__wrap_File_DateofChange, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "File './limits.conf' hasn't changed");
    int value = load_limits_file("wazuh-analysisd", &objet);
    assert_null(objet);
    assert_int_equal(value, LIMITS_FILE_DOESNT_CHANGE);
}

void test_load_limits_could_not_open_file(void **state) {
    cJSON* objet = NULL;

    expect_string(__wrap_File_DateofChange, file, OSSEC_LIMITS);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_fopen, path, OSSEC_LIMITS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "Could not open file './limits.conf'");
    int value = load_limits_file("wazuh-analysisd", &objet);
    assert_null(objet);
    assert_int_equal(value, LIMITS_OPEN_FILE_FAIL);
}

void test_load_limits_could_not_read_file(void **state) {
    cJSON* objet = NULL;

    expect_string(__wrap_File_DateofChange, file, OSSEC_LIMITS);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_fopen, path, OSSEC_LIMITS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Could not read file './limits.conf'");
    int value = load_limits_file("wazuh-analysisd", &objet);
    assert_null(objet);
    assert_int_equal(value, LIMITS_READ_FILE_FAIL);
}

void test_load_limits_invalid_json(void **state) {
    cJSON* objet = NULL;

    expect_string(__wrap_File_DateofChange, file, OSSEC_LIMITS);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_fopen, path, OSSEC_LIMITS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    will_return(__wrap_cJSON_ParseWithOpts, NULL);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Invalid json format file './limits.conf'");
    int value = load_limits_file("wazuh-analysisd", &objet);
    assert_null(objet);
    assert_int_equal(value, LIMITS_JSON_FORMAT_FAIL);
}

void test_load_limits_objet_not_found(void **state) {
    cJSON* objet = NULL;
    cJSON* limits = NULL;

    expect_string(__wrap_File_DateofChange, file, OSSEC_LIMITS);
    will_return(__wrap_File_DateofChange, 2);

    expect_string(__wrap_fopen, path, OSSEC_LIMITS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *)1);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    will_return(__wrap_cJSON_GetObjectItem, limits);
    will_return(__wrap_cJSON_IsObject, NULL);
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap__mdebug2, formatted_msg, "Limits object not found in './limits.conf'");
    int value = load_limits_file("wazuh-analysisd", &objet);
    assert_null(objet);
    assert_int_equal(value, LIMITS_JSON_LIMIT_NOT_FOUND);
}

void test_load_limits_daemon_not_found(void **state) {
    cJSON* objet = NULL;
    cJSON* limits = (cJSON*) "{\"wazuh-analysisd\":{\"max_eps\":10,\"timeframe_eps\":10}}";

    expect_string(__wrap_File_DateofChange, file, OSSEC_LIMITS);
    will_return(__wrap_File_DateofChange, 3);

    expect_string(__wrap_fopen, path, OSSEC_LIMITS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *)1);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    will_return(__wrap_cJSON_GetObjectItem, limits);
    will_return(__wrap_cJSON_IsObject, 1);

    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_IsObject, NULL);

    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap__mdebug2, formatted_msg, "Daemon 'wazuh-analysisd' not found in './limits.conf'");
    int value = load_limits_file("wazuh-analysisd", &objet);
    assert_null(objet);
    assert_int_equal(value, LIMITS_JSON_DAEMON_NOT_FOUND);
}

void test_load_limits_success(void **state) {
    cJSON* objet = NULL;
    cJSON* limits = (cJSON*) "{\"wazuh-analysisd\":{\"max_eps\":10,\"timeframe_eps\":10}}";
    cJSON* daemon = (cJSON*) "{\"max_eps\":10,\"timeframe_eps\":10}";

    expect_string(__wrap_File_DateofChange, file, OSSEC_LIMITS);
    will_return(__wrap_File_DateofChange, 4);

    expect_string(__wrap_fopen, path, OSSEC_LIMITS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *)1);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    will_return(__wrap_cJSON_GetObjectItem, limits);
    will_return(__wrap_cJSON_IsObject, 1);

    will_return(__wrap_cJSON_GetObjectItem, daemon);
    will_return(__wrap_cJSON_IsObject, 1);

    int value = load_limits_file("wazuh-analysisd", &objet);
    assert_non_null(objet);
    assert_int_equal(value, LIMITS_SUCCESS);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_load_limits_file_object_null, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_load_limits_file_not_foud, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_load_limits_file_hasnt_changed, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_load_limits_could_not_open_file, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_load_limits_could_not_read_file, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_load_limits_invalid_json, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_load_limits_objet_not_found, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_load_limits_daemon_not_found, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_load_limits_success, test_setup_ok, test_teardown_ok),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
