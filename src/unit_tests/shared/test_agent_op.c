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
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "../../headers/shared.h"
#include "../../headers/sec.h"
#include "../../addagent/manage_agents.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* redefinitons/wrapping */

extern cJSON* w_create_agent_add_payload(const char *name, const char *ip, const char * groups, const char *key, const int force, const char *id);
extern cJSON* w_create_agent_remove_payload(const char *id, const int purge);
extern cJSON* w_create_sendsync_payload(const char *daemon_name, cJSON *message);
extern int w_parse_agent_add_response(const char* buffer, char *err_response, char* id, char* key, const int json_format, const int exit_on_error);
extern int w_parse_agent_remove_response(const char* buffer, char *err_response, const int json_format, const int exit_on_error);


static void test_create_agent_add_payload(void **state) {
    char* agent = "agent1";
    char* ip = "192.0.0.0";
    char* groups = "Group1,Group2";
    char* key = "1234";
    int force = 1;
    char* id = "001";
    cJSON* payload = NULL;
    payload = w_create_agent_add_payload(agent, ip, groups, key, force, id);

    assert_non_null(payload);
    cJSON* function = cJSON_GetObjectItem(payload, "function");
    assert_non_null(function);
    assert_string_equal(function->valuestring, "add");

    cJSON* arguments = cJSON_GetObjectItem(payload, "arguments");
    assert_non_null(arguments);

    cJSON* item = NULL;
    item = cJSON_GetObjectItem(arguments, "groups");
    assert_non_null(item);
    assert_string_equal(item->valuestring, groups);


    item = cJSON_GetObjectItem(arguments, "key");
    assert_non_null(item);
    assert_string_equal(item->valuestring, key);


    item = cJSON_GetObjectItem(arguments, "id");
    assert_non_null(item);
    assert_string_equal(item->valuestring, id);

    item = cJSON_GetObjectItem(arguments, "force");
    assert_non_null(item);
    assert_int_equal(item->valueint, force);

    cJSON_Delete(payload);
}

#ifndef WIN32
static void test_create_agent_remove_payload(void **state) {
    char* id = "001";
    int purge = 1;
    cJSON* payload = NULL;
    payload = w_create_agent_remove_payload(id, purge);

    assert_non_null(payload);
    cJSON* function = cJSON_GetObjectItem(payload, "function");
    assert_non_null(function);
    assert_string_equal(function->valuestring, "remove");

    cJSON* arguments = cJSON_GetObjectItem(payload, "arguments");
    assert_non_null(arguments);

    cJSON* item = NULL;
    item = cJSON_GetObjectItem(arguments, "id");
    assert_non_null(item);
    assert_string_equal(item->valuestring, id);


    item = cJSON_GetObjectItem(arguments, "purge");
    assert_non_null(item);
    assert_int_equal(item->valueint, purge);

    cJSON_Delete(payload);
}

static void test_create_sendsync_payload(void **state) {
    char* daemon = "daemon_test";
    char* id = "001";
    int purge = 1;
    cJSON* payload = NULL;
    cJSON* message = NULL;
    cJSON* item = NULL;
    /* NULL message */
    payload = w_create_sendsync_payload(daemon, message);

    assert_non_null(payload);

    item = cJSON_GetObjectItem(payload, "daemon_name");
    assert_non_null(item);
    assert_string_equal(item->valuestring, daemon);

    item = cJSON_GetObjectItem(payload, "message");
    assert_null(item);

    cJSON_Delete(payload);

    /* non NULL message */
    message = w_create_agent_remove_payload(id,purge);
    payload = w_create_sendsync_payload(daemon, message);

    assert_non_null(payload);

    item = cJSON_GetObjectItem(payload, "daemon_name");
    assert_non_null(item);
    assert_string_equal(item->valuestring, daemon);

    item = cJSON_GetObjectItem(payload, "message");
    assert_non_null(item);

    cJSON_Delete(payload);
}

static void test_parse_agent_remove_response(void **state) {
    char* success_response = "{\"error\":0}";
    char* error_response = "{\"error\":9009,\"message\":\"ERROR_MESSAGE\"}";
    char* unknown_response = "{\"message \":\"any_message\"}";
    int err = 0;
    char err_response[OS_MAXSTR + 1];

    // Remove _merror checks
    expect_any_always(__wrap__merror, formatted_msg);

    /* Success parse */
    err = w_parse_agent_remove_response(success_response, err_response, FALSE, FALSE);
    assert_int_equal(err, 0);

    /* Error parse */
    err = w_parse_agent_remove_response(error_response, err_response, FALSE, FALSE);
    assert_int_equal(err, -1);
    assert_string_equal(err_response, "ERROR: ERROR_MESSAGE");

    /* Unknown parse */
    err = w_parse_agent_remove_response(unknown_response, err_response, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");
}
#endif

static void test_parse_agent_add_response(void **state) {
    char* success_response = "{\"error\":0,\"data\":{\"id\":\"001\",\"name\":\"agent1\",\"ip\":\"any\",\"key\":\"347e2dc688148aec8544c9777ff291b8868b885\"}}";
    char* missingdata_response = "{\"error\":0}";
    char* missingkey_response = "{\"error\":0,\"data\":{\"id\":\"001\",\"name\":\"agent1\",\"ip\":\"any\"}}";
    char* missingid_response = "{\"error\":0,\"data\":{\"name\":\"agent1\",\"ip\":\"any\",\"key\":\"347e2dc688148aec8544c9777ff291b8868b885\"}}";
    char* error_response = "{\"error\":9009,\"message\":\"ERROR_MESSAGE\"}";
    char* unknown_response = "{\"message \":\"any_message\"}";
    char new_id[FILE_SIZE+1] = { '\0' };
    char new_key[KEYSIZE+1] = { '\0' };
    int err = 0;
    char err_response[OS_MAXSTR + 1];

    // Remove _merror checks
    expect_any_always(__wrap__merror, formatted_msg);

    /* Success parse */
    err = w_parse_agent_add_response(success_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, 0);
    assert_string_equal(new_id, "001");
    assert_string_equal(new_key, "347e2dc688148aec8544c9777ff291b8868b885");

    err = w_parse_agent_add_response(success_response, err_response, new_id, NULL, FALSE, FALSE);
    assert_int_equal(err, 0);
    assert_string_equal(new_id, "001");

    err = w_parse_agent_add_response(success_response, err_response, NULL, new_key, FALSE, FALSE);
    assert_int_equal(err, 0);
    assert_string_equal(new_key, "347e2dc688148aec8544c9777ff291b8868b885");

    /* Error parse */
    err = w_parse_agent_add_response(error_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -1);
    assert_string_equal(err_response, "ERROR: ERROR_MESSAGE");

    /* Unknown parse */
    err = w_parse_agent_add_response(unknown_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Missing Data parse */
    err = w_parse_agent_add_response(missingdata_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Missing ID parse */
    err = w_parse_agent_add_response(missingid_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Missing key parse */
    err = w_parse_agent_add_response(missingkey_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_agent_add_payload),
        cmocka_unit_test(test_parse_agent_add_response),
        #ifndef WIN32
        cmocka_unit_test(test_create_agent_remove_payload),
        cmocka_unit_test(test_create_sendsync_payload),
        cmocka_unit_test(test_parse_agent_remove_response),
        #endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
