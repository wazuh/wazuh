/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 23, 2021.
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
#include <string.h>
#include <stdlib.h>

#include "wazuh_db/helpers/wdb_agents_helpers.h"
#include "wazuhdb_op.h"

extern int test_mode;

/* setup/teardown */

int setup_wdb_agents_helpers(void **state) {
    test_mode = 1;

    return 0;
}

int teardown_wdb_agents_helpers(void **state) {
    test_mode = 0;

    return 0;
}

/* Tests wdb_agents_vuln_cve_insert */

void test_wdb_agents_vuln_cve_insert_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "test_package";
    const char *version = "1.0";
    const char *architecture = "x86";
    const char *cve = "CVE-2021-1001";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_agents_vuln_cve_insert(id, name, version, architecture, cve, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_agents_vuln_cve_insert_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "test_package";
    const char *version = "1.0";
    const char *architecture = "x86";
    const char *cve = "CVE-2021-1001";

    const char *json_str = strdup("{\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}");
    const char *query_str = "agent 1 vuln_cve insert {\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_package");
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "1.0");
    expect_string(__wrap_cJSON_AddStringToObject, name, "architecture");
    expect_string(__wrap_cJSON_AddStringToObject, string, "x86");
    expect_string(__wrap_cJSON_AddStringToObject, name, "cve");
    expect_string(__wrap_cJSON_AddStringToObject, string, "CVE-2021-1001");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cve insert {\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}");

    ret = wdb_agents_vuln_cve_insert(id, name, version, architecture, cve, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_agents_vuln_cve_insert_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "test_package";
    const char *version = "1.0";
    const char *architecture = "x86";
    const char *cve = "CVE-2021-1001";

    const char *json_str = strdup("{\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}");
    const char *query_str = "agent 1 vuln_cve insert {\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_package");
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "1.0");
    expect_string(__wrap_cJSON_AddStringToObject, name, "architecture");
    expect_string(__wrap_cJSON_AddStringToObject, string, "x86");
    expect_string(__wrap_cJSON_AddStringToObject, name, "cve");
    expect_string(__wrap_cJSON_AddStringToObject, string, "CVE-2021-1001");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Cannot execute SQL query");
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cve insert {\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}");

    ret = wdb_agents_vuln_cve_insert(id, name, version, architecture, cve, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_agents_vuln_cve_insert_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "test_package";
    const char *version = "1.0";
    const char *architecture = "x86";
    const char *cve = "CVE-2021-1001";

    const char *json_str = strdup("{\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}");
    const char *query_str = "agent 1 vuln_cve insert {\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_package");
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "1.0");
    expect_string(__wrap_cJSON_AddStringToObject, name, "architecture");
    expect_string(__wrap_cJSON_AddStringToObject, string, "x86");
    expect_string(__wrap_cJSON_AddStringToObject, name, "cve");
    expect_string(__wrap_cJSON_AddStringToObject, string, "CVE-2021-1001");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Error reported in the result of the query");

    ret = wdb_agents_vuln_cve_insert(id, name, version, architecture, cve, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_agents_vuln_cve_insert_success(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "test_package";
    const char *version = "1.0";
    const char *architecture = "x86";
    const char *cve = "CVE-2021-1001";

    const char *json_str = strdup("{\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}");
    const char *query_str = "agent 1 vuln_cve insert {\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_package");
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "1.0");
    expect_string(__wrap_cJSON_AddStringToObject, name, "architecture");
    expect_string(__wrap_cJSON_AddStringToObject, string, "x86");
    expect_string(__wrap_cJSON_AddStringToObject, name, "cve");
    expect_string(__wrap_cJSON_AddStringToObject, string, "CVE-2021-1001");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_agents_vuln_cve_insert(id, name, version, architecture, cve, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_agents_vuln_cve_clear */

void test_wdb_agents_vuln_cve_clear_error_socket(void **state)
{
    int ret = 0;
    int id = 1;

    const char *query_str = "agent 1 vuln_cve clear";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cve clear");

    ret = wdb_agents_vuln_cve_clear(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_agents_vuln_cve_clear_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;

    const char *query_str = "agent 1 vuln_cve clear";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Cannot execute SQL query");
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cve clear");

    ret = wdb_agents_vuln_cve_clear(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_agents_vuln_cve_clear_error_result(void **state)
{
    int ret = 0;
    int id = 1;

    const char *query_str = "agent 1 vuln_cve clear";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Error reported in the result of the query");

    ret = wdb_agents_vuln_cve_clear(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_agents_vuln_cve_clear_success(void **state)
{
    int ret = 0;
    int id = 1;

    const char *query_str = "agent 1 vuln_cve clear";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_agents_vuln_cve_clear(id, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_agents_vuln_cve_update_status */

test_wdb_agents_vuln_cve_update_status_error_json(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_agents_vuln_cve_update_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}
test_wdb_agents_vuln_cve_update_status_error_socket(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";

    const char *json_str = strdup("{\"old_status\":\"valid\",\"new_status\":\"obsolete\"}");
    const char *query_str = "agent 1 vuln_cve update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "old_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "valid");
    expect_string(__wrap_cJSON_AddStringToObject, name, "new_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "obsolete");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cve update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}");

    ret = wdb_agents_vuln_cve_update_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}
test_wdb_agents_vuln_cve_update_status_error_sql_execution(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";

    const char *json_str = strdup("{\"old_status\":\"valid\",\"new_status\":\"obsolete\"}");
    const char *query_str = "agent 1 vuln_cve update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "old_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "valid");
    expect_string(__wrap_cJSON_AddStringToObject, name, "new_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "obsolete");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Cannot execute SQL query");
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cve update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}");

    ret = wdb_agents_vuln_cve_update_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}
test_wdb_agents_vuln_cve_update_status_error_result(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";

    const char *json_str = strdup("{\"old_status\":\"valid\",\"new_status\":\"obsolete\"}");
    const char *query_str = "agent 1 vuln_cve update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "old_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "valid");
    expect_string(__wrap_cJSON_AddStringToObject, name, "new_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "obsolete");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Error reported in the result of the query");

    ret = wdb_agents_vuln_cve_update_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}
test_wdb_agents_vuln_cve_update_status_success(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";

    const char *json_str = strdup("{\"old_status\":\"valid\",\"new_status\":\"obsolete\"}");
    const char *query_str = "agent 1 vuln_cve update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "old_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "valid");
    expect_string(__wrap_cJSON_AddStringToObject, name, "new_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "obsolete");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_agents_vuln_cve_update_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        /* Tests wdb_agents_vuln_cve_insert*/
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_insert_error_json, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_insert_error_socket, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_insert_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_insert_error_result, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_insert_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        /* Tests wdb_agents_vuln_cve_clear*/
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_clear_error_socket, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_clear_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_clear_error_result, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_clear_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        /* Tests wdb_agents_vuln_cve_update_status*/
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_update_status_error_json, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_update_status_error_socket, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_update_status_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_update_status_error_result, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_agents_vuln_cve_update_status_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
