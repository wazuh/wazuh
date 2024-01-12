/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
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

#include "../wazuh_db/helpers/wdb_agents_helpers.h"
#include "wazuhdb_op.h"

#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

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

/* Tests wdb_get_agent_sys_osinfo */

void test_wdb_get_sys_osinfo_error_sql_execution(void ** state)
{
    cJSON *ret = NULL;
    int id = 1;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_get_agent_sys_osinfo(id, NULL);

    assert_null(ret);
}

void test_wdb_get_sys_osinfo_success(void ** state)
{
    cJSON *ret = NULL;
    int id = 1;

    cJSON *root = __real_cJSON_CreateArray();
    cJSON *row = __real_cJSON_CreateObject();
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    ret = wdb_get_agent_sys_osinfo(id, NULL);

    assert_ptr_equal(root, ret);

    __real_cJSON_Delete(root);
}

/* Tests wdb_insert_vuln_cves */

void test_wdb_insert_vuln_cves_error_json(void **state)
{
    cJSON *ret = NULL;
    int id = 1;
    const char *name = "test_package";
    const char *version = "1.0";
    const char *architecture = "x86";
    const char *cve = "CVE-2021-1001";
    const char* severity = "High";
    double cvss2_score = 6.9;
    double cvss3_score = 3.6;
    const char *reference = "69ac04fa9b4a0dcfccd7c2237b366e501b678cc7";
    const char *type = "PACKAGE";
    const char *status = "VALID";
    char **external_references = NULL;
    const char *condition = "Package unfixed";
    const char *title = "CVE-2021-1200 affects package";
    const char *published = "01-01-2021";
    const char *updated = "02-01-2021";
    bool check_pkg_existence = true;

    os_calloc(3, sizeof(char*), external_references);
    os_strdup("https://references.com/ref1.html", external_references[0]);
    os_strdup("https://references.com/ref2.html", external_references[1]);
    external_references[2] = NULL;

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_insert_vuln_cves(id, name, version, architecture, cve, severity, cvss2_score, cvss3_score, reference, type, status,
                               external_references, condition, title, published, updated, check_pkg_existence, NULL);

    assert_null(ret);
    free_strarray(external_references);
}

void test_wdb_insert_vuln_cves_null_parameters(void **state)
{
    cJSON *ret = NULL;
    int id = 1;
    const char *name = NULL;
    const char *version = NULL;
    const char *architecture = NULL;
    const char *cve = NULL;
    const char* severity = NULL;
    double cvss2_score = 0;
    double cvss3_score = 0;
    const char *reference = NULL;
    const char *type = NULL;
    const char *status = NULL;
    char **external_references = NULL;
    const char *condition = NULL;
    const char *title = NULL;
    const char *published = NULL;
    const char *updated = NULL;
    bool check_pkg_existence = false;

    const char *json_str = NULL;

    os_strdup("{}", json_str);

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

     // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, name, "architecture");
    expect_string(__wrap_cJSON_AddStringToObject, name, "cve");
    expect_string(__wrap_cJSON_AddStringToObject, name, "severity");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "cvss2_score");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "cvss3_score");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);
    expect_string(__wrap_cJSON_AddStringToObject, name, "reference");
    expect_string(__wrap_cJSON_AddStringToObject, name, "type");
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)0);
    expect_string(__wrap_cJSON_AddStringToObject, name, "condition");
    expect_string(__wrap_cJSON_AddStringToObject, name, "title");
    expect_string(__wrap_cJSON_AddStringToObject, name, "published");
    expect_string(__wrap_cJSON_AddStringToObject, name, "updated");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, (cJSON *)1);

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_insert_vuln_cves(id, name, version, architecture, cve, severity, cvss2_score, cvss3_score, reference, type, status,
                               external_references, condition, title, published, updated, check_pkg_existence, NULL);

    assert_ptr_equal(1, ret);
}

void test_wdb_insert_vuln_cves_error_sql_execution(void **state)
{
    cJSON *ret = NULL;
    int id = 1;
    const char *name = "test_package";
    const char *version = "1.0";
    const char *architecture = "x86";
    const char *cve = "CVE-2021-1001";
    const char* severity = "High";
    double cvss2_score = 6.9;
    double cvss3_score = 3.6;
    const char *reference = "69ac04fa9b4a0dcfccd7c2237b366e501b678cc7";
    const char *type = "PACKAGE";
    const char *status = "VALID";
    char **external_references = NULL;
    const char *condition = "Package unfixed";
    const char *title = "CVE-2021-1001 affects package";
    const char *published = "01-01-2021";
    const char *updated = "02-01-2021";
    bool check_pkg_existence = true;

    os_calloc(3, sizeof(char*), external_references);
    os_strdup("https://references.com/ref1.html", external_references[0]);
    os_strdup("https://references.com/ref2.html", external_references[1]);
    external_references[2] = NULL;

    const char *json_str = NULL;
    os_strdup("{\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\",\"severity\":\"High\","
              "\"cvss2_score\":6.9,\"cvss3_score\":3.6,\"reference\":\"69ac04fa9b4a0dcfccd7c2237b366e501b678cc7\",\"type\":\"PACKAGE\","
              "\"status\":\"VALID\",\"check_pkg_existence\":true, \"external_references\":\"[\"https://references.com/ref1.html\",\"https://references.com/ref2.html\"]\","
              "\"condition\":\"Package unfixed\", \"title\":\"CVE-2021-1001 affects test_package\", \"published\":\"01-01-2021\",\"updated\":\"02-01-2021\"}", json_str);

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
    expect_string(__wrap_cJSON_AddStringToObject, name, "severity");
    expect_string(__wrap_cJSON_AddStringToObject, string, "High");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "cvss2_score");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 6.9);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "cvss3_score");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 3.6);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);
    expect_string(__wrap_cJSON_AddStringToObject, name, "reference");
    expect_string(__wrap_cJSON_AddStringToObject, string, "69ac04fa9b4a0dcfccd7c2237b366e501b678cc7");
    expect_string(__wrap_cJSON_AddStringToObject, name, "type");
    expect_string(__wrap_cJSON_AddStringToObject, string, "PACKAGE");
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "VALID");
    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "condition");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Package unfixed");
    expect_string(__wrap_cJSON_AddStringToObject, name, "title");
    expect_string(__wrap_cJSON_AddStringToObject, string, "CVE-2021-1001 affects package");
    expect_string(__wrap_cJSON_AddStringToObject, name, "published");
    expect_string(__wrap_cJSON_AddStringToObject, string, "01-01-2021");
    expect_string(__wrap_cJSON_AddStringToObject, name, "updated");
    expect_string(__wrap_cJSON_AddStringToObject, string, "02-01-2021");

    cJSON* j_cvs_references = __real_cJSON_CreateArray();
    __real_cJSON_AddItemToArray(j_cvs_references, __real_cJSON_CreateString("https://references.com/ref1.html"));
    __real_cJSON_AddItemToArray(j_cvs_references, __real_cJSON_CreateString("https://references.com/ref2.html"));

    expect_function_calls(__wrap_cJSON_AddItemToArray, 2);
    will_return_count(__wrap_cJSON_AddItemToArray, true, 2);
    expect_string(__wrap_cJSON_CreateString, string, "https://references.com/ref1.html");
    expect_string(__wrap_cJSON_CreateString, string, "https://references.com/ref2.html");
    will_return_count(__wrap_cJSON_CreateString, NULL, 2);
    will_return(__wrap_cJSON_CreateArray, j_cvs_references);
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);

    // Handling result
    expect_string(__wrap__merror, formatted_msg, "Agents DB (1) Error querying Wazuh DB to insert vuln_cves");

    ret = wdb_insert_vuln_cves(id, name, version, architecture, cve, severity, cvss2_score, cvss3_score, reference, type, status,
                               external_references, condition, title, published, updated, check_pkg_existence, NULL);
    assert_null(ret);
    __real_cJSON_Delete(j_cvs_references);
    free_strarray(external_references);
}

void test_wdb_insert_vuln_cves_success(void **state)
{
    cJSON *ret = NULL;
    int id = 1;
    const char *name = "test_package";
    const char *version = "1.0";
    const char *architecture = "x86";
    const char *cve = "CVE-2021-1001";
    const char* severity = "High";
    double cvss2_score = 6.9;
    double cvss3_score = 3.6;
    const char *reference = "69ac04fa9b4a0dcfccd7c2237b366e501b678cc7";
    const char *type = "PACKAGE";
    const char *status = "VALID";
    char **external_references = NULL;
    const char *condition = "Package unfixed";
    const char *title = "CVE-2021-1001 affects package";
    const char *published = "01-01-2021";
    const char *updated = "02-01-2021";
    bool check_pkg_existence = true;

    os_calloc(3, sizeof(char*), external_references);
    os_strdup("https://references.com/ref1.html", external_references[0]);
    os_strdup("https://references.com/ref2.html", external_references[1]);
    external_references[2] = NULL;

    const char *json_str = NULL;

    os_strdup("{\"name\":\"test_package\",\"version\":\"1.0\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1001\",\"severity\":\"High\","
              "\"cvss2_score\":6.9,\"cvss3_score\":3.6,\"reference\":\"69ac04fa9b4a0dcfccd7c2237b366e501b678cc7\",\"type\":\"PACKAGE\","
              "\"status\":\"VALID\",\"check_pkg_existence\":true, }", json_str);

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
    expect_string(__wrap_cJSON_AddStringToObject, name, "severity");
    expect_string(__wrap_cJSON_AddStringToObject, string, "High");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "cvss2_score");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 6.9);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "cvss3_score");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 3.6);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);
    expect_string(__wrap_cJSON_AddStringToObject, name, "reference");
    expect_string(__wrap_cJSON_AddStringToObject, string, "69ac04fa9b4a0dcfccd7c2237b366e501b678cc7");
    expect_string(__wrap_cJSON_AddStringToObject, name, "type");
    expect_string(__wrap_cJSON_AddStringToObject, string, "PACKAGE");
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "VALID");
    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "condition");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Package unfixed");
    expect_string(__wrap_cJSON_AddStringToObject, name, "title");
    expect_string(__wrap_cJSON_AddStringToObject, string, "CVE-2021-1001 affects package");
    expect_string(__wrap_cJSON_AddStringToObject, name, "published");
    expect_string(__wrap_cJSON_AddStringToObject, string, "01-01-2021");
    expect_string(__wrap_cJSON_AddStringToObject, name, "updated");
    expect_string(__wrap_cJSON_AddStringToObject, string, "02-01-2021");

    cJSON* j_cvs_references = __real_cJSON_CreateArray();
    __real_cJSON_AddItemToArray(j_cvs_references, __real_cJSON_CreateString("https://references.com/ref1.html"));
    __real_cJSON_AddItemToArray(j_cvs_references, __real_cJSON_CreateString("https://references.com/ref2.html"));

    expect_function_calls(__wrap_cJSON_AddItemToArray, 2);
    will_return_count(__wrap_cJSON_AddItemToArray, true, 2);
    expect_string(__wrap_cJSON_CreateString, string, "https://references.com/ref1.html");
    expect_string(__wrap_cJSON_CreateString, string, "https://references.com/ref2.html");
    will_return_count(__wrap_cJSON_CreateString, NULL, 2);
    will_return(__wrap_cJSON_CreateArray, j_cvs_references);
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, (cJSON *)1);

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_insert_vuln_cves(id, name, version, architecture, cve, severity, cvss2_score, cvss3_score, reference, type, status,
                               external_references, condition, title, published, updated, check_pkg_existence, NULL);

    assert_ptr_equal(1, ret);
    __real_cJSON_Delete(j_cvs_references);
    free_strarray(external_references);
}

/* Tests wdb_update_vuln_cves_status */

void test_wdb_update_vuln_cves_status_error_json(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_vuln_cves_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_vuln_cves_status_error_socket(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";
    const char *json_str = NULL;

    os_strdup("{\"old_status\":\"valid\",\"new_status\":\"obsolete\"}", json_str);
    const char *query_str = "agent 1 vuln_cves update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}";
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
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cves update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}");

    ret = wdb_update_vuln_cves_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_vuln_cves_status_error_sql_execution(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";
    const char *json_str = NULL;

    os_strdup("{\"old_status\":\"valid\",\"new_status\":\"obsolete\"}", json_str);
    const char *query_str = "agent 1 vuln_cves update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}";
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
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cves update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}");

    ret = wdb_update_vuln_cves_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_vuln_cves_status_error_result(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";
    const char *json_str = NULL;

    os_strdup("{\"old_status\":\"valid\",\"new_status\":\"obsolete\"}", json_str);
    const char *query_str = "agent 1 vuln_cves update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}";
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

    ret = wdb_update_vuln_cves_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_vuln_cves_status_success(void **state){
    int ret = 0;
    int id = 1;
    const char *old_status = "valid";
    const char *new_status = "obsolete";
    const char *json_str = NULL;

    os_strdup("{\"old_status\":\"valid\",\"new_status\":\"obsolete\"}", json_str);
    const char *query_str = "agent 1 vuln_cves update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}";
    const char *response = "ok";

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

    ret = wdb_update_vuln_cves_status(id, old_status, new_status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_vuln_cves_status_by_type */

void test_wdb_update_vuln_cves_status_by_type_error_json(void **state){
    int ret = 0;
    int id = 1;
    const char *type = "OS";
    const char *new_status = "PENDING";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_vuln_cves_status_by_type(id, type, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_vuln_cves_status_by_type_error_socket(void **state){
    int ret = 0;
    int id = 1;
    const char *type = "OS";
    const char *new_status = "PENDING";
    const char *json_str = NULL;
    const char *response = "err";
    char query_str[OS_SIZE_256];

    os_strdup("{\"type\":\"OS\",\"new_status\":\"PENDING\"}", json_str);
    snprintf(query_str, OS_SIZE_256, "agent 1 vuln_cves update_status %s", json_str);

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "type");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OS");
    expect_string(__wrap_cJSON_AddStringToObject, name, "new_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "PENDING");

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
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cves update_status {\"type\":\"OS\",\"new_status\":\"PENDING\"}");

    ret = wdb_update_vuln_cves_status_by_type(id, type, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_vuln_cves_status_by_type_error_sql_execution(void **state){
    int ret = 0;
    int id = 1;
    const char *type = "OS";
    const char *new_status = "PENDING";
    const char *json_str = NULL;
    const char *response = "err";
    char query_str[OS_SIZE_256];

    os_strdup("{\"type\":\"OS\",\"new_status\":\"PENDING\"}", json_str);
    snprintf(query_str, OS_SIZE_256, "agent 1 vuln_cves update_status %s", json_str);

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "type");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OS");
    expect_string(__wrap_cJSON_AddStringToObject, name, "new_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "PENDING");

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
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 vuln_cves update_status {\"type\":\"OS\",\"new_status\":\"PENDING\"}");

    ret = wdb_update_vuln_cves_status_by_type(id, type, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_vuln_cves_status_by_type_error_result(void **state){
    int ret = 0;
    int id = 1;
    const char *type = "OS";
    const char *new_status = "PENDING";
    const char *json_str = NULL;
    const char *response = "err";
    char query_str[OS_SIZE_256];

    os_strdup("{\"type\":\"OS\",\"new_status\":\"PENDING\"}", json_str);
    snprintf(query_str, OS_SIZE_256, "agent 1 vuln_cves update_status %s", json_str);

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "type");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OS");
    expect_string(__wrap_cJSON_AddStringToObject, name, "new_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "PENDING");

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

    ret = wdb_update_vuln_cves_status_by_type(id, type, new_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_vuln_cves_status_by_type_success(void **state){
    int ret = 0;
    int id = 1;
    const char *type = "OS";
    const char *new_status = "PENDING";
    const char *json_str = NULL;
    char query_str[OS_SIZE_256];
    const char *response = "ok";

    os_strdup("{\"type\":\"OS\",\"new_status\":\"PENDING\"}", json_str);
    snprintf(query_str, OS_SIZE_256, "agent 1 vuln_cves update_status %s", json_str);

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "type");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OS");
    expect_string(__wrap_cJSON_AddStringToObject, name, "new_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "PENDING");

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

    ret = wdb_update_vuln_cves_status_by_type(id, type, new_status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_remove_vuln_cves_by_status */

void test_wdb_remove_vuln_cves_by_status_error_json(void **state)
{
    cJSON *ret_cves = NULL;
    int id = 1;
    const char *status = "OBSOLETE";

    // Creating JSON data_in
    will_return(__wrap_cJSON_CreateObject, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret_cves = wdb_remove_vuln_cves_by_status(id, status, NULL);

    assert_null(ret_cves);
}

void test_wdb_remove_vuln_cves_by_status_error_wdb_query(void **state)
{
    cJSON *ret_cves = NULL;
    int id = 1;
    const char *status = "OBSOLETE";
    const char *json_str = NULL;

    os_strdup("{\"status\":\"OBSOLETE\"}", json_str);
    const char *query_str = "agent 1 vuln_cves remove {\"status\":\"OBSOLETE\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OBSOLETE");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Error removing vulnerabilities from the agent database.");
    expect_function_call(__wrap_cJSON_Delete);

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);

    ret_cves = wdb_remove_vuln_cves_by_status(id, status, NULL);

    assert_null(ret_cves);
}

void test_wdb_remove_vuln_cves_by_status_error_result(void **state)
{
    cJSON *ret_cves = NULL;
    int id = 1;
    const char *status = "OBSOLETE";
    const char *json_str = NULL;

    os_strdup("{\"status\":\"OBSOLETE\"}", json_str);
    const char *query_str = "agent 1 vuln_cves remove {\"status\":\"OBSOLETE\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OBSOLETE");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);

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

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);

    ret_cves = wdb_remove_vuln_cves_by_status(id, status, NULL);

    assert_null(ret_cves);
}

void test_wdb_remove_vuln_cves_by_status_error_json_result(void **state)
{
    cJSON *ret_cves = NULL;
    int id = 1;
    const char *status = "OBSOLETE";
    const char *json_str = NULL;

    os_strdup("{\"status\":\"OBSOLETE\"}", json_str);
    const char *query_str = "agent 1 vuln_cves remove {\"status\":\"OBSOLETE\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OBSOLETE");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Parsing JSON result
    will_return(__wrap_cJSON_ParseWithOpts, "a JSON error");
    will_return(__wrap_cJSON_ParseWithOpts, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cves JSON results syntax after removing vulnerabilities.");
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: a JSON error");

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);

    ret_cves = wdb_remove_vuln_cves_by_status(id, status, NULL);

    assert_null(ret_cves);
}

void test_wdb_remove_vuln_cves_by_status_success_ok(void **state)
{
    cJSON *ret_cves = NULL;
    int id = 1;
    const char *status = "OBSOLETE";
    const char *json_str = NULL;

    os_strdup("{\"status\":\"OBSOLETE\"}", json_str);
    const char *query_str = "agent 1 vuln_cves remove {\"status\":\"OBSOLETE\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OBSOLETE");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Parsing JSON result
    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, 1);

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);

    ret_cves = wdb_remove_vuln_cves_by_status(id, status, NULL);

    assert_ptr_equal(1, ret_cves);
}

void test_wdb_remove_vuln_cves_by_status_success_due(void **state)
{
    cJSON *ret_cves = NULL;
    cJSON *root1 = NULL;
    cJSON *root2 = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;
    int id = 1;
    const char *status = "OBSOLETE";
    const char *json_str = NULL;

    os_strdup("{\"status\":\"OBSOLETE\"}", json_str);
    const char *query_str = "agent 1 vuln_cves remove {\"status\":\"OBSOLETE\"}";
    const char *response = "ok";

    root1 = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("cve-xxxx-yyyy");
    __real_cJSON_AddItemToObject(row, "cve", str);
    __real_cJSON_AddItemToArray(root1, row);
    root2 = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("cve-xxxx-yyyy");
    __real_cJSON_AddItemToObject(row, "cve", str);
    __real_cJSON_AddItemToArray(root2, row);

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "OBSOLETE");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);

    //// First call to Wazuh DB
    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_DUE);

    // Parsing JSON result
    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, root1);

    //// Second call to Wazuh DB
    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Parsing JSON result
    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, root2);

    will_return(__wrap_cJSON_Duplicate, row);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_function_call(__wrap_cJSON_Delete);

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);

    ret_cves = wdb_remove_vuln_cves_by_status(id, status, NULL);

    assert_ptr_equal(root1, ret_cves);
    __real_cJSON_Delete(root1);
    __real_cJSON_Delete(root2);
}

/* Tests wdb_set_agent_sys_osinfo_triaged */

void test_wdb_set_sys_osinfo_triaged_error_socket(void **state)
{
    int ret = 0;
    int id = 1;

    const char *query_str = "agent 1 osinfo set_triaged";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 osinfo set_triaged");

    ret = wdb_set_agent_sys_osinfo_triaged(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_sys_osinfo_triaged_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;

    const char *query_str = "agent 1 osinfo set_triaged";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Agents DB (1) Cannot execute SQL query");
    expect_string(__wrap__mdebug2, formatted_msg, "Agents DB (1) SQL query: agent 1 osinfo set_triaged");

    ret = wdb_set_agent_sys_osinfo_triaged(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_sys_osinfo_triaged_error_result(void **state)
{
    int ret = 0;
    int id = 1;

    const char *query_str = "agent 1 osinfo set_triaged";
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

    ret = wdb_set_agent_sys_osinfo_triaged(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_sys_osinfo_triaged_success(void **state)
{
    int ret = 0;
    int id = 1;

    const char *query_str = "agent 1 osinfo set_triaged";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_set_agent_sys_osinfo_triaged(id, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        /* Tests wdb_get_agent_sys_osinfo */
        cmocka_unit_test_setup_teardown(test_wdb_get_sys_osinfo_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_sys_osinfo_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        /* Tests wdb_insert_vuln_cves*/
        cmocka_unit_test_setup_teardown(test_wdb_insert_vuln_cves_error_json, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_vuln_cves_null_parameters, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_vuln_cves_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_vuln_cves_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        /* Tests wdb_update_vuln_cves_status*/
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_error_json, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_error_socket, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_error_result, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        /* Tests wdb_update_vuln_cves_status_by_type*/
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_by_type_error_json, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_by_type_error_socket, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_by_type_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_by_type_error_result, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_vuln_cves_status_by_type_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        /* Tests wdb_remove_vuln_cves_by_status */
        cmocka_unit_test_setup_teardown(test_wdb_remove_vuln_cves_by_status_error_json, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_vuln_cves_by_status_error_wdb_query, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_vuln_cves_by_status_error_result, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_vuln_cves_by_status_error_json_result, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_vuln_cves_by_status_success_ok, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_vuln_cves_by_status_success_due, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        /* Tests wdb_set_agent_sys_osinfo_triaged*/
        cmocka_unit_test_setup_teardown(test_wdb_set_sys_osinfo_triaged_error_socket, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_set_sys_osinfo_triaged_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_set_sys_osinfo_triaged_error_result, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_set_sys_osinfo_triaged_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
