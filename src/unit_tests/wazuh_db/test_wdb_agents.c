/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 * March, 2021.
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

#include "os_err.h"
#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "wazuhdb_op.h"
#include "wazuh_db/wdb_agents.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

/* Tests wdb_agents_insert_vuln_cves */

void test_wdb_agents_insert_vuln_cves_statement_init_fail(void **state)
{
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_INSERT);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_insert_vuln_cves_success(void **state)
{
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";

    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_INSERT);

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, version);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, architecture);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve);

    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_agents_update_status_vuln_cves*/

void test_wdb_agents_update_status_vuln_cves_statement_init_fail(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* old_status = "valid";
    const char* new_status = "pending";

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_UPDATE);

    ret = wdb_agents_update_status_vuln_cves(data->wdb, old_status, new_status);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_update_status_vuln_cves_success(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* old_status = "valid";
    const char* new_status = "pending";

    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_UPDATE);

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, new_status);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, old_status);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_update_status_vuln_cves(data->wdb, old_status, new_status);
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_agents_update_status_vuln_cves_success_all(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* old_status = "*";
    const char* new_status = "pending";

    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_UPDATE_ALL);

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, new_status);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_update_status_vuln_cves(data->wdb, old_status, new_status);
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_agents_remove_vuln_cves */

void test_wdb_agents_remove_vuln_cves_invalid_data(void **state)
{
    int ret = -1;
    const char *cve = NULL;
    const char *reference = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid data provided");

    ret = wdb_agents_remove_vuln_cves(data->wdb, cve, reference);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_remove_vuln_cves_statement_init_fail(void **state)
{
    int ret = -1;
    const char *cve = "cve-xxxx-yyyy";
    const char *reference = "ref-cve-xxxx-yyyy";
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_agents_remove_vuln_cves(data->wdb, cve, reference);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_remove_vuln_cves_success(void **state)
{
    int ret = -1;
    const char *cve = "cve-xxxx-yyyy";
    const char *reference = "ref-cve-xxxx-yyyy";
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_remove_vuln_cves(data->wdb, cve, reference);

    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_agents_remove_by_status_vuln_cves */

void test_wdb_agents_remove_by_status_vuln_cves_statement_init_fail(void **state)
{
    int ret = -1;
    const char *status = "OBSOLETE";
    test_struct_t *data  = (test_struct_t *)*state;

    // Preparing statement
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_SELECT_BY_STATUS);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_string_equal(data->output, "Cannot cache statement");
    assert_int_equal(ret, WDBC_ERROR);
}

void test_wdb_agents_remove_by_status_vuln_cves_statement_bind_fail(void **state)
{
    int ret = -1;
    const char *status = "OBSOLETE";
    test_struct_t *data  = (test_struct_t *)*state;

    // Preparing statement
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_SELECT_BY_STATUS);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    will_return_count(__wrap_sqlite3_bind_text, SQLITE_ERROR, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);

    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_text(): ERROR MESSAGE");

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_string_equal(data->output, "Cannot bind sql statement");
    assert_int_equal(ret, WDBC_ERROR);
}

void test_wdb_agents_remove_by_status_vuln_cves_no_cves_for_detele(void **state)
{
    int ret = -1;
    const char *status = "OBSOLETE";
    test_struct_t *data  = (test_struct_t *)*state;

    // Preparing statement
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_SELECT_BY_STATUS);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    will_return_count(__wrap_sqlite3_bind_text, SQLITE_OK, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);

    // Executing statement
    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_string_equal(data->output, "[]");
    assert_int_equal(ret, WDBC_OK);
}

void test_wdb_agents_remove_by_status_vuln_cves_error_removing_cve(void **state)
{
    int ret = -1;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str1 = NULL;
    cJSON *str2 = NULL;
    const char *status = "OBSOLETE";
    test_struct_t *data  = (test_struct_t *)*state;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str1 = __real_cJSON_CreateString("cve-xxxx-yyyy");
    __real_cJSON_AddItemToObject(row, "cve", str1);
    str2 = __real_cJSON_CreateString("ref-cve-xxxx-yyyy");
    __real_cJSON_AddItemToObject(row, "reference", str2);
    __real_cJSON_AddItemToArray(root, row);

    // Preparing statement
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_SELECT_BY_STATUS);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    will_return_count(__wrap_sqlite3_bind_text, SQLITE_OK, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);

    // Executing statement
    will_return(__wrap_wdb_exec_stmt, root);
    will_return(__wrap_cJSON_GetObjectItem, str1);
    will_return(__wrap_cJSON_GetObjectItem, str2);

    // Removing vulnerability
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_string(__wrap__merror, formatted_msg, "Error removing vulnerability from the inventory database: cve-xxxx-yyyy");

    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_string_equal(data->output, "Error removing vulnerability from the inventory database:  cve-xxxx-yyyy");
    assert_int_equal(ret, WDBC_ERROR);

    __real_cJSON_Delete(root);
}

void test_wdb_agents_remove_by_status_vuln_cves_success(void **state)
{
    int ret = -1;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str1 = NULL;
    cJSON *str2 = NULL;
    const char *status = "OBSOLETE";
    test_struct_t *data  = (test_struct_t *)*state;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str1 = __real_cJSON_CreateString("cve-xxxx-yyyy");
    __real_cJSON_AddItemToObject(row, "cve", str1);
    str2 = __real_cJSON_CreateString("ref-cve-xxxx-yyyy");
    __real_cJSON_AddItemToObject(row, "reference", str2);
    __real_cJSON_AddItemToArray(root, row);

    // Preparing statement
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_SELECT_BY_STATUS);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    will_return_count(__wrap_sqlite3_bind_text, SQLITE_OK, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);

    // Executing statement first time
    will_return(__wrap_wdb_exec_stmt, root);
    will_return(__wrap_cJSON_GetObjectItem, str1);
    will_return(__wrap_cJSON_GetObjectItem, str2);

    // Removing vulnerability
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cve-xxxx-yyyy");
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ref-cve-xxxx-yyyy");

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
    expect_function_call(__wrap_cJSON_Delete);

    // Executing statement second time
    will_return(__wrap_wdb_exec_stmt, root);
    will_return(__wrap_cJSON_GetObjectItem, str1);
    will_return(__wrap_cJSON_GetObjectItem, str2);

    // Removing vulnerability
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cve-xxxx-yyyy");
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ref-cve-xxxx-yyyy");

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
    expect_function_call(__wrap_cJSON_Delete);

    // Executing statement third time
    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_string_equal(data->output, "[{\"cve\":\"cve-xxxx-yyyy\",\"reference\":\"ref-cve-xxxx-yyyy\"},{\"cve\":\"cve-xxxx-yyyy\",\"reference\":\"ref-cve-xxxx-yyyy\"}]");
    assert_int_equal(ret, WDBC_OK);

    __real_cJSON_Delete(root);
}

void test_wdb_agents_remove_by_status_vuln_cves_full(void **state)
{
    int ret = -1;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str1 = NULL;
    cJSON *str2 = NULL;
    const char *status = "OBSOLETE";
    test_struct_t *data  = (test_struct_t *)*state;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str1 = __real_cJSON_CreateString("cve-xxxx-yyyy");
    __real_cJSON_AddItemToObject(row, "cve", str1);
    str2 = __real_cJSON_CreateString("ref-cve-xxxx-yyyy");
    __real_cJSON_AddItemToObject(row, "reference", str2);
    __real_cJSON_AddItemToArray(root, row);
    // Creating a cJSON array bigger than WDB_MAX_RESPONSE_SIZE
    for(int i = 0; i < 2500; i++){
        __real_cJSON_AddStringToObject(row,"test_field", "test_value");
    }

    // Preparing statement
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_SELECT_BY_STATUS);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    will_return_count(__wrap_sqlite3_bind_text, SQLITE_OK, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);

    // Executing statement first time
    will_return(__wrap_wdb_exec_stmt, root);
    will_return(__wrap_cJSON_GetObjectItem, str1);
    will_return(__wrap_cJSON_GetObjectItem, str2);
    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_string_equal(data->output, "[]");
    assert_int_equal(ret, WDBC_DUE);

    __real_cJSON_Delete(root);
}

/* Tests wdb_agents_clear_vuln_cves */

void test_wdb_agents_clear_vuln_cves_statement_init_fail(void **state)
{
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_CLEAR);

    ret = wdb_agents_clear_vuln_cves(data->wdb);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_clear_vuln_cves_success(void **state)
{
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_CLEAR);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_clear_vuln_cves(data->wdb);

    assert_int_equal(ret, OS_SUCCESS);
}

int main()
{
    const struct CMUnitTest tests[] = {
        /* Tests wdb_agents_insert_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_success, test_setup, test_teardown),
        /* Tests wdb_agents_update_status_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_success_all, test_setup, test_teardown),
        /* Tests wdb_agents_remove_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_success, test_setup, test_teardown),
        /* Tests wdb_agents_remove_by_status_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_statement_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_no_cves_for_detele, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_error_removing_cve, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_full, test_setup, test_teardown),
        /* Tests wdb_agents_clear_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_clear_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_clear_vuln_cves_success, test_setup, test_teardown),
      };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
