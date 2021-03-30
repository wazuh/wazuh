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

/* Tests wdb_agents_find_package */

void test_wdb_agents_find_package_statement_init_fail(void **state){
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_agents_find_package(data->wdb, reference);

    assert_false(ret);
}

void test_wdb_agents_find_package_success_row(void **state){
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_ROW);

    ret = wdb_agents_find_package(data->wdb, reference);

    assert_true(ret);
}

void test_wdb_agents_find_package_success_done(void **state){
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_DONE);

    ret = wdb_agents_find_package(data->wdb, reference);

    assert_false(ret);
}

void test_wdb_agents_find_package_error(void **state){
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_ERROR);
    
    will_return(__wrap_sqlite3_errmsg, "test_sql_no_done");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_sql_no_done");

    ret = wdb_agents_find_package(data->wdb, reference);

    assert_false(ret);
}

/* Tests wdb_agents_find_cve */

void test_wdb_agents_find_cve_statement_init_fail(void **state){
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_agents_find_cve(data->wdb, cve, reference);

    assert_false(ret);
}

void test_wdb_agents_find_cve_success_row(void **state){
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_ROW);

    ret = wdb_agents_find_cve(data->wdb, cve, reference);

    assert_true(ret);
}

void test_wdb_agents_find_cve_success_done(void **state){
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_DONE);

    ret = wdb_agents_find_cve(data->wdb, cve, reference);

    assert_false(ret);
}

void test_wdb_agents_find_cve_error(void **state){
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "test_sql_no_done");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_sql_no_done");

    ret = wdb_agents_find_cve(data->wdb, cve, reference);

    assert_false(ret);
}

/* Tests wdb_agents_insert_vuln_cves */

void test_wdb_agents_insert_vuln_cves_error_json(void **state)
{
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    bool check_pkg_existance = true;

    will_return(__wrap_cJSON_CreateObject, NULL);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status, check_pkg_existance);

    assert_null(ret);
}

void test_wdb_agents_insert_vuln_cves_success_pkg_not_found(void **state)
{
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    bool check_pkg_existance = true;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    
    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_ROW);

    expect_string(__wrap_cJSON_AddStringToObject, name, "action");
    expect_string(__wrap_cJSON_AddStringToObject, string, "UPDATE");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_DONE);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "PKG_NOT_FOUND");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status, check_pkg_existance);

    assert_ptr_equal(1, ret);
}

void test_wdb_agents_insert_vuln_cves_success_statement_init_fail(void **state)
{
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    bool check_pkg_existance = true;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    
    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_DONE);

    expect_string(__wrap_cJSON_AddStringToObject, name, "action");
    expect_string(__wrap_cJSON_AddStringToObject, string, "INSERT");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_ROW);

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_INSERT);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "ERROR");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status, check_pkg_existance);

    assert_ptr_equal(1, ret);
}

void test_wdb_agents_insert_vuln_cves_success_statement_exec_fail(void **state)
{
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    bool check_pkg_existance = true;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    
    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_DONE);

    expect_string(__wrap_cJSON_AddStringToObject, name, "action");
    expect_string(__wrap_cJSON_AddStringToObject, string, "INSERT");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_ROW);

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_INSERT);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, version);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, architecture);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, type);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "Exec statement error ERROR MESSAGE");

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "ERROR");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status, check_pkg_existance);

    assert_ptr_equal(1, ret);
}


void test_wdb_agents_insert_vuln_cves_success_pkg_found(void **state)
{
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    bool check_pkg_existance = true;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    
    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_DONE);

    expect_string(__wrap_cJSON_AddStringToObject, name, "action");
    expect_string(__wrap_cJSON_AddStringToObject, string, "INSERT");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);

    expect_sqlite3_step_call(SQLITE_ROW);

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_INSERT);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, version);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, architecture);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, reference);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, type);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "SUCCESS");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status, check_pkg_existance);

    assert_ptr_equal(1, ret);
}

/* Tests wdb_agents_update_status_vuln_cves*/

void test_wdb_agents_update_status_vuln_cves_statement_parameter_fail(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* old_status = "pending";
    const char* type = "OS";

    ret = wdb_agents_update_status_vuln_cves(data->wdb, old_status, NULL, type);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_update_status_vuln_cves_statement_init_fail(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* old_status = "valid";
    const char* new_status = "pending";

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_UPDATE);

    ret = wdb_agents_update_status_vuln_cves(data->wdb, old_status, new_status, NULL);

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

    ret = wdb_agents_update_status_vuln_cves(data->wdb, old_status, new_status, NULL);
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

    ret = wdb_agents_update_status_vuln_cves(data->wdb, old_status, new_status, NULL);
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_agents_update_status_vuln_cves_by_type_statement_init_fail(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* type = "OS";
    const char* new_status = "pending";

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_UPDATE_BY_TYPE);

    ret = wdb_agents_update_status_vuln_cves(data->wdb, NULL, new_status, type);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_update_status_vuln_cves_by_type_success(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* type = "OS";
    const char* new_status = "pending";

    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_UPDATE_BY_TYPE);

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, new_status);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, type);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_update_status_vuln_cves(data->wdb, NULL, new_status, type);

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

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_null(data->output);
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

    assert_null(data->output);
    assert_int_equal(ret, WDBC_ERROR);
}

void test_wdb_agents_remove_by_status_vuln_cves_error_exec_stmt_sized(void **state)
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

    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);
    expect_string(__wrap__merror, formatted_msg, "Failed to retrieve vulnerabilities with status OBSOLETE from the database");

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_null(data->output);
    assert_int_equal(ret, WDBC_ERROR);
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

    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);

    // Removing vulnerability
    will_return(__wrap_cJSON_GetObjectItem, str1);
    will_return(__wrap_cJSON_GetObjectItem, str2);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_string(__wrap__merror, formatted_msg, "Error removing vulnerability from the inventory database: cve-xxxx-yyyy");

    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_null(data->output);
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

    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);

    // Removing vulnerability
    will_return(__wrap_cJSON_GetObjectItem, str1);
    will_return(__wrap_cJSON_GetObjectItem, str2);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cve-xxxx-yyyy");
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ref-cve-xxxx-yyyy");

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_agents_remove_by_status_vuln_cves(data->wdb, status, &data->output);

    assert_string_equal(data->output, "[{\"cve\":\"cve-xxxx-yyyy\",\"reference\":\"ref-cve-xxxx-yyyy\"}]");
    assert_int_equal(ret, WDBC_OK);

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
        /* Tests wdb_agents_find_package */
        cmocka_unit_test_setup_teardown(test_wdb_agents_find_package_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_find_package_success_row, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_find_package_success_done, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_find_package_error, test_setup, test_teardown),
        /* Tests wdb_agents_find_cve */
        cmocka_unit_test_setup_teardown(test_wdb_agents_find_cve_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_find_cve_success_row, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_find_cve_success_done, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_find_cve_error, test_setup, test_teardown),
        /* Tests wdb_agents_insert_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_error_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_success_pkg_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_success_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_success_statement_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_success_pkg_found, test_setup, test_teardown),
        /* Tests wdb_agents_update_status_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_statement_parameter_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_success_all, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_by_type_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_status_vuln_cves_by_type_success, test_setup, test_teardown),
        /* Tests wdb_agents_remove_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_success, test_setup, test_teardown),
        /* Tests wdb_agents_remove_by_status_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_statement_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_error_exec_stmt_sized, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_error_removing_cve, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_by_status_vuln_cves_success, test_setup, test_teardown),
        /* Tests wdb_agents_clear_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_clear_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_clear_vuln_cves_success, test_setup, test_teardown),
      };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
