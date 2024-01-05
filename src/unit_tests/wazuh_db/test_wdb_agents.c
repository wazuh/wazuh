/*
 * Copyright (C) 2015, Wazuh Inc.
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
#include "../wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "wazuhdb_op.h"
#include "../wazuh_db/wdb_agents.h"

/* setup/teardown */

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
    init_data->wdb->peer = 1234;
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    *state = init_data;
    return 0;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

/* wrappers configurations for fail/success */

// __wrap_wdb_exec_stmt_sized

/**
 * @brief Configure a successful call to __wrap_wdb_exec_stmt_sized
 *
 * @param j_array The cJSON* array to mock
 * @param column_mode The expected column mode, STMT_MULTI_COLUMN or STMT_SINGLE_COLUMN
 */
void wrap_wdb_exec_stmt_sized_success_call(cJSON* j_array, int column_mode) {
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    expect_value(__wrap_wdb_exec_stmt_sized, column_mode, column_mode);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, j_array);
}

/**
 * @brief Configure a failed call to __wrap_wdb_exec_stmt_sized
 *
 * @param column_mode The expected column mode, STMT_MULTI_COLUMN or STMT_SINGLE_COLUMN
 */
void wrap_wdb_exec_stmt_sized_failed_call(int column_mode) {
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    expect_value(__wrap_wdb_exec_stmt_sized, column_mode, column_mode);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);
}

/* Tests wdb_agents_get_sys_osinfo */

void test_wdb_agents_get_sys_osinfo_statement_init_fail(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_OSINFO_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_agents_get_sys_osinfo(data->wdb);

    assert_null(ret);
}

void test_wdb_agents_get_sys_osinfo_exec_stmt_fail(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_OSINFO_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    ret = wdb_agents_get_sys_osinfo(data->wdb);

    assert_null(ret);
}

void test_wdb_agents_get_sys_osinfo_success(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_OSINFO_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    ret = wdb_agents_get_sys_osinfo(data->wdb);

    assert_ptr_equal(ret, (cJSON*)1);
}

/* Tests wdb_agents_find_package */

void test_wdb_agents_find_package_statement_init_fail(void **state) {
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_PROGRAM_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_agents_find_package(data->wdb, reference);

    assert_false(ret);
}

void test_wdb_agents_find_package_success_row(void **state) {
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

void test_wdb_agents_find_package_success_done(void **state) {
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

void test_wdb_agents_find_package_error(void **state) {
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
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_sql_no_done");

    ret = wdb_agents_find_package(data->wdb, reference);

    assert_false(ret);
}

/* Tests wdb_agents_find_cve */

void test_wdb_agents_find_cve_statement_init_fail(void **state) {
    bool ret = FALSE;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_FIND_CVE);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_agents_find_cve(data->wdb, cve, reference);

    assert_false(ret);
}

void test_wdb_agents_find_cve_success_row(void **state) {
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

void test_wdb_agents_find_cve_success_done(void **state) {
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

void test_wdb_agents_find_cve_error(void **state) {
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
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_sql_no_done");

    ret = wdb_agents_find_cve(data->wdb, cve, reference);

    assert_false(ret);
}

/* Tests wdb_agents_insert_vuln_cves */

void test_wdb_agents_insert_vuln_cves_error_json(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    const char* external_references = "[\"https://references.com/ref1.html\",\"https://references.com/ref2.html\"]";
    const char* condition = "Package unfixed";
    const char* title = "CVE-2021-1200 affects package";
    const char* published = "01-01-2021";
    const char* updated = "02-01-2021";
    bool check_pkg_existence = true;
    const char* severity = "Unknown";
    double cvss2_score = 0.0;
    double cvss3_score = 0.0;

    will_return(__wrap_cJSON_CreateObject, NULL);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status,
                                      check_pkg_existence, severity, cvss2_score, cvss3_score,
                                      external_references, condition, title, published, updated);

    assert_null(ret);
}

void test_wdb_agents_insert_vuln_cves_update_success(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    const char* external_references = "[\"https://references.com/ref1.html\",\"https://references.com/ref2.html\"]";
    const char* condition = "Package unfixed";
    const char* title = "CVE-2021-1200 affects package";
    const char* published = "01-01-2021";
    const char* updated = "02-01-2021";
    bool check_pkg_existence = false;
    const char* severity = "Unknown";
    double cvss2_score = 0.0;
    double cvss3_score = 0.0;

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
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, severity);
    will_return_count(__wrap_sqlite3_bind_double, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_double, index, 9);
    expect_value(__wrap_sqlite3_bind_double, value, 0.0);
    expect_value(__wrap_sqlite3_bind_double, index, 10);
    expect_value(__wrap_sqlite3_bind_double, value, 0.0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, external_references);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, condition);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, title);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, published);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, updated);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "SUCCESS");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status,
                                      check_pkg_existence, severity, cvss2_score, cvss3_score,
                                      external_references, condition, title, published, updated);
    assert_ptr_equal(1, ret);
}

void test_wdb_agents_insert_vuln_cves_pkg_not_found(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    const char* external_references = "[\"https://references.com/ref1.html\",\"https://references.com/ref2.html\"]";
    const char* condition = "Package unfixed";
    const char* title = "CVE-2021-1200 affects package";
    const char* published = "01-01-2021";
    const char* updated = "02-01-2021";
    bool check_pkg_existence = true;
    const char* severity = "Unknown";
    double cvss2_score = 0.0;
    double cvss3_score = 0.0;

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

    expect_sqlite3_step_call(SQLITE_DONE);

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
    expect_string(__wrap_sqlite3_bind_text, buffer, VULN_CVES_STATUS_OBSOLETE);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, severity);
    will_return_count(__wrap_sqlite3_bind_double, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_double, index, 9);
    expect_value(__wrap_sqlite3_bind_double, value, 0.0);
    expect_value(__wrap_sqlite3_bind_double, index, 10);
    expect_value(__wrap_sqlite3_bind_double, value, 0.0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, external_references);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, condition);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, title);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, published);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, updated);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "SUCCESS");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status,
                                      check_pkg_existence, severity, cvss2_score, cvss3_score,
                                      external_references, condition, title, published, updated);
    assert_ptr_equal(1, ret);
}

void test_wdb_agents_insert_vuln_cves_success_statement_init_fail(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    const char* external_references = "[\"https://references.com/ref1.html\",\"https://references.com/ref2.html\"]";
    const char* condition = "Package unfixed";
    const char* title = "CVE-2021-1200 affects package";
    const char* published = "01-01-2021";
    const char* updated = "02-01-2021";
    bool check_pkg_existence = true;
    const char* severity = "Unknown";
    double cvss2_score = 0.0;
    double cvss3_score = 0.0;

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

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status,
                                      check_pkg_existence, severity, cvss2_score, cvss3_score,
                                      external_references, condition, title, published, updated);
    assert_ptr_equal(1, ret);
}

void test_wdb_agents_insert_vuln_cves_success_statement_exec_fail(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    const char* external_references = "[\"https://references.com/ref1.html\",\"https://references.com/ref2.html\"]";
    const char* condition = "Package unfixed";
    const char* title = "CVE-2021-1200 affects package";
    const char* published = "01-01-2021";
    const char* updated = "02-01-2021";
    bool check_pkg_existence = true;
    const char* severity = "Unknown";
    double cvss2_score = 0.0;
    double cvss3_score = 0.0;

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
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, severity);
    will_return_count(__wrap_sqlite3_bind_double, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_double, index, 9);
    expect_value(__wrap_sqlite3_bind_double, value, 0.0);
    expect_value(__wrap_sqlite3_bind_double, index, 10);
    expect_value(__wrap_sqlite3_bind_double, value, 0.0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, external_references);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, condition);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, title);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, published);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, updated);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "Exec statement error ERROR MESSAGE");

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "ERROR");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status,
                                      check_pkg_existence, severity, cvss2_score, cvss3_score,
                                      external_references, condition, title, published, updated);
    assert_ptr_equal(1, ret);
}

void test_wdb_agents_insert_vuln_cves_success_pkg_found(void **state) {
    cJSON *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";
    const char* reference = "1c979289c63e6225fea818ff9ca83d9d0d25c46a";
    const char* type = "PACKAGE";
    const char* status = "VALID";
    const char* external_references = "[\"https://references.com/ref1.html\",\"https://references.com/ref2.html\"]";
    const char* condition = "Package unfixed";
    const char* title = "CVE-2021-1200 affects package";
    const char* published = "01-01-2021";
    const char* updated = "02-01-2021";
    bool check_pkg_existence = true;
    const char* severity = "Unknown";
    double cvss2_score = 0.0;
    double cvss3_score = 0.0;

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
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, severity);
    will_return_count(__wrap_sqlite3_bind_double, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_double, index, 9);
    expect_value(__wrap_sqlite3_bind_double, value, 0.0);
    expect_value(__wrap_sqlite3_bind_double, index, 10);
    expect_value(__wrap_sqlite3_bind_double, value, 0.0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, external_references);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, condition);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, title);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, published);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, updated);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "SUCCESS");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    ret = wdb_agents_insert_vuln_cves(data->wdb, name, version, architecture, cve, reference, type, status,
                                      check_pkg_existence, severity, cvss2_score, cvss3_score,
                                      external_references, condition, title, published, updated);
    assert_ptr_equal(1, ret);
}

/* Tests wdb_agents_update_vuln_cves_status*/

void test_wdb_agents_update_vuln_cves_status_statement_parameter_fail(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* old_status = "pending";
    const char* type = "OS";

    ret = wdb_agents_update_vuln_cves_status(data->wdb, old_status, NULL, type);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_update_vuln_cves_status_statement_init_fail(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* old_status = "valid";
    const char* new_status = "pending";

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_UPDATE);

    ret = wdb_agents_update_vuln_cves_status(data->wdb, old_status, new_status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_update_vuln_cves_status_success(void **state) {
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

    ret = wdb_agents_update_vuln_cves_status(data->wdb, old_status, new_status, NULL);
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_agents_update_vuln_cves_status_success_all(void **state) {
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

    ret = wdb_agents_update_vuln_cves_status(data->wdb, old_status, new_status, NULL);
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_agents_update_vuln_cves_status_by_type_statement_init_fail(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* type = "OS";
    const char* new_status = "pending";

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_UPDATE_BY_TYPE);

    ret = wdb_agents_update_vuln_cves_status(data->wdb, NULL, new_status, type);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_update_vuln_cves_status_by_type_success(void **state) {
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

    ret = wdb_agents_update_vuln_cves_status(data->wdb, NULL, new_status, type);

    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_agents_remove_vuln_cves */

void test_wdb_agents_remove_vuln_cves_invalid_data(void **state) {
    int ret = -1;
    const char *cve = NULL;
    const char *reference = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid data provided");

    ret = wdb_agents_remove_vuln_cves(data->wdb, cve, reference);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_remove_vuln_cves_statement_init_fail(void **state) {
    int ret = -1;
    const char *cve = "cve-xxxx-yyyy";
    const char *reference = "ref-cve-xxxx-yyyy";
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_agents_remove_vuln_cves(data->wdb, cve, reference);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_remove_vuln_cves_success(void **state) {
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

/* Tests wdb_agents_remove_vuln_cves_by_status */

void test_wdb_agents_remove_vuln_cves_by_status_statement_init_fail(void **state) {
    int ret = -1;
    const char *status = "OBSOLETE";
    test_struct_t *data  = (test_struct_t *)*state;

    // Preparing statement
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_SELECT_BY_STATUS);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_agents_remove_vuln_cves_by_status(data->wdb, status, &data->output);

    assert_null(data->output);
    assert_int_equal(ret, WDBC_ERROR);
}

void test_wdb_agents_remove_vuln_cves_by_status_statement_bind_fail(void **state) {
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

    ret = wdb_agents_remove_vuln_cves_by_status(data->wdb, status, &data->output);

    assert_null(data->output);
    assert_int_equal(ret, WDBC_ERROR);
}

void test_wdb_agents_remove_vuln_cves_by_status_error_exec_stmt_sized(void **state) {
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
    wrap_wdb_exec_stmt_sized_failed_call(STMT_MULTI_COLUMN);

    expect_string(__wrap__merror, formatted_msg, "Failed to retrieve vulnerabilities with status OBSOLETE from the database");

    ret = wdb_agents_remove_vuln_cves_by_status(data->wdb, status, &data->output);

    assert_null(data->output);
    assert_int_equal(ret, WDBC_ERROR);
}

void test_wdb_agents_remove_vuln_cves_by_status_error_removing_cve(void **state) {
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
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_MULTI_COLUMN);

    // Removing vulnerability
    will_return(__wrap_cJSON_GetObjectItem, str1);
    will_return(__wrap_cJSON_GetObjectItem, str2);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVES_DELETE_ENTRY);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_string(__wrap__merror, formatted_msg, "Error removing vulnerability from the inventory database: cve-xxxx-yyyy");

    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_agents_remove_vuln_cves_by_status(data->wdb, status, &data->output);

    assert_null(data->output);
    assert_int_equal(ret, WDBC_ERROR);

    __real_cJSON_Delete(root);
}

void test_wdb_agents_remove_vuln_cves_by_status_success(void **state) {
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
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_MULTI_COLUMN);

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

    ret = wdb_agents_remove_vuln_cves_by_status(data->wdb, status, &data->output);

    assert_string_equal(data->output, "[{\"cve\":\"cve-xxxx-yyyy\",\"reference\":\"ref-cve-xxxx-yyyy\"}]");
    assert_int_equal(ret, WDBC_OK);

    __real_cJSON_Delete(root);
}

/* Tests wdb_agents_set_sys_osinfo_triaged */

void test_wdb_agents_set_sys_osinfo_triaged_statement_init_fail(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_OSINFO_SET_TRIAGED);

    ret = wdb_agents_set_sys_osinfo_triaged(data->wdb);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_set_sys_osinfo_triaged_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_OSINFO_SET_TRIAGED);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_set_sys_osinfo_triaged(data->wdb);

    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_agents_set_packages_triaged */

void test_wdb_agents_set_packages_triaged_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_SET_TRIAGED);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    int ret = wdb_agents_set_packages_triaged(data->wdb);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_set_packages_triaged_stmt_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_SET_TRIAGED);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    int ret = wdb_agents_set_packages_triaged(data->wdb);

    assert_int_equal (OS_INVALID, ret);
}

/* wdb_agents_send_packages */

void test_wdb_agents_send_packages_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_SUCCESS);

    int ret = wdb_agents_send_packages(data->wdb, FALSE);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_send_packages_not_triaged_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_GET_NOT_TRIAGED);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_SUCCESS);

    int ret = wdb_agents_send_packages(data->wdb, TRUE);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_send_packages_stmt_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    int ret = wdb_agents_send_packages(data->wdb, FALSE);

    assert_int_equal (OS_INVALID, ret);
}

/* wdb_agents_send_hotfixes */

void test_wdb_agents_send_hotfixes_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_HOTFIXES_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_SUCCESS);

    int ret = wdb_agents_send_hotfixes(data->wdb);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_send_hotfixes_stmt_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_HOTFIXES_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    int ret = wdb_agents_send_hotfixes(data->wdb);

    assert_int_equal (OS_INVALID, ret);
}

/* Tests wdb_agents_get_packages */

void test_wdb_agents_get_packages_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_PACKAGES);
    will_return(__wrap_wdbi_check_sync_status, 1);

    /* wdb_agents_send_packages */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_SUCCESS);

    /* wdb_agents_set_packages_triaged */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_SET_TRIAGED);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "SUCCESS");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_packages(data->wdb, FALSE, &status_response);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_get_packages_not_synced(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_PACKAGES);
    will_return(__wrap_wdbi_check_sync_status, 0);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "NOT_SYNCED");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_packages(data->wdb, FALSE, &status_response);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_get_packages_sync_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_PACKAGES);
    will_return(__wrap_wdbi_check_sync_status, OS_INVALID);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "ERROR");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_packages(data->wdb, FALSE, &status_response);

    assert_int_equal (OS_INVALID, ret);
}

void test_wdb_agents_get_packages_send_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_PACKAGES);
    will_return(__wrap_wdbi_check_sync_status, 1);

    /* wdb_agents_send_packages */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_INVALID);


    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "ERROR");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_packages(data->wdb, FALSE, &status_response);

    assert_int_equal (OS_INVALID, ret);
}

void test_wdb_agents_get_packages_set_triaged_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_PACKAGES);
    will_return(__wrap_wdbi_check_sync_status, 1);

    /* wdb_agents_send_packages */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_SUCCESS);

    /* wdb_agents_set_packages_triaged */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_SET_TRIAGED);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "ERROR");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_packages(data->wdb, FALSE, &status_response);

    assert_int_equal (OS_INVALID, ret);
}

/* Tests wdb_agents_get_hotfixes */

void test_wdb_agents_get_hotfixes_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_HOTFIXES);
    will_return(__wrap_wdbi_check_sync_status, 1);

    /* wdb_agents_send_hotfixes */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_HOTFIXES_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_SUCCESS);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "SUCCESS");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_hotfixes(data->wdb, &status_response);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_get_hotfixes_not_synced(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_HOTFIXES);
    will_return(__wrap_wdbi_check_sync_status, 0);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "NOT_SYNCED");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_hotfixes(data->wdb, &status_response);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_get_hotfixes_sync_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_HOTFIXES);
    will_return(__wrap_wdbi_check_sync_status, OS_INVALID);

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "ERROR");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_hotfixes(data->wdb, &status_response);

    assert_int_equal (OS_INVALID, ret);
}

void test_wdb_agents_get_hotfixes_send_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    /* wdbi_check_sync_status */
    expect_value(__wrap_wdbi_check_sync_status, component, WDB_SYSCOLLECTOR_HOTFIXES);
    will_return(__wrap_wdbi_check_sync_status, 1);

    /* wdb_agents_send_hotfixes */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_HOTFIXES_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_INVALID);


    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "ERROR");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_hotfixes(data->wdb, &status_response);

    assert_int_equal (OS_INVALID, ret);
}

int main()
{
    const struct CMUnitTest tests[] = {
        /* Tests wdb_agents_get_sys_osinfo */
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_sys_osinfo_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_sys_osinfo_exec_stmt_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_sys_osinfo_success, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_update_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_pkg_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_success_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_success_statement_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cves_success_pkg_found, test_setup, test_teardown),
        /* Tests wdb_agents_update_vuln_cves_status */
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_vuln_cves_status_statement_parameter_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_vuln_cves_status_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_vuln_cves_status_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_vuln_cves_status_success_all, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_vuln_cves_status_by_type_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_update_vuln_cves_status_by_type_success, test_setup, test_teardown),
        /* Tests wdb_agents_remove_vuln_cves */
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_success, test_setup, test_teardown),
        /* Tests wdb_agents_remove_vuln_cves_by_status */
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_by_status_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_by_status_statement_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_by_status_error_exec_stmt_sized, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_by_status_error_removing_cve, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_remove_vuln_cves_by_status_success, test_setup, test_teardown),
        /* Tests wdb_agents_set_sys_osinfo_triaged */
        cmocka_unit_test_setup_teardown(test_wdb_agents_set_sys_osinfo_triaged_statement_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_set_sys_osinfo_triaged_success, test_setup, test_teardown),
        /* Tests wdb_agents_set_packages_triaged */
        cmocka_unit_test_setup_teardown(test_wdb_agents_set_packages_triaged_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_set_packages_triaged_stmt_err, test_setup, test_teardown),
        /* Tests wdb_agents_send_packages */
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_packages_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_packages_not_triaged_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_packages_stmt_err, test_setup, test_teardown),
        /* Tests wdb_agents_send_hotfixes */
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_hotfixes_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_hotfixes_stmt_err, test_setup, test_teardown),
        /* wdb_agents_get_packages */
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_not_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_sync_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_send_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_set_triaged_err, test_setup, test_teardown),
        /* Tests wdb_agents_get_hotfixes */
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_hotfixes_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_hotfixes_not_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_hotfixes_sync_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_hotfixes_send_err, test_setup, test_teardown),
      };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
