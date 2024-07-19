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

/* wdb_agents_send_packages */

void test_wdb_agents_send_packages_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_exec_stmt_send, peer, 1234);
    will_return(__wrap_wdb_exec_stmt_send, OS_SUCCESS);

    int ret = wdb_agents_send_packages(data->wdb);

    assert_int_equal (OS_SUCCESS, ret);
}

void test_wdb_agents_send_packages_stmt_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_SYS_PROGRAMS_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    int ret = wdb_agents_send_packages(data->wdb);

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

    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "SUCCESS");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    cJSON *status_response = NULL;
    int ret = wdb_agents_get_packages(data->wdb, &status_response);

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
    int ret = wdb_agents_get_packages(data->wdb, &status_response);

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
    int ret = wdb_agents_get_packages(data->wdb, &status_response);

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
    int ret = wdb_agents_get_packages(data->wdb, &status_response);

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
        /* Tests wdb_agents_send_packages */
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_packages_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_packages_stmt_err, test_setup, test_teardown),
        /* Tests wdb_agents_send_hotfixes */
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_hotfixes_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_send_hotfixes_stmt_err, test_setup, test_teardown),
        /* wdb_agents_get_packages */
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_not_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_sync_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_packages_send_err, test_setup, test_teardown),
        /* Tests wdb_agents_get_hotfixes */
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_hotfixes_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_hotfixes_not_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_hotfixes_sync_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_get_hotfixes_send_err, test_setup, test_teardown),
      };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
