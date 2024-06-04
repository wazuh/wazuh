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
#include <string.h>
#include <stdlib.h>

#include "../wazuh_db/wdb.h"
#include "wazuhdb_op.h"
#include "hash_op.h"

#include "../wrappers/common.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/libc/string_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"

int wdb_execute_non_select_query(wdb_t * wdb, const char *query);
int wdb_select_from_temp_table(wdb_t * wdb);
int wdb_get_last_vacuum_data(wdb_t * wdb, int *last_vacuum_time, int *last_vacuum_value);
int wdb_execute_single_int_select_query(wdb_t * wdb, const char *query, int *value);

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

int __wrap_getuid(void) {
    return mock();
}

/* setup/teardown */

int setup_wdb(void **state) {

    test_mode = 1;

    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    init_data->wdb->stmt[0] = (sqlite3_stmt*)1;
    *state = init_data;
    return 0;
}

int teardown_wdb(void **state) {
    test_mode = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

int wazuh_db_config_setup() {
    wdb_init_conf();

    return OS_SUCCESS;
}

int  wazuh_db_config_teardown() {
    wdb_free_conf();

    return OS_SUCCESS;
}

/* Tests wdb_open_global */

void test_wdb_open_tasks_pool_success_wdb_in_pool_db_open(void **state)
{
    wdb_t *ret = NULL;

    wdb_t *node = wdb_init(WDB_TASK_NAME);
    node->db = (sqlite3 *)1;

    expect_string(__wrap_wdb_pool_get_or_create, name, WDB_TASK_NAME);
    will_return(__wrap_wdb_pool_get_or_create, node);

    ret = wdb_open_tasks();

    assert_string_equal(ret->id, WDB_TASK_NAME);
    assert_non_null(ret->db);
    wdb_destroy(ret);
}

void test_wdb_open_tasks_pool_success_wdb_in_pool_db_null(void **state)
{
    wdb_t *ret = NULL;

    wdb_t *node = wdb_init(WDB_TASK_NAME);
    sqlite3 *db = (sqlite3 *)1;

    expect_string(__wrap_wdb_pool_get_or_create, name, WDB_TASK_NAME);
    will_return(__wrap_wdb_pool_get_or_create, node);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/tasks/tasks.db");
    will_return(__wrap_sqlite3_open_v2, db);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_SUCCESS);

    ret = wdb_open_tasks();

    assert_string_equal(ret->id, WDB_TASK_NAME);
    assert_non_null(ret->db);
    wdb_destroy(ret);
}

void test_wdb_open_tasks_create_error(void **state)
{
    wdb_t *ret = NULL;
    wdb_t *node = wdb_init(WDB_TASK_NAME);

    expect_string(__wrap_wdb_pool_get_or_create, name, WDB_TASK_NAME);
    will_return(__wrap_wdb_pool_get_or_create, node);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/tasks/tasks.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Tasks database not found, creating.");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_pool_leave);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/tasks/tasks.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);

    will_return(__wrap_sqlite3_errmsg, "out of memory");
    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't create SQLite database 'queue/tasks/tasks.db': out of memory");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database 'queue/tasks/tasks.db'");

    ret = wdb_open_tasks();

    assert_null(ret);
    wdb_destroy(node);
}

void test_wdb_open_tasks_retry_open_error(void **state)
{
    wdb_t *ret = NULL;
    wdb_t *node = wdb_init(WDB_TASK_NAME);
    sqlite3 *db = (sqlite3 *)1;

    expect_string(__wrap_wdb_pool_get_or_create, name, WDB_TASK_NAME);
    will_return(__wrap_wdb_pool_get_or_create, node);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/tasks/tasks.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Tasks database not found, creating.");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    // wdb_create_file ok
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/tasks/tasks.db");
    will_return(__wrap_sqlite3_open_v2, db);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, OS_SUCCESS);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);
    will_return(__wrap_getuid, 1);
    expect_string(__wrap__mdebug1, formatted_msg, "Ignoring chown when creating file from SQL.");
    expect_string(__wrap_chmod, path, "queue/tasks/tasks.db");
    will_return(__wrap_chmod, 0);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/tasks/tasks.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);


    will_return(__wrap_sqlite3_errmsg, "out of memory");
    expect_string(__wrap__merror, formatted_msg, "Can't open SQLite database 'queue/tasks/tasks.db': out of memory");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_open_tasks();

    assert_null(ret);
    wdb_destroy(node);
}

void test_wdb_open_global_pool_success_wdb_in_pool_db_open(void **state)
{
    wdb_t *ret = NULL;

    wdb_t *node = wdb_init(WDB_GLOB_NAME);
    node->db = (sqlite3 *)1;

    expect_string(__wrap_wdb_pool_get_or_create, name, WDB_GLOB_NAME);
    will_return(__wrap_wdb_pool_get_or_create, node);

    ret = wdb_open_global();

    assert_string_equal(ret->id, WDB_GLOB_NAME);
    assert_non_null(ret->db);
    wdb_destroy(ret);
}

void test_wdb_open_global_create_error(void **state)
{
    wdb_t *ret = NULL;
    wdb_t *node = wdb_init(WDB_GLOB_NAME);

    expect_string(__wrap_wdb_pool_get_or_create, name, WDB_GLOB_NAME);
    will_return(__wrap_wdb_pool_get_or_create, node);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Global database not found, creating.");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_pool_leave);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);

    will_return(__wrap_sqlite3_errmsg, "out of memory");
    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db': out of memory");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db'");

    ret = wdb_open_global();

    assert_null(ret);
    wdb_destroy(node);
}

/* Tests wdb_exec_row_stmt_multi_column */

void test_wdb_exec_row_stmt_multi_column_one_int(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, json_value);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt_multi_column(*data->wdb->stmt, &status);

    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_string_equal(result->child->string, json_str);
    assert_int_equal(result->child->valuedouble, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_row_stmt_multi_column_multiple_int(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int columns = 10;
    char json_strs[columns][OS_SIZE_256];
    for (int column=0; column < columns; column++){
        snprintf(json_strs[column], OS_SIZE_256, "COLUMN%d",column);
    }

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, columns);
    for (int column=0; column < columns; column++){
        expect_value(__wrap_sqlite3_column_type, i, column);
        will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
        expect_value(__wrap_sqlite3_column_name, N, column);
        will_return(__wrap_sqlite3_column_name, json_strs[column]);
        expect_value(__wrap_sqlite3_column_double, iCol, column);
        will_return(__wrap_sqlite3_column_double, column);
    }

    int status = 0;
    cJSON* result = wdb_exec_row_stmt_multi_column(*data->wdb->stmt, &status);

    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    cJSON* json_column = NULL;
    int column = 0;
    cJSON_ArrayForEach(json_column, result) {
        assert_string_equal(json_column->string, json_strs[column]);
        assert_int_equal(json_column->valuedouble, column);
        column++;
    }

    cJSON_Delete(result);
}

void test_wdb_exec_row_stmt_multi_column_one_text(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    const char*  json_value = "VALUE";

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, json_value);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt_multi_column(*data->wdb->stmt, &status);
    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_string_equal(result->child->string, json_str);
    assert_string_equal(result->child->valuestring, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_row_stmt_multi_column_done(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_DONE);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt_multi_column(*data->wdb->stmt, &status);

    assert_null(result);
    assert_int_equal(status, SQLITE_DONE);
    assert_null(result);
}

void test_wdb_exec_row_stmt_multi_column_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    int status = 0;
    cJSON* result = wdb_exec_row_stmt_multi_column(*data->wdb->stmt, &status);
    assert_int_equal(status, SQLITE_ERROR);
    assert_null(result);
}

/* Tests wdb_exec_stmt_sized */

void test_wdb_exec_stmt_sized_success_single_column_string(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    char col_text[4][16] = { 0 };
    int status = SQLITE_ERROR;

    for (int i = 0; i < 4; ++i) {
        expect_sqlite3_step_call(SQLITE_ROW);
        will_return(__wrap_sqlite3_column_count, 1);
        expect_value(__wrap_sqlite3_column_type, i, 0);
        will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
        snprintf(col_text[i], 16, "COL_TEXT_%d", i);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, col_text[i]);
    }

    expect_sqlite3_step_call(SQLITE_DONE);

    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, WDB_MAX_RESPONSE_SIZE, &status, STMT_SINGLE_COLUMN);
    char* ret_str = cJSON_PrintUnformatted(result);

    assert_string_equal("[\"COL_TEXT_0\",\"COL_TEXT_1\",\"COL_TEXT_2\",\"COL_TEXT_3\"]", ret_str);
    assert_int_equal(status, SQLITE_DONE);
    cJSON_Delete(result);
    free(ret_str);
}

void test_wdb_exec_stmt_sized_success_single_column_value(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    int status = SQLITE_ERROR;

    for (int i = 0; i < 4; ++i) {
        expect_sqlite3_step_call(SQLITE_ROW);
        will_return(__wrap_sqlite3_column_count, 1);
        expect_value(__wrap_sqlite3_column_type, i, 0);
        will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
        expect_value(__wrap_sqlite3_column_double, iCol, 0);
        will_return(__wrap_sqlite3_column_double, i + 1);
    }

    expect_sqlite3_step_call(SQLITE_DONE);

    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, WDB_MAX_RESPONSE_SIZE, &status, STMT_SINGLE_COLUMN);
    char* ret_str = cJSON_PrintUnformatted(result);

    assert_string_equal("[1,2,3,4]", ret_str);
    assert_int_equal(status, SQLITE_DONE);
    cJSON_Delete(result);
    free(ret_str);
}

void test_wdb_exec_stmt_sized_success_multi_column(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return_count(__wrap_sqlite3_column_count, 1, -1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER,-1);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return_count(__wrap_sqlite3_column_name, json_str, -1);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return_count(__wrap_sqlite3_column_double, json_value, -1);

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, WDB_MAX_RESPONSE_SIZE, &status, STMT_MULTI_COLUMN);

    assert_int_equal(status, SQLITE_DONE);
    assert_non_null(result);
    assert_string_equal(result->child->child->string, json_str);
    assert_int_equal(result->child->child->valuedouble, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_stmt_sized_success_limited(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;
    const int rows = 20;
    const int max_size = 282;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_count(SQLITE_ROW, rows);
    will_return_count(__wrap_sqlite3_column_count, 1, -1);
    expect_any_count(__wrap_sqlite3_column_type, i, -1);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER, -1);
    expect_any_count(__wrap_sqlite3_column_name, N, -1);
    will_return_count(__wrap_sqlite3_column_name, json_str, -1);
    expect_any_count(__wrap_sqlite3_column_double, iCol, -1);
    will_return_count(__wrap_sqlite3_column_double, json_value, -1);

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, max_size, &status, STMT_MULTI_COLUMN);

    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_int_equal(cJSON_GetArraySize(result), rows-1);

    cJSON_Delete(result);
}

void test_wdb_exec_stmt_sized_invalid_statement(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid SQL statement.");

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(NULL, WDB_MAX_RESPONSE_SIZE, &status, STMT_MULTI_COLUMN);

    assert_int_equal(status, SQLITE_ERROR);
    assert_null(result);
}

void test_wdb_exec_stmt_sized_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, WDB_MAX_RESPONSE_SIZE, &status, STMT_MULTI_COLUMN);

    assert_int_equal(status, SQLITE_ERROR);
    assert_null(result);

    cJSON_Delete(result);
}

/* Tests wdb_exec_stmt */

void test_wdb_exec_stmt_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return_count(__wrap_sqlite3_column_count, 1, -1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER,-1);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return_count(__wrap_sqlite3_column_name, json_str, -1);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return_count(__wrap_sqlite3_column_double, json_value, -1);

    cJSON* result = wdb_exec_stmt(*data->wdb->stmt);

    assert_non_null(result);
    assert_string_equal(result->child->child->string, json_str);
    assert_int_equal(result->child->child->valuedouble, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_stmt_invalid_statement(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid SQL statement.");

    cJSON* result = wdb_exec_stmt(NULL);

    assert_null(result);
}

void test_wdb_exec_stmt_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    cJSON* result = wdb_exec_stmt(*data->wdb->stmt);
    assert_null(result);

    cJSON_Delete(result);
}

/* Tests wdb_exec_stmt_silent */

void test_wdb_exec_stmt_silent_success_sqlite_done(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_DONE);

    int result = wdb_exec_stmt_silent(*data->wdb->stmt);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_exec_stmt_silent_success_sqlite_row(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_ROW);

    int result = wdb_exec_stmt_silent(*data->wdb->stmt);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_exec_stmt_silent_invalid(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    int result = wdb_exec_stmt_silent(*data->wdb->stmt);

    assert_int_equal(result, OS_INVALID);
}

/* Tests wdb_exec_stmt_send */

void test_wdb_exec_stmt_send_single_row_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;
    const char* json_str = "COLUMN";
    double json_value = 10;
    cJSON* j_query_result = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_query_result, json_str, json_value);
    char* str_query_result = cJSON_PrintUnformatted(j_query_result);
    char* command_result = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), command_result);

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return(__wrap_sqlite3_column_double, json_value);
    expect_sqlite3_step_call(SQLITE_DONE);

    os_snprintf(command_result, OS_MAXSTR, "due %s", str_query_result);
    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(command_result));
    expect_string(__wrap_OS_SendSecureTCP, msg, command_result);
    will_return(__wrap_OS_SendSecureTCP, 0);

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SUCCESS);

    cJSON_Delete(j_query_result);
    os_free(str_query_result);
    os_free(command_result);
}

void test_wdb_exec_stmt_send_multiple_rows_success(void **state) {
    int ROWS_RESPONSE = 100;
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;
    const char* json_str = "COLUMN";
    double json_value = 10;
    cJSON* j_query_result = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_query_result, json_str, json_value);
    char* str_query_result = cJSON_PrintUnformatted(j_query_result);
    char* command_result = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), command_result);

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_count(SQLITE_ROW, ROWS_RESPONSE);
    will_return_count(__wrap_sqlite3_column_count, 1, ROWS_RESPONSE);
    expect_any_count(__wrap_sqlite3_column_type, i, ROWS_RESPONSE);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER, ROWS_RESPONSE);
    expect_any_count(__wrap_sqlite3_column_name, N, ROWS_RESPONSE);
    will_return_count(__wrap_sqlite3_column_name, json_str, ROWS_RESPONSE);
    expect_any_count(__wrap_sqlite3_column_double, iCol, ROWS_RESPONSE);
    will_return_count(__wrap_sqlite3_column_double, json_value, ROWS_RESPONSE);
    expect_sqlite3_step_call(SQLITE_DONE);

    os_snprintf(command_result, OS_MAXSTR, "due %s", str_query_result);
    expect_value_count(__wrap_OS_SendSecureTCP, sock, peer, ROWS_RESPONSE);
    expect_value_count(__wrap_OS_SendSecureTCP, size, strlen(command_result), ROWS_RESPONSE);
    expect_string_count(__wrap_OS_SendSecureTCP, msg, command_result, ROWS_RESPONSE);
    will_return_count(__wrap_OS_SendSecureTCP, 0, ROWS_RESPONSE);

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SUCCESS);

    cJSON_Delete(j_query_result);
    os_free(str_query_result);
    os_free(command_result);
}

void test_wdb_exec_stmt_send_no_rows_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_DONE);

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_exec_stmt_send_row_size_limit_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;
    const char* json_str = "COLUMN";
    char* json_value = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), json_value);
    memset(json_value,'A',OS_MAXSTR-1);
    cJSON* j_query_result = cJSON_CreateObject();
    cJSON_AddStringToObject(j_query_result, json_str, json_value);
    char* str_query_result = cJSON_PrintUnformatted(j_query_result);

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_any(__wrap_sqlite3_column_text, iCol);
    will_return(__wrap_sqlite3_column_text, json_value);

    will_return(__wrap_sqlite3_sql, "STATEMENT");
    expect_string(__wrap__merror, formatted_msg, "SQL row response for statement STATEMENT is too big to be sent");

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SIZELIM);

    cJSON_Delete(j_query_result);
    os_free(str_query_result);
    os_free(json_value);
}

void test_wdb_exec_stmt_send_socket_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;
    const char* json_str = "COLUMN";
    double json_value = 10;
    cJSON* j_query_result = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_query_result, json_str, json_value);
    char* str_query_result = cJSON_PrintUnformatted(j_query_result);
    char* command_result = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), command_result);

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return(__wrap_sqlite3_column_double, json_value);

    os_snprintf(command_result, OS_MAXSTR, "due %s", str_query_result);
    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(command_result));
    expect_string(__wrap_OS_SendSecureTCP, msg, command_result);
    will_return(__wrap_OS_SendSecureTCP, -1);

    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "Socket 1234 error: error (0)");

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SOCKTERR);

    cJSON_Delete(j_query_result);
    os_free(str_query_result);
    os_free(command_result);
}

void test_wdb_exec_stmt_send_timeout_set_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;

    will_return(__wrap_OS_SetSendTimeout, -1);

    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "Socket 1234 error setting timeout: error (0)");

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SOCKTERR);
}

void test_wdb_exec_stmt_send_statement_invalid(void **state) {
    int peer = 1234;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid SQL statement.");

    int result = wdb_exec_stmt_send(NULL, peer);

    assert_int_equal(result, OS_INVALID);
}

/* Tests wdb_init_stmt_in_cache */

void test_wdb_init_stmt_in_cache_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return_always(__wrap_time, 0);

    // wdb_begin2
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_stmt_cache
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    sqlite3_stmt* result = wdb_init_stmt_in_cache(data->wdb, WDB_STMT_FIM_LOAD);

    assert_non_null(result);
}

void test_wdb_init_stmt_in_cache_invalid_transaction(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    // wdb_begin2
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    sqlite3_stmt* result = wdb_init_stmt_in_cache(data->wdb, 0);

    assert_null(result);
}

void test_wdb_init_stmt_in_cache_invalid_statement(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int STR_SIZE = 48;
    char error_message[STR_SIZE];
    snprintf(error_message, STR_SIZE, "DB(000) SQL statement index (%d) out of bounds", WDB_STMT_SIZE);

    will_return_always(__wrap_time, 0);

    // wdb_begin2
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_stmt_cache
    expect_string(__wrap__merror, formatted_msg, error_message);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    sqlite3_stmt* result = wdb_init_stmt_in_cache(data->wdb,WDB_STMT_SIZE);

    assert_null(result);
}

void test_wdb_get_internal_config() {
    cJSON *ret = wdb_get_internal_config();
    assert_true(cJSON_IsObject(ret));

    cJSON* root = cJSON_GetObjectItem(ret, "wazuh_db");
    assert_true(cJSON_IsObject(root));

    cJSON *c1 = cJSON_GetObjectItem(root, "commit_time_max");
    assert_true(cJSON_IsNumber(c1));
    cJSON *c2 = cJSON_GetObjectItem(root, "commit_time_min");
    assert_true(cJSON_IsNumber(c2));
    cJSON *c3 = cJSON_GetObjectItem(root, "open_db_limit");
    assert_true(cJSON_IsNumber(c3));
    cJSON *c4 = cJSON_GetObjectItem(root, "worker_pool_size");
    assert_true(cJSON_IsNumber(c4));

    cJSON_Delete(ret);
}

/* Tests wdb_get_config */

void test_wdb_get_config(){
    cJSON *ret = wdb_get_config();

    cJSON *root = cJSON_GetObjectItem(ret, "wdb");
    assert_true(cJSON_IsObject(root));

    cJSON *cfg_array = cJSON_GetObjectItem(root, "backup");
    assert_true(cJSON_IsArray(cfg_array));

    cJSON *cfg = 0;
    cJSON_ArrayForEach(cfg, cfg_array){
        assert_true(cJSON_IsObject(cfg));

        cJSON *c0 = cJSON_GetObjectItem(cfg, "database");
        assert_true(cJSON_IsString(c0));
        cJSON *c1 = cJSON_GetObjectItem(cfg, "enabled");
        assert_true(cJSON_IsBool(c1));
        cJSON *c2 = cJSON_GetObjectItem(cfg, "interval");
        assert_true(cJSON_IsNumber(c2));
        cJSON *c3 = cJSON_GetObjectItem(cfg, "max_files");
        assert_true(cJSON_IsNumber(c3));
    }

    cJSON_Delete(ret);
}

/* Tests wdb_check_backup_enabled */

void test_wdb_check_backup_enabled_enabled(void **state)
{
    bool ret = false;
    wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled = true;

    ret = wdb_check_backup_enabled();
    assert_true(ret);
}

void test_wdb_check_backup_enabled_disabled(void **state)
{
    bool ret = false;
    wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled = false;

    ret = wdb_check_backup_enabled();
    assert_false(ret);
}

/* Tests wdb_exec_row_stmt_single_column */

void test_wdb_exec_row_stmt_single_column_success_string(){
    int status = SQLITE_ERROR;

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "COL_TEXT_0");

    sqlite3_stmt *stmt = (sqlite3_stmt *)1;
    cJSON *ret = wdb_exec_row_stmt_single_column(stmt, &status);

    char *ret_str = cJSON_PrintUnformatted(ret);
    assert_string_equal("\"COL_TEXT_0\"", ret_str);
    assert_int_equal(status, SQLITE_ROW);
    cJSON_Delete(ret);
    free(ret_str);
}

void test_wdb_exec_row_stmt_single_column_success_number(){
    int status = SQLITE_ERROR;

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 100);

    sqlite3_stmt *stmt = (sqlite3_stmt *)1;
    cJSON *ret = wdb_exec_row_stmt_single_column(stmt, &status);

    char *ret_str = cJSON_PrintUnformatted(ret);
    assert_string_equal("100", ret_str);
    assert_int_equal(status, SQLITE_ROW);
    cJSON_Delete(ret);
    free(ret_str);
}

void test_wdb_exec_row_stmt_single_column_invalid_stmt(){
    int *status = NULL;
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid SQL statement.");

    cJSON *ret = wdb_exec_row_stmt_single_column(NULL, status);

    assert_ptr_equal(status, NULL);
    assert_null(ret);
}

void test_wdb_exec_row_stmt_single_column_sql_error(void **state){
    int status = SQLITE_ERROR;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    cJSON *ret = wdb_exec_row_stmt_single_column(*data->wdb->stmt, &status);

    assert_int_equal(status, SQLITE_ERROR);
    assert_null(ret);
}

void test_wdb_finalize_all_statements(){
    const int kMaxStmt = 10;
    wdb_t wdb = {0};

    for (int i = 0; i < kMaxStmt; ++i) { wdb.stmt[i] = (sqlite3_stmt *)0xDEADBEEF; }

    struct stmt_cache_list** c = &(wdb.cache_list);
    for(int i = 0; i < kMaxStmt; ++i){
        *c = calloc(1, sizeof(struct stmt_cache_list));
        (*c)->value.stmt = (sqlite3_stmt*) 0xDEADBEEF;
        c = &((*c)->next);
    }

    *c = 0;

    // free the prepared statements
    will_return_count(__wrap_sqlite3_finalize, 1, kMaxStmt);
    // free the statement cache
    will_return_count(__wrap_sqlite3_finalize, 1, kMaxStmt);

    wdb_finalize_all_statements(&wdb);

    for (int i = 0; i < kMaxStmt; ++i) { assert_null(wdb.stmt[i]); }
    assert_null(wdb.cache_list);
}

/* Tests wdb_close*/

void test_wdb_close_no_commit_sqlerror(){
    wdb_t wdb = {0};
    wdb.id = "agent";

    will_return(__wrap_sqlite3_close_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "mock_error");

    expect_string(__wrap__merror, formatted_msg, "DB(agent) wdb_close(): mock_error");

    assert_int_equal(-1, wdb_close(&wdb, 0));
}

void test_wdb_close_success(){
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->id = strdup("agent");

    test_mode = 1;

    will_return(__wrap_sqlite3_close_v2, SQLITE_OK);

    assert_int_equal(0, wdb_close(wdb, 0));
    wdb_destroy(wdb);
}

void test_wdb_get_db_free_pages_percentage_page_count_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    os_strdup("000",wdb->id);

    // wdb_execute_single_int_select_query -> page_count
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");

    expect_string(__wrap__mdebug1, formatted_msg, "Error getting total_pages for '000' database.");

    assert_int_equal(OS_INVALID, wdb_get_db_free_pages_percentage(wdb));

    os_free(wdb->db);
    os_free(wdb->id);
    os_free(wdb);
}

void test_wdb_get_db_free_pages_percentage_page_free_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    os_strdup("000",wdb->id);

    // wdb_execute_single_int_select_query -> page_count
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_execute_single_int_select_query -> page_free
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");

    expect_string(__wrap__mdebug1, formatted_msg, "Error getting free_pages for '000' database.");

    assert_int_equal(OS_INVALID, wdb_get_db_free_pages_percentage(wdb));

    os_free(wdb->db);
    os_free(wdb->id);
    os_free(wdb);
}

void test_wdb_get_db_free_pages_percentage_success_10(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    os_strdup("000",wdb->id);

    // wdb_execute_single_int_select_query -> page_count
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_execute_single_int_select_query -> page_free
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(10, wdb_get_db_free_pages_percentage(wdb));

    os_free(wdb->db);
    os_free(wdb->id);
    os_free(wdb);
}

void test_wdb_execute_single_int_select_query_query_null(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    int value;
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_execute_single_int_select_query(): null query.");

    assert_int_equal(OS_INVALID, wdb_execute_single_int_select_query(wdb, NULL, &value));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_execute_single_int_select_query_prepare_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    int value;

    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");

    assert_int_equal(OS_INVALID, wdb_execute_single_int_select_query(wdb, "query", &value));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_execute_single_int_select_query_step_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    int value;

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(OS_INVALID, wdb_execute_single_int_select_query(wdb, "query", &value));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_execute_single_int_select_query_success_1(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    int value;

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(0, wdb_execute_single_int_select_query(wdb, "query", &value));
    assert_int_equal(1, value);

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_execute_non_select_query_query_null(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_execute_non_select_query(): null query.");

    assert_int_equal(OS_INVALID, wdb_execute_non_select_query(wdb, 0));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_execute_non_select_query_prepare_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");

    assert_int_equal(OS_INVALID, wdb_execute_non_select_query(wdb, "query"));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_execute_non_select_query_step_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_sqlite3_step_call(SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(OS_INVALID, wdb_execute_non_select_query(wdb, "query"));

    os_free(wdb);
}

void test_wdb_execute_non_select_query_success(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(OS_SUCCESS, wdb_execute_non_select_query(wdb, "query"));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_select_from_temp_table_prepare_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");

    assert_int_equal(OS_INVALID, wdb_select_from_temp_table(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_select_from_temp_table_step_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(OS_INVALID, wdb_select_from_temp_table(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_select_from_temp_table_success_0(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 1);

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(0, wdb_select_from_temp_table(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_select_from_temp_table_success_100(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(100, wdb_select_from_temp_table(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_get_db_state_create_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    // create temp table fail
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating temporary table.");

    assert_int_equal(OS_INVALID, wdb_get_db_state(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_get_db_state_truncate_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    // create temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // truncate table fail
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap__mdebug1, formatted_msg, "Error truncate temporary table.");

    assert_int_equal(OS_INVALID, wdb_get_db_state(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_get_db_state_insert_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    // create table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // truncate temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // insert temp table fail
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap__mdebug1, formatted_msg, "Error inserting into temporary table.");

    assert_int_equal(OS_INVALID, wdb_get_db_state(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_get_db_state_select_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    // create table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // truncate temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // insert temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // select from temp table fail
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap__mdebug1, formatted_msg, "Error in select from temporary table.");

    assert_int_equal(OS_INVALID, wdb_get_db_state(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_get_db_state_success_0(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    // create table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // truncate temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // insert temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // select from temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(0, wdb_get_db_state(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_get_db_state_success_100(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));

    // create table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // truncate temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // insert temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // select from temp table success
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(100, wdb_get_db_state(wdb));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_get_last_vacuum_data_exec_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    int last_vacuum_time;
    int last_vacuum_value;

    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");
    expect_string(__wrap__mdebug2, formatted_msg, "SQL: SELECT key, value FROM metadata WHERE key in ('last_vacuum_time', 'last_vacuum_value');");

    assert_int_equal(-1, wdb_get_last_vacuum_data(wdb, &last_vacuum_time, &last_vacuum_value));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_get_last_vacuum_data_ok(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    int last_vacuum_time;
    int last_vacuum_value;

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_time");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "1655555");
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_value");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "85");
    expect_sqlite3_step_call(SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(0, wdb_get_last_vacuum_data(wdb, &last_vacuum_time, &last_vacuum_value));
    assert_int_equal(last_vacuum_time, 1655555);
    assert_int_equal(last_vacuum_value, 85);

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_update_last_vacuum_data_prepare_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    const char *last_vacuum_time = "1655555";
    const char *last_vacuum_value = "85";

    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");

    assert_int_equal(-1, wdb_update_last_vacuum_data(wdb, last_vacuum_time, last_vacuum_value));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_update_last_vacuum_data_step_error(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    const char *last_vacuum_time = "1655555";
    const char *last_vacuum_value = "85";

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, last_vacuum_time);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, last_vacuum_value);
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(-1, wdb_update_last_vacuum_data(wdb, last_vacuum_time, last_vacuum_value));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_update_last_vacuum_data_ok_done(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    const char *last_vacuum_time = "1655555";
    const char *last_vacuum_value = "85";

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, last_vacuum_time);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, last_vacuum_value);
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(0, wdb_update_last_vacuum_data(wdb, last_vacuum_time, last_vacuum_value));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_update_last_vacuum_data_ok_constraint(void **state) {
    wdb_t *wdb = calloc(1, sizeof(wdb_t));
    wdb->db = calloc(1, sizeof(sqlite3 *));
    const char *last_vacuum_time = "1655555";
    const char *last_vacuum_value = "85";

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, last_vacuum_time);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, last_vacuum_value);
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(0, wdb_update_last_vacuum_data(wdb, last_vacuum_time, last_vacuum_value));

    os_free(wdb->db);
    os_free(wdb);
}

void test_wdb_check_fragmentation_node_null(void **state)
{

    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, NULL);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
}

void test_wdb_check_fragmentation_get_state_error(void **state)
{
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    expect_string(__wrap__mdebug1, formatted_msg, "Error creating temporary table.");

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting total_pages for '000' database.");

    expect_string(__wrap__merror, formatted_msg, "Couldn't get current state for the database '000'");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_get_last_vacuum_data_error(void **state)
{
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");
    expect_string(__wrap__mdebug2, formatted_msg, "SQL: SELECT key, value FROM metadata WHERE key in ('last_vacuum_time', 'last_vacuum_value');");

    expect_string(__wrap__merror, formatted_msg, "Couldn't get last vacuum info for the database '000'");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_commit_error(void **state)
{
    wconfig.max_fragmentation = 80;
    wconfig.free_pages_percentage = 5;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 1;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_time");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "1655555");
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_value");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "85");
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_commit2
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "Couldn't execute commit statement, before vacuum, for the database '000'");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_vacuum_error(void **state)
{
    wconfig.max_fragmentation = 80;
    wconfig.free_pages_percentage = 5;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_time");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "1655555");
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_value");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "85");
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_vacuum
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "Couldn't execute vacuum for the database '000'");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_get_fragmentation_after_vacuum_error(void **state)
{
    wconfig.max_fragmentation = 80;
    wconfig.free_pages_percentage = 5;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_time");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "1655555");
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_value");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "85");
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_vacuum
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time_diff, 2);

    expect_string(__wrap__mdebug1, formatted_msg, "Vacuum executed on the '000' database. Time: 2000.000 ms.");

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    expect_string(__wrap__mdebug1, formatted_msg, "Error creating temporary table.");

    expect_string(__wrap__merror, formatted_msg, "Couldn't get fragmentation after vacuum for the database '000'");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_update_last_vacuum_data_error(void **state)
{
    wconfig.max_fragmentation = 80;
    wconfig.free_pages_percentage = 5;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_time");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "1655555");
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_value");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "85");
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_vacuum
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time_diff, 2);

    expect_string(__wrap__mdebug1, formatted_msg, "Vacuum executed on the '000' database. Time: 2000.000 ms.");

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time, 0);

    // wdb_update_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "Couldn't update last vacuum info for the database '000'");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_success_with_warning(void **state)
{
    wconfig.max_fragmentation = 80;
    wconfig.free_pages_percentage = 5;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    expect_string(__wrap__mdebug2, formatted_msg, "No vacuum data in metadata table.");

    // wdb_vacuum
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time_diff, 2);

    expect_string(__wrap__mdebug1, formatted_msg, "Vacuum executed on the '000' database. Time: 2000.000 ms.");

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time, 12);

    // wdb_update_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "12");
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "100");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap__mwarn, formatted_msg, "After vacuum, the database '000' has become just as fragmented or worse");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_success(void **state)
{
    wconfig.max_fragmentation = 80;
    wconfig.free_pages_percentage = 5;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    expect_string(__wrap__mdebug2, formatted_msg, "No vacuum data in metadata table.");

    // wdb_vacuum
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time_diff, 2);

    expect_string(__wrap__mdebug1, formatted_msg, "Vacuum executed on the '000' database. Time: 2000.000 ms.");

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time, 12);

    // wdb_update_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "12");
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_no_vacuum_free_pages(void **state)
{
    wconfig.max_fragmentation = 80;
    wconfig.free_pages_percentage = 5;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 4);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    expect_string(__wrap__mdebug2, formatted_msg, "No vacuum data in metadata table.");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_no_vacuum_current_fragmentation(void **state)
{
    wconfig.max_fragmentation = 80;
    wconfig.free_pages_percentage = 5;
    wconfig.fragmentation_threshold = 75;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 15);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    expect_string(__wrap__mdebug2, formatted_msg, "No vacuum data in metadata table.");

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_no_vacuum_current_fragmentation_delta(void **state)
{
    wconfig.max_fragmentation = 100;
    wconfig.free_pages_percentage = 5;
    wconfig.fragmentation_threshold = 60;
    wconfig.fragmentation_delta = 40;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 15);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_time");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "1655555");
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_value");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "85");
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_vacuum_first(void **state)
{
    wconfig.max_fragmentation = 100;
    wconfig.free_pages_percentage = 5;
    wconfig.fragmentation_threshold = 60;
    wconfig.fragmentation_delta = 50;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 10);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    expect_string(__wrap__mdebug2, formatted_msg, "No vacuum data in metadata table.");

    // wdb_vacuum
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time_diff, 2);

    expect_string(__wrap__mdebug1, formatted_msg, "Vacuum executed on the '000' database. Time: 2000.000 ms.");

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time, 12);

    // wdb_update_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "12");
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_check_fragmentation_vacuum_current_fragmentation_delta(void **state)
{
    wconfig.max_fragmentation = 100;
    wconfig.free_pages_percentage = 5;
    wconfig.fragmentation_threshold = 90;
    wconfig.fragmentation_delta = 20;
    // wdb_pool_keys
    rb_tree * tree = rbtree_init();
    char *value = strdup("testing");
    rbtree_insert(tree, "000", value);
    char** keys = rbtree_keys(tree);

    will_return(__wrap_wdb_pool_keys, keys);

    wdb_t *node = wdb_init("000");
    node->db = (sqlite3 *)1;
    node->transaction = 0;
    expect_string(__wrap_wdb_pool_get, name, "000");
    will_return(__wrap_wdb_pool_get, node);

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 0);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_db_free_pages_percentage
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 100);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 15);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_get_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_time");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "1655555");
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 2);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, "key");
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "last_vacuum_value");
    expect_value(__wrap_sqlite3_column_type, i, 1);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 1);
    will_return(__wrap_sqlite3_column_name, "value");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "70");
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_vacuum
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time_diff, 2);

    expect_string(__wrap__mdebug1, formatted_msg, "Vacuum executed on the '000' database. Time: 2000.000 ms.");

    // wdb_get_db_state
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    will_return(__wrap_time, 12);

    // wdb_update_last_vacuum_data
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "12");
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_function_call(__wrap_wdb_pool_leave);

    wdb_check_fragmentation();

    rbtree_destroy(tree);
    os_free(value);
    wdb_destroy(node);
}

void test_wdb_set_synchronous_normal_null_errmsg(void ** state) {
    wdb_t * wdb = wdb_init("000");
    assert_non_null(wdb);
    wdb->db = (sqlite3 *)1;

    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous=1;");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, 0);

    int retval = wdb_set_synchronous_normal(wdb);

    assert_int_equal(retval, 0);
    wdb_destroy(wdb);
}

void test_wdb_set_synchronous_normal_with_errmsg(void ** state) {
    wdb_t * wdb = wdb_init("000");
    assert_non_null(wdb);
    wdb->db = (sqlite3 *)1;

    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous=1;");
    will_return(__wrap_sqlite3_exec, "synchronous ERROR");
    will_return(__wrap_sqlite3_exec, -1);

    expect_string(__wrap__merror, formatted_msg, "Cannot set synchronous mode: 'synchronous ERROR'");

    int result = wdb_set_synchronous_normal(wdb);

    assert_int_equal(result, -1);
    wdb_destroy(wdb);
}


int main() {
    const struct CMUnitTest tests[] = {
        // wdb_open_tasks
        cmocka_unit_test(test_wdb_open_tasks_pool_success_wdb_in_pool_db_open),
        cmocka_unit_test(test_wdb_open_tasks_pool_success_wdb_in_pool_db_null),
        cmocka_unit_test(test_wdb_open_tasks_create_error),
        cmocka_unit_test(test_wdb_open_tasks_retry_open_error),
        // wdb_open_global
        cmocka_unit_test(test_wdb_open_global_pool_success_wdb_in_pool_db_open),
        cmocka_unit_test(test_wdb_open_global_create_error),
        // wdb_exec_row_stm
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_multi_column_one_int, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_multi_column_multiple_int, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_multi_column_one_text, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_multi_column_done, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_multi_column_error, setup_wdb, teardown_wdb),
        // wdb_exec_stmt
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_invalid_statement, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_error, setup_wdb, teardown_wdb),
        // wdb_exec_stmt_sized
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_success_single_column_string, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_success_single_column_value, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_success_multi_column, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_success_limited, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_invalid_statement, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_error, setup_wdb, teardown_wdb),
        // wdb_exec_stmt_silent
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_silent_success_sqlite_done, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_silent_success_sqlite_row, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_silent_invalid, setup_wdb, teardown_wdb),
        // wdb_exec_stmt_send
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_single_row_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_multiple_rows_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_no_rows_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_row_size_limit_err, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_socket_err, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_timeout_set_err, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_statement_invalid, setup_wdb, teardown_wdb),
        // wdb_init_stmt_in_cache
        cmocka_unit_test_setup_teardown(test_wdb_init_stmt_in_cache_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_init_stmt_in_cache_invalid_transaction, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_init_stmt_in_cache_invalid_statement, setup_wdb, teardown_wdb),
        // wdb_get_config
        cmocka_unit_test_setup_teardown(test_wdb_get_config, wazuh_db_config_setup, wazuh_db_config_teardown),
        // wdb_check_backup_enabled
        cmocka_unit_test_setup_teardown(test_wdb_check_backup_enabled_enabled, wazuh_db_config_setup, wazuh_db_config_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_check_backup_enabled_disabled, wazuh_db_config_setup, wazuh_db_config_teardown),
        // wdb_get_internal_config
        cmocka_unit_test(test_wdb_get_internal_config),
        // wdb_exec_row_stmt_single_column
        cmocka_unit_test(test_wdb_exec_row_stmt_single_column_success_string),
        cmocka_unit_test(test_wdb_exec_row_stmt_single_column_success_number),
        cmocka_unit_test(test_wdb_exec_row_stmt_single_column_invalid_stmt),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_single_column_sql_error, setup_wdb, teardown_wdb),
        // wdb_finalize_all_statements
        cmocka_unit_test(test_wdb_finalize_all_statements),
        // wdb_close
        cmocka_unit_test(test_wdb_close_no_commit_sqlerror),
        cmocka_unit_test(test_wdb_close_success),
        // wdb_get_db_free_pages_percentage
        cmocka_unit_test(test_wdb_get_db_free_pages_percentage_page_count_error),
        cmocka_unit_test(test_wdb_get_db_free_pages_percentage_page_free_error),
        cmocka_unit_test(test_wdb_get_db_free_pages_percentage_success_10),
        // wdb_execute_single_int_select_query
        cmocka_unit_test(test_wdb_execute_single_int_select_query_query_null),
        cmocka_unit_test(test_wdb_execute_single_int_select_query_prepare_error),
        cmocka_unit_test(test_wdb_execute_single_int_select_query_step_error),
        cmocka_unit_test(test_wdb_execute_single_int_select_query_success_1),
        // wdb_execute_non_select_query
        cmocka_unit_test(test_wdb_execute_non_select_query_query_null),
        cmocka_unit_test(test_wdb_execute_non_select_query_prepare_error),
        cmocka_unit_test(test_wdb_execute_non_select_query_step_error),
        cmocka_unit_test(test_wdb_execute_non_select_query_success),
        // wdb_select_from_temp_table
        cmocka_unit_test(test_wdb_select_from_temp_table_prepare_error),
        cmocka_unit_test(test_wdb_select_from_temp_table_step_error),
        cmocka_unit_test(test_wdb_select_from_temp_table_success_0),
        cmocka_unit_test(test_wdb_select_from_temp_table_success_100),
        // wdb_get_db_state
        cmocka_unit_test(test_wdb_get_db_state_create_error),
        cmocka_unit_test(test_wdb_get_db_state_truncate_error),
        cmocka_unit_test(test_wdb_get_db_state_insert_error),
        cmocka_unit_test(test_wdb_get_db_state_select_error),
        cmocka_unit_test(test_wdb_get_db_state_success_0),
        cmocka_unit_test(test_wdb_get_db_state_success_100),
        // wdb_get_last_vacuum_data
        cmocka_unit_test(test_wdb_get_last_vacuum_data_exec_error),
        cmocka_unit_test(test_wdb_get_last_vacuum_data_ok),
        // wdb_update_last_vacuum_data
        cmocka_unit_test(test_wdb_update_last_vacuum_data_prepare_error),
        cmocka_unit_test(test_wdb_update_last_vacuum_data_step_error),
        cmocka_unit_test(test_wdb_update_last_vacuum_data_ok_done),
        cmocka_unit_test(test_wdb_update_last_vacuum_data_ok_constraint),
        // wdb_check_fragmentation
        cmocka_unit_test(test_wdb_check_fragmentation_node_null),
        cmocka_unit_test(test_wdb_check_fragmentation_get_state_error),
        cmocka_unit_test(test_wdb_check_fragmentation_get_last_vacuum_data_error),
        cmocka_unit_test(test_wdb_check_fragmentation_commit_error),
        cmocka_unit_test(test_wdb_check_fragmentation_vacuum_error),
        cmocka_unit_test(test_wdb_check_fragmentation_get_fragmentation_after_vacuum_error),
        cmocka_unit_test(test_wdb_check_fragmentation_update_last_vacuum_data_error),
        cmocka_unit_test(test_wdb_check_fragmentation_success_with_warning),
        cmocka_unit_test(test_wdb_check_fragmentation_success),
        cmocka_unit_test(test_wdb_check_fragmentation_no_vacuum_free_pages),
        cmocka_unit_test(test_wdb_check_fragmentation_no_vacuum_current_fragmentation),
        cmocka_unit_test(test_wdb_check_fragmentation_no_vacuum_current_fragmentation_delta),
        cmocka_unit_test(test_wdb_check_fragmentation_vacuum_first),
        cmocka_unit_test(test_wdb_check_fragmentation_vacuum_current_fragmentation_delta),
        // wdb_set_synchronous_normal
        cmocka_unit_test(test_wdb_set_synchronous_normal_null_errmsg),
        cmocka_unit_test(test_wdb_set_synchronous_normal_with_errmsg),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
