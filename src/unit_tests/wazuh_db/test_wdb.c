/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * September, 2020.
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

#include "wazuh_db/wdb.h"
#include "wazuhdb_op.h"
#include "hash_op.h"

#include "../wrappers/common.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

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

/* Tests wdb_open_global */

void test_wdb_open_global_pool_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_OSHash_Get, self, (OSHash*) 0);
    expect_string(__wrap_OSHash_Get, key, WDB_GLOB_NAME);
    will_return(__wrap_OSHash_Get, data->wdb);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_open_global();

    assert_int_equal(ret, data->wdb);
}

void test_wdb_open_global_create_fail(void **state)
{
    wdb_t *ret = NULL;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_OSHash_Get, self, (OSHash*) 0);
    expect_string(__wrap_OSHash_Get, key, WDB_GLOB_NAME);
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Global database not found, creating.");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    // wdb_create_global
    //// wdb_create_file
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db': out of memory");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db'");
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_open_global();

    assert_null(ret);
}

/* Tests db_exec_row_stmt */

void test_wdb_exec_row_stmt_one_int(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;

    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, json_value);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);

    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_string_equal(result->child->string, json_str);
    assert_int_equal(result->child->valuedouble, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_row_stmt_multiple_int(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int columns = 10;
    char json_strs[columns][OS_SIZE_256];
    for (int column=0; column < columns; column++){
        snprintf(json_strs[column], OS_SIZE_256, "COLUMN%d",column);
    }

    will_return(__wrap_sqlite3_step, SQLITE_ROW);
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
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);

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

void test_wdb_exec_row_stmt_one_text(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    const char*  json_value = "VALUE";

    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, json_value);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);
    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_string_equal(result->child->string, json_str);
    assert_string_equal(result->child->valuestring, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_row_stmt_done(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);assert_null(result);
    assert_int_equal(status, SQLITE_DONE);
    assert_null(result);
}

void test_wdb_exec_row_stmt_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);
    assert_int_equal(status, SQLITE_ERROR);
    assert_null(result);
}

/* Tests wdb_exec_stmt_sized */

void test_wdb_exec_stmt_sized_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;

    //Calling wdb_exec_row_stmt
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return_count(__wrap_sqlite3_column_count, 1, -1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER,-1);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return_count(__wrap_sqlite3_column_name, json_str, -1);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return_count(__wrap_sqlite3_column_double, json_value, -1);

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, WDB_MAX_RESPONSE_SIZE, &status);

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
    will_return_count(__wrap_sqlite3_step, SQLITE_ROW, rows);
    will_return_count(__wrap_sqlite3_column_count, 1, -1);
    expect_any_count(__wrap_sqlite3_column_type, i, -1);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER, -1);
    expect_any_count(__wrap_sqlite3_column_name, N, -1);
    will_return_count(__wrap_sqlite3_column_name, json_str, -1);
    expect_any_count(__wrap_sqlite3_column_double, iCol, -1);
    will_return_count(__wrap_sqlite3_column_double, json_value, -1);

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, max_size, &status);

    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_int_equal(cJSON_GetArraySize(result), rows-1);

    cJSON_Delete(result);
}

void test_wdb_exec_stmt_sized_invalid_statement(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid SQL statement.");

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(NULL, WDB_MAX_RESPONSE_SIZE, &status);

    assert_int_equal(status, SQLITE_ERROR);
    assert_null(result);
}

void test_wdb_exec_stmt_sized_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    //Calling wdb_exec_row_stmt
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, WDB_MAX_RESPONSE_SIZE, &status);

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
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
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
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    cJSON* result = wdb_exec_stmt(*data->wdb->stmt);
    assert_null(result);

    cJSON_Delete(result);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        //wdb_open_global
        cmocka_unit_test_setup_teardown(test_wdb_open_global_pool_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_open_global_create_fail, setup_wdb, teardown_wdb),
        //wdb_exec_row_stm
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_one_int, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_multiple_int, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_one_text, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_done, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_error, setup_wdb, teardown_wdb),
        //wdb_exec_stmt
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_invalid_statement, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_error, setup_wdb, teardown_wdb),
        //wdb_exec_stmt_sized
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_success_limited, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_invalid_statement, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_error, setup_wdb, teardown_wdb),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
