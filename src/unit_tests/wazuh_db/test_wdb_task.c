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

#include "wdb.h"

// External function declarations
extern int wdb_task_create(wdb_t* wdb, const char *task_id, const char *agent_id, const char *task_type, const char *payload);
extern int wdb_task_get_pending(wdb_t* wdb, const char *agent_id, int max_tasks, cJSON **tasks_json);
extern int wdb_task_mark_delivered(wdb_t* wdb, const char *task_id, time_t delivery_time);
extern int wdb_task_cleanup_expired(wdb_t* wdb, int ttl);
extern int wdb_task_delete_old(wdb_t* wdb, time_t timestamp);

// Setup/teardown

static int test_setup(void **state) {
    wdb_t *wdb = NULL;
    os_calloc(1, sizeof(wdb_t), wdb);
    os_calloc(1, sizeof(sqlite3 *), wdb->db);
    *state = wdb;
    return 0;
}

static int test_teardown(void **state) {
    wdb_t *wdb = *state;
    os_free(wdb->db);
    os_free(wdb);
    return 0;
}

/* Tests for wdb_task_create */

void test_wdb_task_create_success(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_time, 1234567890);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "task-123");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "001");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "upgrade");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "{\"version\":\"4.5.0\"}");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 1234567890);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "pending");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int result = wdb_task_create(wdb, "task-123", "001", "upgrade", "{\"version\":\"4.5.0\"}");

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_task_create_transaction_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_time, 1234567890);
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_TRANSACTION_ERROR);

    int result = wdb_task_create(wdb, "task-123", "001", "upgrade", "{\"version\":\"4.5.0\"}");

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_create_cache_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_time, 1234567890);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_CACHE_ERROR);

    int result = wdb_task_create(wdb, "task-123", "001", "upgrade", "{\"version\":\"4.5.0\"}");

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_create_step_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_time, 1234567890);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "task-123");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "001");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "upgrade");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "{\"version\":\"4.5.0\"}");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 1234567890);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "pending");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "SQL error");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'SQL error'");

    int result = wdb_task_create(wdb, "task-123", "001", "upgrade", "{\"version\":\"4.5.0\"}");

    assert_int_equal(result, OS_INVALID);
}

/* Tests for wdb_task_get_pending */

void test_wdb_task_get_pending_success(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;
    cJSON *tasks_json = NULL;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "001");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 10);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // First row
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "task-123");
    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "upgrade");
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "{\"version\":\"4.5.0\"}");
    expect_value(__wrap_sqlite3_column_int, iCol, 4);
    will_return(__wrap_sqlite3_column_int, 1234567890);

    // No more rows
    will_return(__wrap_wdb_step, SQLITE_DONE);

    int result = wdb_task_get_pending(wdb, "001", 10, &tasks_json);

    assert_int_equal(result, OS_SUCCESS);
    assert_non_null(tasks_json);
    assert_int_equal(cJSON_GetArraySize(tasks_json), 1);

    cJSON_Delete(tasks_json);
}

void test_wdb_task_get_pending_transaction_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;
    cJSON *tasks_json = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_TRANSACTION_ERROR);

    int result = wdb_task_get_pending(wdb, "001", 10, &tasks_json);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_get_pending_cache_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;
    cJSON *tasks_json = NULL;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_CACHE_ERROR);

    int result = wdb_task_get_pending(wdb, "001", 10, &tasks_json);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_get_pending_step_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;
    cJSON *tasks_json = NULL;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "001");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 10);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // First row
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "task-123");
    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "upgrade");
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "{\"version\":\"4.5.0\"}");
    expect_value(__wrap_sqlite3_column_int, iCol, 4);
    will_return(__wrap_sqlite3_column_int, 1234567890);

    // Error on second iteration
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "SQL error");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'SQL error'");

    int result = wdb_task_get_pending(wdb, "001", 10, &tasks_json);

    assert_int_equal(result, OS_INVALID);
    assert_null(tasks_json);
}

/* Tests for wdb_task_mark_delivered */

void test_wdb_task_mark_delivered_success(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1234567890);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "task-123");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int result = wdb_task_mark_delivered(wdb, "task-123", 1234567890);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_task_mark_delivered_transaction_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_TRANSACTION_ERROR);

    int result = wdb_task_mark_delivered(wdb, "task-123", 1234567890);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_mark_delivered_cache_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_CACHE_ERROR);

    int result = wdb_task_mark_delivered(wdb, "task-123", 1234567890);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_mark_delivered_step_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1234567890);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "task-123");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "SQL error");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'SQL error'");

    int result = wdb_task_mark_delivered(wdb, "task-123", 1234567890);

    assert_int_equal(result, OS_INVALID);
}

/* Tests for wdb_task_cleanup_expired */

void test_wdb_task_cleanup_expired_success(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_time, 2000000000);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 2000000000 - 3600);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int result = wdb_task_cleanup_expired(wdb, 3600);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_task_cleanup_expired_transaction_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_time, 2000000000);
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_TRANSACTION_ERROR);

    int result = wdb_task_cleanup_expired(wdb, 3600);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_cleanup_expired_cache_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_time, 2000000000);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_CACHE_ERROR);

    int result = wdb_task_cleanup_expired(wdb, 3600);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_cleanup_expired_step_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_time, 2000000000);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 2000000000 - 3600);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "SQL error");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'SQL error'");

    int result = wdb_task_cleanup_expired(wdb, 3600);

    assert_int_equal(result, OS_INVALID);
}

/* Tests for wdb_task_delete_old */

void test_wdb_task_delete_old_success(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 1234567890);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int64, index, 2);
    expect_value(__wrap_sqlite3_bind_int64, value, 1234567890);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int result = wdb_task_delete_old(wdb, 1234567890);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_task_delete_old_transaction_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_TRANSACTION_ERROR);

    int result = wdb_task_delete_old(wdb, 1234567890);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_delete_old_cache_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, DB_CACHE_ERROR);

    int result = wdb_task_delete_old(wdb, 1234567890);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_task_delete_old_step_fail(void **state) {
    wdb_t *wdb = *state;
    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 1234567890);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int64, index, 2);
    expect_value(__wrap_sqlite3_bind_int64, value, 1234567890);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "SQL error");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'SQL error'");

    int result = wdb_task_delete_old(wdb, 1234567890);

    assert_int_equal(result, OS_INVALID);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wdb_task_create tests
        cmocka_unit_test_setup_teardown(test_wdb_task_create_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_create_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_create_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_create_step_fail, test_setup, test_teardown),
        // wdb_task_get_pending tests
        cmocka_unit_test_setup_teardown(test_wdb_task_get_pending_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_pending_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_pending_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_pending_step_fail, test_setup, test_teardown),
        // wdb_task_mark_delivered tests
        cmocka_unit_test_setup_teardown(test_wdb_task_mark_delivered_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_mark_delivered_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_mark_delivered_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_mark_delivered_step_fail, test_setup, test_teardown),
        // wdb_task_cleanup_expired tests
        cmocka_unit_test_setup_teardown(test_wdb_task_cleanup_expired_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_cleanup_expired_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_cleanup_expired_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_cleanup_expired_step_fail, test_setup, test_teardown),
        // wdb_task_delete_old tests
        cmocka_unit_test_setup_teardown(test_wdb_task_delete_old_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_delete_old_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_delete_old_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_delete_old_step_fail, test_setup, test_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
