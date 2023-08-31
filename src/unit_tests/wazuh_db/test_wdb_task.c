/*
 * Copyright (C) 2015, Wazuh Inc.
 * November, 2020.
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

#include "../wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "wazuhdb_op.h"

extern void __real_cJSON_Delete(cJSON *item);

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("tasks",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
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


void test_wdb_task_delete_old_entries_ok(void **state)
{
    int timestamp = 12345;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, timestamp);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int ret = wdb_task_delete_old_entries(data->wdb, timestamp);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_task_delete_old_entries_step_err(void **state)
{
    int timestamp = 12345;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, timestamp);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, -1);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");

    int ret = wdb_task_delete_old_entries(data->wdb, timestamp);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_delete_old_entries_cache_err(void **state)
{
    int timestamp = 12345;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_delete_old_entries(data->wdb, timestamp);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_delete_old_entries_begin2_err(void **state)
{
    int timestamp = 12345;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_delete_old_entries(data->wdb, timestamp);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_set_timeout_status_timeout_ok(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;
    int update_time = now - timeout;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Timeout");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int ret = wdb_task_set_timeout_status(data->wdb, now, timeout, &next_timeout);

    assert_int_equal(ret, 0);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wdb_task_set_timeout_status_no_timeout_ok(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;
    int update_time = (now - timeout) + 100;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int ret = wdb_task_set_timeout_status(data->wdb, now, timeout, &next_timeout);

    assert_int_equal(ret, 0);
    assert_int_equal(next_timeout, now + 100);
}

void test_wdb_task_set_timeout_status_timeout_step_err(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;
    int update_time = now - timeout;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Timeout");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");

    int ret = wdb_task_set_timeout_status(data->wdb, now, timeout, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wdb_task_set_timeout_status_timeout_cache_err(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;
    int update_time = now - timeout;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_set_timeout_status(data->wdb, now, timeout, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wdb_task_set_timeout_status_cache_err(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_set_timeout_status(data->wdb, now, timeout, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wdb_task_set_timeout_status_begin2_err(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_set_timeout_status(data->wdb, now, timeout, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wdb_task_insert_task(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    char *status = "Pending";
    int task_id = 20;
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    int ret = wdb_task_insert_task(data->wdb, agent_id, node, module, command);

    assert_int_equal(ret, task_id);
}

void test_wdb_task_insert_task_task_id_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    char *status = "Pending";
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, NULL);

    int ret = wdb_task_insert_task(data->wdb, agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_insert_task_begin2_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_insert_task(data->wdb, agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_insert_task_stmt_cache_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_insert_task(data->wdb, agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_insert_task_step1_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    char *status = "Pending";
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, -1);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");

    int ret = wdb_task_insert_task(data->wdb, agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_insert_task_cache2_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    char *status = "Pending";
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_insert_task(data->wdb, agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_insert_task_step2_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    char *status = "Pending";
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");


    int ret = wdb_task_insert_task(data->wdb, agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_get_upgrade_task_status_ok(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "node03");

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "In progress");

    int ret = wdb_task_get_upgrade_task_status(data->wdb, agent_id, node, &status);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(status, "In progress");
    os_free(status);
}

void test_wdb_task_get_upgrade_task_status_delete_old_node_pending(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "node02");

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "Pending");

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int ret = wdb_task_get_upgrade_task_status(data->wdb, agent_id, node, &status);

    assert_int_equal(ret, OS_SUCCESS);
    assert_null(status);
}

void test_wdb_task_get_upgrade_task_status_delete_old_node_pending_step_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "node02");

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "Pending");

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");


    int ret = wdb_task_get_upgrade_task_status(data->wdb, agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wdb_task_get_upgrade_task_status_delete_old_node_pending_cache_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "node02");

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "Pending");

    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_get_upgrade_task_status(data->wdb, agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wdb_task_get_upgrade_task_status_no_task_id(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 0;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);


    int ret = wdb_task_get_upgrade_task_status(data->wdb, agent_id, node, &status);

    assert_int_equal(ret, OS_SUCCESS);
    assert_null(status);
}

void test_wdb_task_get_upgrade_task_status_step_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");


    int ret = wdb_task_get_upgrade_task_status(data->wdb, agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wdb_task_get_upgrade_task_status_cache_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_get_upgrade_task_status(data->wdb, agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wdb_task_get_upgrade_task_status_begin2_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_get_upgrade_task_status(data->wdb, agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wdb_task_update_upgrade_task_status_ok(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    char *node_old = "node03";
    char *status_old = "In progress";
    char *error = "Error message";
    int task_id = 36;
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, error);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);


    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, error);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_task_update_upgrade_task_status_old_status_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    char *node_old = "node03";
    char *status_old = "Done";
    int task_id = 36;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, NULL);

    assert_int_equal(ret, OS_NOTFOUND);
}

void test_wdb_task_update_upgrade_task_status_old_status2_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Failed";
    char *node_old = "node03";
    char *status_old = "Done";
    int task_id = 36;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, NULL);

    assert_int_equal(ret, OS_NOTFOUND);
}

void test_wdb_task_update_upgrade_task_status_task_id_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    int task_id = 0;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, NULL);

    assert_int_equal(ret, OS_NOTFOUND);
}

void test_wdb_task_update_upgrade_task_status_status_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Timeout";

    test_struct_t *data  = (test_struct_t *)*state;

    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_update_upgrade_task_status_begin2_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_update_upgrade_task_status_cache_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_update_upgrade_task_status_step_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");

    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_update_upgrade_task_status_cache2_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    char *node_old = "node03";
    char *status_old = "In progress";
    int task_id = 36;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_update_upgrade_task_status_step2_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    char *node_old = "node03";
    char *status_old = "In progress";
    char *error = "Error message";
    int task_id = 36;
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, error);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");


    int ret = wdb_task_update_upgrade_task_status(data->wdb, agent_id, node, status, error);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_get_upgrade_task_by_agent_id_begin2_err(void **state)
{
    int agent_id = 88;
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_get_upgrade_task_by_agent_id(data->wdb, agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_get_upgrade_task_by_agent_id_cache_err(void **state)
{
    int agent_id = 88;
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_get_upgrade_task_by_agent_id(data->wdb, agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_get_upgrade_task_by_agent_id_step_err(void **state)
{
    int agent_id = 88;
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");

    int ret = wdb_task_get_upgrade_task_by_agent_id(data->wdb, agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_get_upgrade_task_by_agent_id_no_task_id(void **state)
{
    int agent_id = 88;
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;
    int task_id = 0;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    int ret = wdb_task_get_upgrade_task_by_agent_id(data->wdb, agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_NOTFOUND);
}

void test_wdb_task_get_upgrade_task_by_agent_id_ok(void **state)
{
    int agent_id = 88;
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;
    int task_id = 65;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 2, 2);
    will_return_count(__wrap_sqlite3_column_text, "node05", 2);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 3, 2);
    will_return_count(__wrap_sqlite3_column_text, "upgrade_module", 2);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 4, 2);
    will_return_count(__wrap_sqlite3_column_text, "upgrade", 2);

    expect_value(__wrap_sqlite3_column_int, iCol, 5);
    will_return(__wrap_sqlite3_column_int, 12345);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, 67890);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 7, 2);
    will_return_count(__wrap_sqlite3_column_text, "In progress", 2);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 8, 2);
    will_return_count(__wrap_sqlite3_column_text, "Error string", 2);


    int ret = wdb_task_get_upgrade_task_by_agent_id(data->wdb, agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, task_id);
    assert_string_equal(node, "node05");
    assert_string_equal(module, "upgrade_module");
    assert_string_equal(command, "upgrade");
    assert_int_equal(update_time, 12345);
    assert_int_equal(last_update, 67890);
    assert_string_equal(status, "In progress");
    assert_string_equal(error, "Error string");

    os_free(node);
    os_free(module);
    os_free(command);
    os_free(status);
    os_free(error);
}


void test_wdb_task_cancel_upgrade_tasks_ok(void **state)
{
    char *node = "node05";
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);


    int ret = wdb_task_cancel_upgrade_tasks(data->wdb, node);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_task_cancel_upgrade_tasks_step_err(void **state)
{
    char *node = "node05";
    int now = 123456789;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "(5211): SQL error: 'ERROR MESSAGE'");

    int ret = wdb_task_cancel_upgrade_tasks(data->wdb, node);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_cancel_upgrade_tasks_cache_err(void **state)
{
    char *node = "node05";

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_cancel_upgrade_tasks(data->wdb, node);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_task_cancel_upgrade_tasks_begin2_err(void **state)
{
    char *node = "node05";

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    int ret = wdb_task_cancel_upgrade_tasks(data->wdb, node);

    assert_int_equal(ret, OS_INVALID);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wdb_task_delete_old_entries
        cmocka_unit_test_setup_teardown(test_wdb_task_delete_old_entries_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_delete_old_entries_step_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_delete_old_entries_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_delete_old_entries_begin2_err, test_setup, test_teardown),
        // wdb_task_set_timeout_status
        cmocka_unit_test_setup_teardown(test_wdb_task_set_timeout_status_timeout_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_set_timeout_status_no_timeout_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_set_timeout_status_timeout_step_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_set_timeout_status_timeout_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_set_timeout_status_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_set_timeout_status_begin2_err, test_setup, test_teardown),
        // wdb_task_insert_task
        cmocka_unit_test_setup_teardown(test_wdb_task_insert_task, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_insert_task_task_id_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_insert_task_begin2_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_insert_task_stmt_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_insert_task_step1_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_insert_task_cache2_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_insert_task_step2_err, test_setup, test_teardown),
        // wdb_task_get_upgrade_task_status
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_status_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_status_delete_old_node_pending, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_status_delete_old_node_pending_step_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_status_delete_old_node_pending_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_status_no_task_id, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_status_step_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_status_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_status_begin2_err, test_setup, test_teardown),
        // wdb_task_update_upgrade_task_status
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_old_status_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_old_status2_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_task_id_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_status_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_begin2_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_step_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_cache2_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_update_upgrade_task_status_step2_err, test_setup, test_teardown),
        // wdb_task_get_upgrade_task_by_agent_id
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_by_agent_id_begin2_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_by_agent_id_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_by_agent_id_step_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_by_agent_id_no_task_id, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_get_upgrade_task_by_agent_id_ok, test_setup, test_teardown),
        // wdb_task_cancel_upgrade_tasks
        cmocka_unit_test_setup_teardown(test_wdb_task_cancel_upgrade_tasks_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_cancel_upgrade_tasks_step_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_cancel_upgrade_tasks_cache_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_task_cancel_upgrade_tasks_begin2_err, test_setup, test_teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
