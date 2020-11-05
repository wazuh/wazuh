/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../../wrappers/posix/stat_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/privsep_op_wrappers.h"
#include "../../wrappers/wazuh/shared/time_op_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/task_manager/wm_task_manager_db.h"
#include "../../headers/shared.h"

int wm_task_manager_set_timeout_status(time_t now, int timeout, time_t *next_timeout);
int wm_task_manager_delete_old_entries(int timestamp);

// Setup / teardown

static int setup_config(void **state) {
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);
    *state = config;
    return 0;
}

static int teardown_config(void **state) {
    wm_task_manager *config = *state;
    os_free(config);
    return 0;
}

static int teardown_strings(void **state) {
    char *string1 = state[0];
    char *string2 = state[1];
    os_free(string1);
    os_free(string2);
    return 0;
}

// Wrappers

time_t __wrap_time(time_t *__timer) {
    return mock();
}

// Tests

void test_wm_task_manager_check_db_ok(void **state)
{
    int uid = 5;
    int gid = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_string(__wrap_Privsep_GetUser, name, ROOTUSER);
    will_return(__wrap_Privsep_GetUser, uid);

    expect_string(__wrap_Privsep_GetGroup, name, GROUPGLOBAL);
    will_return(__wrap_Privsep_GetGroup, gid);

    expect_string(__wrap_chown, __file, TASKS_DB);
    expect_value(__wrap_chown, __owner, uid);
    expect_value(__wrap_chown, __group, gid);
    will_return(__wrap_chown, 0);

    expect_string(__wrap_chmod, path, TASKS_DB);
    will_return(__wrap_chmod, 0);

    int ret = wm_task_manager_check_db();

    assert_int_equal(ret, 0);
}

void test_wm_task_manager_check_db_chmod_err(void **state)
{
    int uid = 5;
    int gid = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_MISUSE);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_string(__wrap_Privsep_GetUser, name, ROOTUSER);
    will_return(__wrap_Privsep_GetUser, uid);

    expect_string(__wrap_Privsep_GetGroup, name, GROUPGLOBAL);
    will_return(__wrap_Privsep_GetGroup, gid);

    expect_string(__wrap_chown, __file, TASKS_DB);
    expect_value(__wrap_chown, __owner, uid);
    expect_value(__wrap_chown, __group, gid);
    will_return(__wrap_chown, 0);

    expect_string(__wrap_chmod, path, TASKS_DB);
    will_return(__wrap_chmod, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(1127): Could not chmod object 'queue/tasks/tasks.db' due to [(0)-(Success)].");

    int ret = wm_task_manager_check_db();

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_check_db_chown_err(void **state)
{
    int uid = 5;
    int gid = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_string(__wrap_Privsep_GetUser, name, ROOTUSER);
    will_return(__wrap_Privsep_GetUser, uid);

    expect_string(__wrap_Privsep_GetGroup, name, GROUPGLOBAL);
    will_return(__wrap_Privsep_GetGroup, gid);

    expect_string(__wrap_chown, __file, TASKS_DB);
    expect_value(__wrap_chown, __owner, uid);
    expect_value(__wrap_chown, __group, gid);
    will_return(__wrap_chown, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(1135): Could not chown object 'queue/tasks/tasks.db' due to [(0)-(Success)].");

    int ret = wm_task_manager_check_db();

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_check_db_id_err(void **state)
{
    int uid = 5;
    int gid = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_CONSTRAINT);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_string(__wrap_Privsep_GetUser, name, ROOTUSER);
    will_return(__wrap_Privsep_GetUser, OS_INVALID);

    expect_string(__wrap_Privsep_GetGroup, name, GROUPGLOBAL);
    will_return(__wrap_Privsep_GetGroup, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(1203): Invalid user 'root' or group 'ossec' given: Success (0)");

    int ret = wm_task_manager_check_db();

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_check_db_step_err(void **state)
{
    int uid = 5;
    int gid = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_check_db();

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_check_db_prepare_err(void **state)
{
    int uid = 5;
    int gid = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_check_db();

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_check_db_open_err(void **state)
{
    int uid = 5;
    int gid = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8275): DB couldn't be checked or created.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_check_db();

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_delete_old_entries_ok(void **state)
{
    int timestamp = 12345;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8206): Running daily clean DB thread.");

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, timestamp);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_delete_old_entries(timestamp);

    assert_int_equal(ret, 0);
}

void test_wm_task_manager_delete_old_entries_step_err(void **state)
{
    int timestamp = 12345;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8206): Running daily clean DB thread.");

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, timestamp);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_delete_old_entries(timestamp);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_delete_old_entries_prepare_err(void **state)
{
    int timestamp = 12345;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8206): Running daily clean DB thread.");

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_delete_old_entries(timestamp);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_delete_old_entries_open_err(void **state)
{
    int timestamp = 12345;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8206): Running daily clean DB thread.");

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8276): DB couldn't be opened.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_delete_old_entries(timestamp);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_set_timeout_status_timeout_ok(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;
    int update_time = now - timeout;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, timeout, &next_timeout);

    assert_int_equal(ret, 0);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wm_task_manager_set_timeout_status_no_timeout_ok(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;
    int update_time = (now - timeout) + 100;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, timeout, &next_timeout);

    assert_int_equal(ret, 0);
    assert_int_equal(next_timeout, now + 100);
}

void test_wm_task_manager_set_timeout_status_timeout_step_err(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;
    int update_time = now - timeout;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, timeout, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wm_task_manager_set_timeout_status_timeout_prepare_err(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;
    int update_time = now - timeout;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, timeout, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wm_task_manager_set_timeout_status_prepare_err(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, timeout, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wm_task_manager_set_timeout_status_open_err(void **state)
{
    time_t now = 123456789;
    int timeout = 700;
    time_t next_timeout = now + timeout;
    int task_id = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8276): DB couldn't be opened.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, timeout, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, now + timeout);
}

void test_wm_task_manager_clean_db(void **state)
{

    wm_task_manager *config = *state;

    config->cleanup_time = 1000;
    config->task_timeout = 850;

    int now = 123456789;
    int timestamp = now - config->cleanup_time;

    int task_id = 10;
    int update_time = now - config->task_timeout;

    will_return(__wrap_time, now);

    will_return(__wrap_time, now);

    will_return(__wrap_time, now);

    // wm_task_manager_set_timeout_status

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    // wm_task_manager_delete_old_entries

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8206): Running daily clean DB thread.");

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, timestamp);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    wm_task_manager_clean_db(config);

    assert_int_equal(current_time, now + config->task_timeout);
}

void test_wm_task_manager_clean_db_timeout(void **state)
{

    wm_task_manager *config = *state;

    config->cleanup_time = 1000;
    config->task_timeout = 850;

    int now = 123456789;
    int timestamp = now - config->cleanup_time;

    int task_id = 10;
    int update_time = now - config->task_timeout;

    will_return(__wrap_time, now + 100);

    will_return(__wrap_time, now);

    will_return(__wrap_time, now);

    // wm_task_manager_set_timeout_status

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, update_time);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    wm_task_manager_clean_db(config);

    assert_int_equal(current_time, now + 100);
}

void test_wm_task_manager_clean_db_clean(void **state)
{

    wm_task_manager *config = *state;

    config->cleanup_time = 1000;
    config->task_timeout = 850;

    int now = 123456789;
    int timestamp = now - config->cleanup_time;

    int task_id = 10;

    will_return(__wrap_time, now);

    will_return(__wrap_time, now + 200);

    will_return(__wrap_time, now);

    // wm_task_manager_delete_old_entries

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8206): Running daily clean DB thread.");

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, timestamp);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    wm_task_manager_clean_db(config);

    assert_int_equal(current_time, now + 200);
}

void test_wm_task_manager_insert_task_ok(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 20;
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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
    expect_string(__wrap_sqlite3_bind_text, buffer, "Pending");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, node, module, command);

    assert_int_equal(ret, task_id);
}

void test_wm_task_manager_insert_task_task_id_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 0;
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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
    expect_string(__wrap_sqlite3_bind_text, buffer, "Pending");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_step2_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 0;
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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
    expect_string(__wrap_sqlite3_bind_text, buffer, "Pending");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_prepare2_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 0;
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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
    expect_string(__wrap_sqlite3_bind_text, buffer, "Pending");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_step_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 0;
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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
    expect_string(__wrap_sqlite3_bind_text, buffer, "Pending");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_prepare_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 0;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_open_err(void **state)
{
    int agent_id = 55;
    char *node = "node03";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 0;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8276): DB couldn't be opened.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, node, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_get_upgrade_task_status_ok(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "node03");

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "In progress");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_status(agent_id, node, &status);

    *state = status;

    assert_int_equal(ret, WM_TASK_SUCCESS);
    assert_string_equal(status, "In progress");
}

void test_wm_task_manager_get_upgrade_task_status_delete_old_node_pending(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "node02");

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "Pending");

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_status(agent_id, node, &status);

    assert_int_equal(ret, WM_TASK_SUCCESS);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_status_delete_old_node_pending_step_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "node02");

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "Pending");

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_status(agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_status_delete_old_node_pending_prepare_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "node02");

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "Pending");

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_status(agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_status_no_task_id_ok(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 0;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_status(agent_id, node, &status);

    assert_int_equal(ret, WM_TASK_SUCCESS);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_status_step_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_status(agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_status_prepare_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_status(agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_status_open_err(void **state)
{
    int agent_id = 78;
    char *node = "node03";
    char *status = NULL;
    int task_id = 6;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8276): DB couldn't be opened.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_status(agent_id, node, &status);

    assert_int_equal(ret, OS_INVALID);
    assert_null(status);
}

void test_wm_task_manager_update_upgrade_task_status_ok(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    char *node_old = "node03";
    char *status_old = "In progress";
    char *error = "Error message";
    int task_id = 36;
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

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

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, error);

    assert_int_equal(ret, WM_TASK_SUCCESS);
}

void test_wm_task_manager_update_upgrade_task_status_old_status_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    char *node_old = "node03";
    char *status_old = "Done";
    int task_id = 36;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, NULL);

    assert_int_equal(ret, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_update_upgrade_task_status_task_id_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    int task_id = 0;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, NULL);

    assert_int_equal(ret, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_update_upgrade_task_status_status_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Timeout";

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, NULL);

    assert_int_equal(ret, WM_TASK_INVALID_STATUS);
}

void test_wm_task_manager_update_upgrade_task_status_step2_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    char *node_old = "node03";
    char *status_old = "In progress";
    int task_id = 36;
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_update_upgrade_task_status_prepare2_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    char *node_old = "node03";
    char *status_old = "In progress";
    int task_id = 36;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, node_old);

    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, status_old);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_update_upgrade_task_status_step_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    int task_id = 36;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_update_upgrade_task_status_prepare_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    int task_id = 36;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_update_upgrade_task_status_open_err(void **state)
{
    int agent_id = 115;
    char *node = "node03";
    char *status = "Done";
    int task_id = 36;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8276): DB couldn't be opened.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_update_upgrade_task_status(agent_id, node, status, NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_cancel_upgrade_tasks_ok(void **state)
{
    char *node = "node05";
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_cancel_upgrade_tasks(node);

    assert_int_equal(ret, WM_TASK_SUCCESS);
}

void test_wm_task_manager_cancel_upgrade_tasks_step_err(void **state)
{
    char *node = "node05";
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, node);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_cancel_upgrade_tasks(node);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_cancel_upgrade_tasks_prepare_err(void **state)
{
    char *node = "node05";
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_cancel_upgrade_tasks(node);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_cancel_upgrade_tasks_open_err(void **state)
{
    char *node = "node05";
    int now = 123456789;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8276): DB couldn't be opened.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_cancel_upgrade_tasks(node);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_get_upgrade_task_by_agent_id_ok(void **state)
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

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

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

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_by_agent_id(agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    state[0] = node;
    state[1] = module;

    assert_int_equal(ret, task_id);
    assert_string_equal(node, "node05");
    assert_string_equal(module, "upgrade_module");
    assert_string_equal(command, "upgrade");
    assert_int_equal(update_time, 12345);
    assert_int_equal(last_update, 67890);
    assert_string_equal(status, "In progress");
    assert_string_equal(error, "Error string");

    os_free(command);
    os_free(status);
    os_free(error);
}

void test_wm_task_manager_get_upgrade_task_by_agent_id_task_id_err(void **state)
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

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_by_agent_id(agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_NOTFOUND);
    assert_null(module);
    assert_null(command);
    assert_int_equal(update_time, 0);
    assert_int_equal(last_update, 0);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_by_agent_id_step_err(void **state)
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

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_by_agent_id(agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
    assert_null(module);
    assert_null(command);
    assert_int_equal(update_time, 0);
    assert_int_equal(last_update, 0);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_by_agent_id_prepare_err(void **state)
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

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_by_agent_id(agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
    assert_null(module);
    assert_null(command);
    assert_int_equal(update_time, 0);
    assert_int_equal(last_update, 0);
    assert_null(status);
}

void test_wm_task_manager_get_upgrade_task_by_agent_id_open_err(void **state)
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

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8276): DB couldn't be opened.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_upgrade_task_by_agent_id(agent_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
    assert_null(module);
    assert_null(command);
    assert_int_equal(update_time, 0);
    assert_int_equal(last_update, 0);
    assert_null(status);
}

void test_wm_task_manager_get_task_by_task_id_ok(void **state)
{
    int agent_id = 100;
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;
    int task_id = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, agent_id);

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

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_task_by_task_id(task_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    state[0] = node;
    state[1] = module;

    assert_int_equal(ret, agent_id);
    assert_string_equal(node, "node05");
    assert_string_equal(module, "upgrade_module");
    assert_string_equal(command, "upgrade");
    assert_int_equal(update_time, 12345);
    assert_int_equal(last_update, 67890);
    assert_string_equal(status, "In progress");
    assert_string_equal(error, "Error string");

    os_free(command);
    os_free(status);
    os_free(error);
}

void test_wm_task_manager_get_task_by_task_id_task_id_err(void **state)
{
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;
    int task_id = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_task_by_task_id(task_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_NOTFOUND);
    assert_null(module);
    assert_null(command);
    assert_int_equal(update_time, 0);
    assert_int_equal(last_update, 0);
    assert_null(status);
}

void test_wm_task_manager_get_task_by_task_id_step_err(void **state)
{
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;
    int task_id = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_task_by_task_id(task_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
    assert_null(module);
    assert_null(command);
    assert_int_equal(update_time, 0);
    assert_int_equal(last_update, 0);
    assert_null(status);
}

void test_wm_task_manager_get_task_by_task_id_prepare_err(void **state)
{
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;
    int task_id = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_task_by_task_id(task_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
    assert_null(module);
    assert_null(command);
    assert_int_equal(update_time, 0);
    assert_int_equal(last_update, 0);
    assert_null(status);
}

void test_wm_task_manager_get_task_by_task_id_open_err(void **state)
{
    char *node = NULL;
    char *module = NULL;
    char *command = NULL;
    char *status = NULL;
    char *error = NULL;
    int update_time = 0;
    int last_update = 0;
    int task_id = 10;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READONLY);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8276): DB couldn't be opened.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_get_task_by_task_id(task_id, &node, &module, &command, &status, &error, &update_time, &last_update);

    assert_int_equal(ret, OS_INVALID);
    assert_null(module);
    assert_null(command);
    assert_int_equal(update_time, 0);
    assert_int_equal(last_update, 0);
    assert_null(status);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_check_db
        cmocka_unit_test(test_wm_task_manager_check_db_ok),
        cmocka_unit_test(test_wm_task_manager_check_db_chmod_err),
        cmocka_unit_test(test_wm_task_manager_check_db_chown_err),
        cmocka_unit_test(test_wm_task_manager_check_db_id_err),
        cmocka_unit_test(test_wm_task_manager_check_db_step_err),
        cmocka_unit_test(test_wm_task_manager_check_db_prepare_err),
        cmocka_unit_test(test_wm_task_manager_check_db_open_err),
        // wm_task_manager_delete_old_entries
        cmocka_unit_test(test_wm_task_manager_delete_old_entries_ok),
        cmocka_unit_test(test_wm_task_manager_delete_old_entries_step_err),
        cmocka_unit_test(test_wm_task_manager_delete_old_entries_prepare_err),
        cmocka_unit_test(test_wm_task_manager_delete_old_entries_open_err),
        // wm_task_manager_set_timeout_status
        cmocka_unit_test(test_wm_task_manager_set_timeout_status_timeout_ok),
        cmocka_unit_test(test_wm_task_manager_set_timeout_status_no_timeout_ok),
        cmocka_unit_test(test_wm_task_manager_set_timeout_status_timeout_step_err),
        cmocka_unit_test(test_wm_task_manager_set_timeout_status_timeout_prepare_err),
        cmocka_unit_test(test_wm_task_manager_set_timeout_status_prepare_err),
        cmocka_unit_test(test_wm_task_manager_set_timeout_status_open_err),
        // wm_task_manager_clean_db
        cmocka_unit_test_setup_teardown(test_wm_task_manager_clean_db, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_wm_task_manager_clean_db_timeout, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_wm_task_manager_clean_db_clean, setup_config, teardown_config),
        // wm_task_manager_insert_task
        cmocka_unit_test(test_wm_task_manager_insert_task_ok),
        cmocka_unit_test(test_wm_task_manager_insert_task_task_id_err),
        cmocka_unit_test(test_wm_task_manager_insert_task_step2_err),
        cmocka_unit_test(test_wm_task_manager_insert_task_prepare2_err),
        cmocka_unit_test(test_wm_task_manager_insert_task_step_err),
        cmocka_unit_test(test_wm_task_manager_insert_task_prepare_err),
        cmocka_unit_test(test_wm_task_manager_insert_task_open_err),
        //wm_task_manager_get_upgrade_task_status
        cmocka_unit_test_teardown(test_wm_task_manager_get_upgrade_task_status_ok, teardown_strings),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_status_delete_old_node_pending),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_status_delete_old_node_pending_step_err),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_status_delete_old_node_pending_prepare_err),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_status_no_task_id_ok),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_status_step_err),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_status_prepare_err),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_status_open_err),
        // wm_task_manager_update_upgrade_task_status
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_ok),
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_old_status_err),
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_task_id_err),
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_status_err),
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_step2_err),
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_prepare2_err),
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_step_err),
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_prepare_err),
        cmocka_unit_test(test_wm_task_manager_update_upgrade_task_status_open_err),
        // wm_task_manager_cancel_upgrade_tasks
        cmocka_unit_test(test_wm_task_manager_cancel_upgrade_tasks_ok),
        cmocka_unit_test(test_wm_task_manager_cancel_upgrade_tasks_step_err),
        cmocka_unit_test(test_wm_task_manager_cancel_upgrade_tasks_prepare_err),
        cmocka_unit_test(test_wm_task_manager_cancel_upgrade_tasks_open_err),
        // wm_task_manager_get_upgrade_task_by_agent_id
        cmocka_unit_test_teardown(test_wm_task_manager_get_upgrade_task_by_agent_id_ok, teardown_strings),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_by_agent_id_task_id_err),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_by_agent_id_step_err),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_by_agent_id_prepare_err),
        cmocka_unit_test(test_wm_task_manager_get_upgrade_task_by_agent_id_open_err),
        // wm_task_manager_get_task_by_task_id
        cmocka_unit_test_teardown(test_wm_task_manager_get_task_by_task_id_ok, teardown_strings),
        cmocka_unit_test(test_wm_task_manager_get_task_by_task_id_task_id_err),
        cmocka_unit_test(test_wm_task_manager_get_task_by_task_id_step_err),
        cmocka_unit_test(test_wm_task_manager_get_task_by_task_id_prepare_err),
        cmocka_unit_test(test_wm_task_manager_get_task_by_task_id_open_err)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
