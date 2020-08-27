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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/task_manager/wm_task_manager_db.h"
#include "../../headers/shared.h"

int wm_task_manager_set_timeout_status(time_t now, time_t *next_timeout);
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

// Wrappers

void __wrap__mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs) {
    check_expected(filename);
    check_expected(flags);
    *ppDb = mock_type(sqlite3 *);
    return mock();
}

int __wrap_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail) {
    if(ppStmt) {
        *ppStmt = (sqlite3_stmt *)1;
    }
    if(pzTail) {
        *pzTail = 0;
    }
    return mock();
}

int __wrap_sqlite3_step(sqlite3_stmt* ptr) {
    return mock();
}

int __wrap_sqlite3_finalize(sqlite3_stmt *pStmt) {
    return mock();
}

int __wrap_sqlite3_close_v2(sqlite3* ptr){
    return mock();
}

char *__wrap_sqlite3_errmsg(sqlite3* db){
    return mock_type(char *);
}

uid_t __wrap_Privsep_GetUser(const char *name) {
    check_expected(name);

    return mock();
}

gid_t __wrap_Privsep_GetGroup(const char *name) {
    check_expected(name);

    return mock();
}

int __wrap_chown(const char *__file, __uid_t __owner, __gid_t __group) {
    check_expected(__file);
    check_expected(__owner);
    check_expected(__group);

    return mock();
}

int __wrap_chmod(const char *__file, __mode_t __mode) {
    check_expected(__file);
    check_expected(__mode);

    return mock();
}

int __wrap_sqlite3_bind_int(sqlite3_stmt *stmt, int index, int value) {
    check_expected(index);
    check_expected(value);

    return mock();
}

int __wrap_sqlite3_bind_text(sqlite3_stmt* pStmt, int a, const char* b, int c, void *d) {
    check_expected(a);
    if (b) check_expected(b);

    return mock();
}

int __wrap_sqlite3_column_int(sqlite3_stmt *pStmt, int i) {
    check_expected(i);
    return mock();
}

char *__wrap_sqlite3_column_text(sqlite3_stmt *pStmt, int i) {
    check_expected(i);
    return mock_type(char*);
}

time_t __wrap_time(time_t *__timer) {
    return mock();
}

void __wrap_w_sleep_until(const time_t new_time){
    check_expected(new_time);
}

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

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_string(__wrap_Privsep_GetUser, name, ROOTUSER);
    will_return(__wrap_Privsep_GetUser, uid);

    expect_string(__wrap_Privsep_GetGroup, name, GROUPGLOBAL);
    will_return(__wrap_Privsep_GetGroup, gid);

    expect_string(__wrap_chown, __file, TASKS_DB);
    expect_value(__wrap_chown, __owner, uid);
    expect_value(__wrap_chown, __group, gid);
    will_return(__wrap_chown, 0);

    expect_string(__wrap_chmod, __file, TASKS_DB);
    expect_value(__wrap_chmod, __mode, 0660);
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

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_string(__wrap_Privsep_GetUser, name, ROOTUSER);
    will_return(__wrap_Privsep_GetUser, uid);

    expect_string(__wrap_Privsep_GetGroup, name, GROUPGLOBAL);
    will_return(__wrap_Privsep_GetGroup, gid);

    expect_string(__wrap_chown, __file, TASKS_DB);
    expect_value(__wrap_chown, __owner, uid);
    expect_value(__wrap_chown, __group, gid);
    will_return(__wrap_chown, 0);

    expect_string(__wrap_chmod, __file, TASKS_DB);
    expect_value(__wrap_chmod, __mode, 0660);
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

    will_return(__wrap_sqlite3_finalize, 0);

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

    will_return(__wrap_sqlite3_finalize, 0);

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

    will_return(__wrap_sqlite3_finalize, 0);

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

    will_return(__wrap_sqlite3_finalize, 0);

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

    will_return(__wrap_sqlite3_finalize, 0);

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

    will_return(__wrap_sqlite3_finalize, 0);

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

    will_return(__wrap_sqlite3_finalize, 0);

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
    time_t next_timeout = 0;
    int task_id = 10;
    int last_update_time = now - WM_TASK_MAX_IN_PROGRESS_TIME;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, i, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, i, 5);
    will_return(__wrap_sqlite3_column_int, last_update_time);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "Timeout");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, &next_timeout);

    assert_int_equal(ret, 0);
    assert_int_equal(next_timeout, 0);
}

void test_wm_task_manager_set_timeout_status_no_timeout_ok(void **state)
{
    time_t now = 123456789;
    time_t next_timeout = 0;
    int task_id = 10;
    int last_update_time = (now - WM_TASK_MAX_IN_PROGRESS_TIME) + 100;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, i, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, i, 5);
    will_return(__wrap_sqlite3_column_int, last_update_time);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, &next_timeout);

    assert_int_equal(ret, 0);
    assert_int_equal(next_timeout, now + 100);
}

void test_wm_task_manager_set_timeout_status_timeout_step_err(void **state)
{
    time_t now = 123456789;
    time_t next_timeout = 0;
    int task_id = 10;
    int last_update_time = now - WM_TASK_MAX_IN_PROGRESS_TIME;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, i, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, i, 5);
    will_return(__wrap_sqlite3_column_int, last_update_time);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "Timeout");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, 0);
}

void test_wm_task_manager_set_timeout_status_timeout_prepare_err(void **state)
{
    time_t now = 123456789;
    time_t next_timeout = 0;
    int task_id = 10;
    int last_update_time = now - WM_TASK_MAX_IN_PROGRESS_TIME;

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, i, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, i, 5);
    will_return(__wrap_sqlite3_column_int, last_update_time);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, 0);
}

void test_wm_task_manager_set_timeout_status_prepare_err(void **state)
{
    time_t now = 123456789;
    time_t next_timeout = 0;
    int task_id = 10;
    int last_update_time = now - WM_TASK_MAX_IN_PROGRESS_TIME;

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

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_set_timeout_status(now, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, 0);
}

void test_wm_task_manager_set_timeout_status_open_err(void **state)
{
    time_t now = 123456789;
    time_t next_timeout = 0;
    int task_id = 10;
    int last_update_time = now - WM_TASK_MAX_IN_PROGRESS_TIME;

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

    int ret = wm_task_manager_set_timeout_status(now, &next_timeout);

    assert_int_equal(ret, OS_INVALID);
    assert_int_equal(next_timeout, 0);
}

void test_wm_task_manager_clean_db(void **state)
{

    wm_task_manager *config = *state;

    config->cleanup_time = 1000;

    int now = 123456789;
    int timestamp = now - config->cleanup_time;

    int task_id = 10;
    int last_update_time = now - WM_TASK_MAX_IN_PROGRESS_TIME;

    will_return(__wrap_time, now);

    will_return(__wrap_time, now);

    will_return(__wrap_time, now);

    // wm_task_manager_set_timeout_status

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, i, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, i, 5);
    will_return(__wrap_sqlite3_column_int, last_update_time);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "Timeout");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, 0);

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

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_value(__wrap_w_sleep_until, new_time, now + WM_TASK_MAX_IN_PROGRESS_TIME);

    wm_task_manager_clean_db(config);
}

void test_wm_task_manager_clean_db_timeout(void **state)
{

    wm_task_manager *config = *state;

    config->cleanup_time = 1000;

    int now = 123456789;
    int timestamp = now - config->cleanup_time;

    int task_id = 10;
    int last_update_time = now - WM_TASK_MAX_IN_PROGRESS_TIME;

    will_return(__wrap_time, now + 100);

    will_return(__wrap_time, now);

    will_return(__wrap_time, now);

    // wm_task_manager_set_timeout_status

    expect_string(__wrap_sqlite3_open_v2, filename, TASKS_DB);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "In progress");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, i, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    expect_value(__wrap_sqlite3_column_int, i, 5);
    will_return(__wrap_sqlite3_column_int, last_update_time);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, a, 1);
    expect_string(__wrap_sqlite3_bind_text, b, "Timeout");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, task_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_value(__wrap_w_sleep_until, new_time, now + 100);

    wm_task_manager_clean_db(config);
}

void test_wm_task_manager_clean_db_clean(void **state)
{

    wm_task_manager *config = *state;

    config->cleanup_time = 1000;

    int now = 123456789;
    int timestamp = now - config->cleanup_time;

    int task_id = 10;
    int last_update_time = now - WM_TASK_MAX_IN_PROGRESS_TIME;

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

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    expect_value(__wrap_w_sleep_until, new_time, now + 200);

    wm_task_manager_clean_db(config);
}

void test_wm_task_manager_insert_task_ok(void **state)
{
    int agent_id = 55;
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

    expect_value(__wrap_sqlite3_bind_text, a, 2);
    expect_string(__wrap_sqlite3_bind_text, b, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 3);
    expect_string(__wrap_sqlite3_bind_text, b, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 6);
    expect_string(__wrap_sqlite3_bind_text, b, "New");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 2);
    expect_string(__wrap_sqlite3_bind_text, b, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, i, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, module, command);

    assert_int_equal(ret, task_id);
}

void test_wm_task_manager_insert_task_task_id_err(void **state)
{
    int agent_id = 55;
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

    expect_value(__wrap_sqlite3_bind_text, a, 2);
    expect_string(__wrap_sqlite3_bind_text, b, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 3);
    expect_string(__wrap_sqlite3_bind_text, b, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 6);
    expect_string(__wrap_sqlite3_bind_text, b, "New");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 2);
    expect_string(__wrap_sqlite3_bind_text, b, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, i, 0);
    will_return(__wrap_sqlite3_column_int, task_id);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_step2_err(void **state)
{
    int agent_id = 55;
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

    expect_value(__wrap_sqlite3_bind_text, a, 2);
    expect_string(__wrap_sqlite3_bind_text, b, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 3);
    expect_string(__wrap_sqlite3_bind_text, b, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 6);
    expect_string(__wrap_sqlite3_bind_text, b, "New");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 2);
    expect_string(__wrap_sqlite3_bind_text, b, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_prepare2_err(void **state)
{
    int agent_id = 55;
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

    expect_value(__wrap_sqlite3_bind_text, a, 2);
    expect_string(__wrap_sqlite3_bind_text, b, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 3);
    expect_string(__wrap_sqlite3_bind_text, b, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 6);
    expect_string(__wrap_sqlite3_bind_text, b, "New");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8278): Couldn't prepare SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_step_err(void **state)
{
    int agent_id = 55;
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

    expect_value(__wrap_sqlite3_bind_text, a, 2);
    expect_string(__wrap_sqlite3_bind_text, b, module);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 3);
    expect_string(__wrap_sqlite3_bind_text, b, command);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_time, now);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, now);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, a, 6);
    expect_string(__wrap_sqlite3_bind_text, b, "New");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8279): Couldn't execute SQL statement.");

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8277): SQL error: 'ERROR MESSAGE'");

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_prepare_err(void **state)
{
    int agent_id = 55;
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 0;
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

    will_return(__wrap_sqlite3_finalize, 0);

    will_return(__wrap_sqlite3_close_v2,0);

    int ret = wm_task_manager_insert_task(agent_id, module, command);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_insert_task_open_err(void **state)
{
    int agent_id = 55;
    char *module = "upgrade_module";
    char *command = "upgrade";
    int task_id = 0;
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

    int ret = wm_task_manager_insert_task(agent_id, module, command);

    assert_int_equal(ret, OS_INVALID);
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
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
