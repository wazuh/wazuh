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
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
