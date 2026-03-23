/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sqlite3_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../common.h"


int __wrap_sqlite3_bind_int(__attribute__((unused)) sqlite3_stmt *stmt,
                            int index,
                            int value) {
    check_expected(index);
    check_expected(value);

    return mock();
}

void expect_sqlite3_bind_int_call(int idx, int val, int ret) {
    expect_value(__wrap_sqlite3_bind_int, index, idx);
    expect_value(__wrap_sqlite3_bind_int, value, val);
    will_return(__wrap_sqlite3_bind_int, ret);
}

int __wrap_sqlite3_bind_int64(__attribute__((unused)) sqlite3_stmt *stmt,
                              int index,
                              sqlite3_int64 value) {
    check_expected(index);
    check_expected(value);

    return mock();
}

int __wrap_sqlite3_bind_double(__attribute__((unused)) sqlite3_stmt *pStmt, int index, double value) {
    check_expected(index);
    check_expected(value);

    return mock();
}

int __wrap_sqlite3_bind_null(__attribute__((unused)) sqlite3_stmt *pStmt, int index) {
    check_expected(index);

    return mock();
}

void expect_sqlite3_bind_int64_call(int idx, double val, int ret) {
    expect_value(__wrap_sqlite3_bind_int64, index, idx);
    expect_value(__wrap_sqlite3_bind_int64, value, val);
    will_return(__wrap_sqlite3_bind_int64, ret);
}

int __wrap_sqlite3_bind_text(__attribute__((unused)) sqlite3_stmt* pStmt,
                             int pos,
                             const char* buffer,
                             __attribute__((unused)) int length,
                             __attribute__((unused)) void *mem_callback) {
    check_expected(pos);
    if (buffer) check_expected(buffer);

    return mock();
}

void expect_sqlite3_bind_text_call(int position, const char *buf, int ret) {
    expect_value(__wrap_sqlite3_bind_text, pos, position);

    if (buf) {
        expect_string(__wrap_sqlite3_bind_text, buffer, buf);
    }

    will_return(__wrap_sqlite3_bind_text, ret);
}

int __wrap_sqlite3_bind_parameter_index(__attribute__((unused)) sqlite3_stmt * stmt,
                                        const char *zName) {
    check_expected(zName);

    return mock();
}

int __wrap_sqlite3_clear_bindings(__attribute__((unused)) sqlite3_stmt* pStmt) {
    return mock();
}

int __wrap_sqlite3_close_v2() {
    return mock();
}

double __wrap_sqlite3_column_double(__attribute__((unused)) sqlite3_stmt *pStmt,
                                    int iCol) {
    check_expected(iCol);
    return mock_type(double);
}

int __wrap_sqlite3_column_int(__attribute__((unused)) sqlite3_stmt *pStmt,
                              int iCol) {
    check_expected(iCol);
    return mock();
}

sqlite3_int64 __wrap_sqlite3_column_int64(__attribute__((unused)) sqlite3_stmt* stmt,
                                          int iCol) {
    check_expected(iCol);
    return mock();
}

const unsigned char *__wrap_sqlite3_column_text(__attribute__((unused)) sqlite3_stmt *pStmt,
                                                int iCol) {
    check_expected(iCol);
    return mock_type(const unsigned char*);

}

int __wrap_sqlite3_extended_errcode(__attribute__((unused)) sqlite3* db) {
    return mock();
}

const char *__wrap_sqlite3_errmsg(__attribute__((unused)) sqlite3* db) {
    return mock_ptr_type(const char *);
}

int __wrap_sqlite3_exec(__attribute__((unused)) sqlite3* db,                                /* An open database */
                        const char *sql,                                                    /* SQL to be evaluated */
                        __attribute__((unused)) int (*callback)(void*,int,char**,char**),   /* Callback function */
                        __attribute__((unused)) void *arg,                                  /* 1st argument to callback */
                        char **errmsg) {                                                    /* Error msg written here */
    check_expected(sql);
    *errmsg = mock_ptr_type(char *);
    return mock();
}

int __wrap_sqlite3_finalize(__attribute__((unused)) sqlite3_stmt *pStmt) {
    return mock();
}

void __wrap_sqlite3_free(__attribute__((unused)) void* ptr) {
    return;
}

int __wrap_sqlite3_last_insert_rowid(__attribute__((unused)) sqlite3* db){
    return mock();
}

int __wrap_sqlite3_open_v2(const char *filename,                           /* Database filename (UTF-8) */
                           sqlite3 **ppDb,                                 /* OUT: SQLite db handle */
                           int flags,                                      /* Flags */
                           __attribute__((unused)) const char *zVfs) {     /* Name of VFS module to use */
    check_expected(filename);
    check_expected(flags);
    *ppDb = mock_type(sqlite3 *);
    return mock();
}

int __wrap_sqlite3_prepare_v2(__attribute__((unused)) sqlite3 *db,            /* Database handle */
                              __attribute__((unused)) const char *zSql,       /* SQL statement, UTF-8 encoded */
                              __attribute__((unused)) int nByte,              /* Maximum length of zSql in bytes. */
                              sqlite3_stmt **ppStmt,                          /* OUT: Statement handle */
                              const char **pzTail){                           /* OUT: Pointer to unused portion of zSql */

    *ppStmt = mock_type(sqlite3_stmt *);
    if(pzTail){
        *pzTail = 0;
    }
    return mock();
}

int __wrap_sqlite3_reset(__attribute__((unused)) sqlite3_stmt *pStmt) {
    return mock();
}

extern int __real_sqlite3_step(__attribute__((unused)) sqlite3_stmt * stmt);
int __wrap_sqlite3_step(__attribute__((unused)) sqlite3_stmt * stmt){
    if (mock())
        return __real_sqlite3_step(stmt);
    else
        return mock();
}

void expect_sqlite3_step_call(int ret) {
    will_return(__wrap_sqlite3_step, 0);    // This will_return prevents from calling the real function
    will_return(__wrap_sqlite3_step, ret);
}

void expect_sqlite3_step_count(int ret, int count) {
    for (int i = count; i; i--) {
        expect_sqlite3_step_call(ret);
    }
}

int __wrap_sqlite3_column_count(__attribute__((unused)) sqlite3_stmt *stmt) {
    return mock();
}

int __wrap_sqlite3_column_type(__attribute__((unused)) sqlite3_stmt *pStmt,
                               int i){
    check_expected(i);
    return mock();
}

const char* __wrap_sqlite3_column_name(__attribute__((unused)) sqlite3_stmt *pStmt,
                                       int N){
    check_expected(N);
    return mock_ptr_type(char *);
}

int __wrap_sqlite3_changes(__attribute__((unused)) sqlite3 * db){
    return mock();
}

int __wrap_sqlite3_get_autocommit(__attribute__((unused)) sqlite3 * db) {
    return mock();
}

const char*  __wrap_sqlite3_sql(__attribute__((unused)) sqlite3_stmt *pStmt){
    return mock_ptr_type(char*);
}
