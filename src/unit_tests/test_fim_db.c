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
#include <stdlib.h>
#include "../syscheckd/fim_db.h"
/*--------------WRAPS-----------------------*/

int __wrap_w_is_file(const char * const file) {
    check_expected(file);
    return mock();
}

int __wrap_remove(const char *filename) {
    check_expected(filename);
    return mock();
}

int __wrap_sqlite3_open_v2(
  const char *filename,   /* Database filename (UTF-8) */
  sqlite3 **ppDb,         /* OUT: SQLite db handle */
  int flags,              /* Flags */
  const char *zVfs        /* Name of VFS module to use */
) {
    check_expected(filename);
    check_expected(flags);
    return mock();
}

int __wrap_sqlite3_exec(
  sqlite3* db,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *arg,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
) {
    check_expected(sql);
    *errmsg = mock_ptr_type(char *);
    return mock();
}

int __wrap_sqlite3_prepare_v2(
  sqlite3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
){
    if(pzTail){
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

void __wrap_sqlite3_free(void* ptr) {
   return;
}

int __wrap_sqlite3_reset(sqlite3_stmt *pStmt) {
    return mock();
}

int __wrap_sqlite3_clear_bindings(sqlite3_stmt* pStmt) {
    return mock();
}

const char *__wrap_sqlite3_errmsg(sqlite3* db){
    return mock_ptr_type(const char *);
}

int __wrap_sqlite3_bind_int(sqlite3_stmt* pStmt, int a, int b) {
    return mock();
}

int __wrap_sqlite3_bind_text(sqlite3_stmt* pStmt,int a,const char* b,int c,void *d ) {
    return mock();
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_chmod (const char *__file, __mode_t __mode) {
    return 0;
}
/*-----------------------------------------*/

/*---------------AUXILIAR------------------*/

/**
 * Successfully wrappes a fim_db_clean() call
 * */
static void wraps_fim_db_clean() {
    expect_string(__wrap_w_is_file, file, FIM_DB_DISK_PATH);
    will_return(__wrap_w_is_file, 1);
    expect_string(__wrap_remove, filename, FIM_DB_DISK_PATH);
    will_return(__wrap_remove, 0);
}

/**
 * Successfully wrappes a fim_db_create_file() call
 * */
static void wraps_fim_db_create_file() {
    expect_string(__wrap_sqlite3_open_v2, filename, "/var/ossec/queue/db/fim.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_close_v2,0);
}

/**
 * Successfully wrappes a fim_db_cache() call
 * */
static void wraps_fim_db_cache() {
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return_count(__wrap_sqlite3_prepare_v2, SQLITE_OK, FIMDB_STMT_SIZE);
}

/**
 * Successfully wrappes a fim_db_exec_simple_wquery() call
 * */
static void wraps_fim_db_exec_simple_wquery() {
    expect_string(__wrap_sqlite3_exec, sql, "BEGIN;");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
}

/*-----------------------------------------*/
/*---------------fim_db_init------------------*/
static int test_teardown_fim_db_init(void **state) {
    fdb_t *fim_db = (fdb_t *) *state;
    os_free(fim_db);
    return 0;
}

void test_fim_db_init_failed_db_clean(void **state) {
    expect_string(__wrap_w_is_file, file, FIM_DB_DISK_PATH);
    will_return(__wrap_w_is_file, 1);
    expect_string(__wrap_remove, filename, FIM_DB_DISK_PATH);
    will_return(__wrap_remove, -1);
    fdb_t* fim_db;
    fim_db = fim_db_init(0);
    assert_null(fim_db);
}

void test_fim_db_init_failed_file_creation(void **state) {
    wraps_fim_db_clean();
    expect_string(__wrap_sqlite3_open_v2, filename, "/var/ossec/queue/db/fim.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_close_v2, 0);
    fdb_t* fim_db;
    fim_db = fim_db_init(0);
    assert_null(fim_db);
}

void test_fim_db_init_failed_open_db(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, "/var/ossec/queue/db/fim.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);
    fdb_t* fim_db;
    fim_db = fim_db_init(0);
    assert_null(fim_db);
}

void test_fim_db_init_failed_cache(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
    expect_string(__wrap__merror, formatted_msg, "Error in fim_db_cache(): statement(0)'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);' REASON GOES HERE");
    fdb_t* fim_db;
    fim_db = fim_db_init(0);
    assert_null(fim_db);
}

void test_fim_db_init_failed_execution(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF");
    will_return(__wrap_sqlite3_exec, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR_MESSAGE");
    fdb_t* fim_db;
    fim_db = fim_db_init(0);
    assert_null(fim_db);
}

void test_fim_db_init_failed_simple_query(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    // Simple query fails
    expect_string(__wrap_sqlite3_exec, sql, "BEGIN;");
    will_return(__wrap_sqlite3_exec, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR_MESSAGE");
    fdb_t* fim_db;
    fim_db = fim_db_init(0);
    assert_null(fim_db);
}

void test_fim_db_init_success(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    wraps_fim_db_exec_simple_wquery();
    fdb_t* fim_db;
    fim_db = fim_db_init(0);
    assert_non_null(fim_db);
    *state = fim_db;
}
/*-----------------------------------------*/
/*---------------fim_db_clean------------------*/
void test_fim_db_clean_success() {
    wraps_fim_db_clean();
    int ret = fim_db_clean();
    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_clean_failed() {
    expect_string(__wrap_w_is_file, file, FIM_DB_DISK_PATH);
    will_return(__wrap_w_is_file, 1);
    expect_string(__wrap_remove, filename, FIM_DB_DISK_PATH);
    will_return(__wrap_remove, FIMDB_ERR);
    int ret = fim_db_clean();
    assert_int_equal(ret, FIMDB_ERR);
}
/*-----------------------------------------*/
/*----------fim_db_insert_data------------------*/
typedef struct _test_fim_db_insert_data {
    fdb_t *fim_sql;
    char* filepath;
    fim_entry_data *entry_data;
} test_fim_db_insert_data;

static int test_fim_db_insert_data_setup(void **state) {
    test_fim_db_insert_data *test_data;
    os_calloc(1, sizeof(test_fim_db_insert_data), test_data);
    os_calloc(1, sizeof(fdb_t), test_data->fim_sql);
    os_calloc(1, sizeof(fim_entry_data), test_data->entry_data);
    test_data->filepath =  strdup("/test/path");
    test_data->fim_sql->transaction.last_commit = 1; //Set a time diferent than 0
    *state = test_data;
    return 0;
}

static int test_fim_db_insert_data_teardown(void **state) {
    test_fim_db_insert_data *test_data = *state;
    os_free(test_data->filepath);
    os_free(test_data->entry_data);
    os_free(test_data->fim_sql);
    os_free(test_data);
    return 0;
}

void test_fim_db_insert_data_clean_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_ERROR);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Error in fim_db_cache(): ERROR MESSAGE");
    int ret;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->filepath, test_data->entry_data);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_insert_data_insert_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: (1)ERROR MESSAGE");
    int ret;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->filepath, test_data->entry_data);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_insert_data_update_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: (1)ERROR MESSAGE");
    int ret;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->filepath, test_data->entry_data);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_insert_data_insert_path_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: (1)ERROR MESSAGE");
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    expect_string(__wrap_sqlite3_exec, sql, "BEGIN;");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    int ret;
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->filepath, test_data->entry_data);
    assert_int_equal(ret, FIMDB_ERR);
    // Last commit time should not change
    assert_int_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

/*-----------------------------------------*/
int main(void) {
    const struct CMUnitTest tests[] = {
        // fim_db_init
        cmocka_unit_test(test_fim_db_init_failed_db_clean),
        cmocka_unit_test(test_fim_db_init_failed_file_creation),
        cmocka_unit_test(test_fim_db_init_failed_open_db),
        cmocka_unit_test(test_fim_db_init_failed_cache),
        cmocka_unit_test(test_fim_db_init_failed_execution),
        cmocka_unit_test(test_fim_db_init_failed_simple_query),
        cmocka_unit_test_teardown(test_fim_db_init_success, test_teardown_fim_db_init),
        // fim_db_clean
        cmocka_unit_test(test_fim_db_clean_success),
        cmocka_unit_test(test_fim_db_clean_failed),
        // fim_db_insert_data
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_clean_error, test_fim_db_insert_data_setup, test_fim_db_insert_data_teardown),    
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_insert_error, test_fim_db_insert_data_setup, test_fim_db_insert_data_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_update_error, test_fim_db_insert_data_setup, test_fim_db_insert_data_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_insert_path_error, test_fim_db_insert_data_setup, test_fim_db_insert_data_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}