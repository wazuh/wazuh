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

int __wrap_sqlite3_column_int(sqlite3_stmt* pStmt, int iCol) {
    check_expected(iCol);
    return mock();
}

const char *__wrap_sqlite3_column_text(sqlite3_stmt* pStmt, int iCol) {
    check_expected(iCol);
    return mock_ptr_type(const char *);
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

/**
 * Successfully wrappes a fim_db_check_transaction() call
 * */
static void wraps_fim_db_check_transaction() {
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    expect_string(__wrap_sqlite3_exec, sql, "BEGIN;");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
}
/*---------------SETUP/TEARDOWN------------------*/
typedef struct _test_fim_db_insert_data {
    fdb_t *fim_sql;
    fim_entry *entry;
} test_fim_db_insert_data;

static int test_fim_db_setup(void **state) {
    test_fim_db_insert_data *test_data;
    os_calloc(1, sizeof(test_fim_db_insert_data), test_data);
    os_calloc(1, sizeof(fdb_t), test_data->fim_sql);
    os_calloc(1, sizeof(fim_entry), test_data->entry);
    os_calloc(1, sizeof(fim_entry_data), test_data->entry->data);
    test_data->entry->path =  strdup("/test/path");
    test_data->fim_sql->transaction.last_commit = 1; //Set a time diferent than 0
    *state = test_data;
    return 0;
}

static int test_fim_db_teardown(void **state) {
    test_fim_db_insert_data *test_data = *state;
    os_free(test_data->entry->path);
    os_free(test_data->entry->data);
    os_free(test_data->entry);
    os_free(test_data->fim_sql);
    os_free(test_data);
    return 0;
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
void test_fim_db_insert_data_clean_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_ERROR);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Error in fim_db_cache(): ERROR MESSAGE");
    int ret;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->path, test_data->entry->data);
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
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->path, test_data->entry->data);
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
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->path, test_data->entry->data);
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
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->path, test_data->entry->data);
    assert_int_equal(ret, FIMDB_ERR);
    // Last commit time should not change
    assert_int_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_insert_data_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    wraps_fim_db_check_transaction();
    int ret;
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->path, test_data->entry->data);
    assert_int_equal(ret, FIMDB_OK);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}
/*-----------------------------------------*/
/*----------fim_db_remove_path------------------*/
void test_fim_db_remove_path_no_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_one_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return_count(__wrap_sqlite3_step, SQLITE_DONE, 2);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_multiple_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_failed_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_maybe(__wrap_sqlite3_bind_int, 0);
    will_return_maybe(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR MESSAGE");
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, NULL);
    // Last commit time should change
    assert_int_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}
/*----------------------------------------------*/
/*----------fim_db_get_inode------------------*/
void test_fim_db_get_inode_non_existent(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK); 
    will_return_maybe(__wrap_sqlite3_bind_int, 0);
    will_return_maybe(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    wraps_fim_db_check_transaction();
    int ret = fim_db_get_inode(test_data->fim_sql, 1, 1);
    assert_int_equal(ret, 0);
}

void test_fim_db_get_inode_existent(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK); 
    will_return_maybe(__wrap_sqlite3_bind_int, 0);
    will_return_maybe(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_check_transaction();
    int ret = fim_db_get_inode(test_data->fim_sql, 1, 1);
    assert_int_equal(ret, 1);
}
/*----------------------------------------------*/
/*----------fim_db_get_path()------------------*/
void test_fim_db_get_path_inexistent(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_maybe(__wrap_sqlite3_bind_int, 0);
    will_return_maybe(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    fim_entry *ret = fim_db_get_path(test_data->fim_sql, test_data->entry->path);
    assert_null(ret);
}

void test_fim_db_get_path_existent(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_maybe(__wrap_sqlite3_bind_int, 0);
    will_return_maybe(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "/some/random/path"); // path
    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, 1); // mode
    expect_value(__wrap_sqlite3_column_int, iCol, 3);
    will_return(__wrap_sqlite3_column_int, 1000000); // last_event
    expect_value(__wrap_sqlite3_column_int, iCol, 4);
    will_return(__wrap_sqlite3_column_int, 2); // entry_type
    expect_value(__wrap_sqlite3_column_int, iCol, 5);
    will_return(__wrap_sqlite3_column_int, 1000001); // scanned
    expect_value(__wrap_sqlite3_column_int, iCol, 6);
    will_return(__wrap_sqlite3_column_int, 1000002); // options
    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "checksum"); // checksum
    expect_value(__wrap_sqlite3_column_int, iCol, 8);
    will_return(__wrap_sqlite3_column_int, 111); // dev
    expect_value(__wrap_sqlite3_column_int, iCol, 9);
    will_return(__wrap_sqlite3_column_int, 1024); // inode
    expect_value(__wrap_sqlite3_column_int, iCol, 10);
    will_return(__wrap_sqlite3_column_int, 4096); // size
    expect_value(__wrap_sqlite3_column_text, iCol, 11);
    will_return(__wrap_sqlite3_column_text, "perm"); // perm
    expect_value(__wrap_sqlite3_column_text, iCol, 12);
    will_return(__wrap_sqlite3_column_text, "attributes"); // attributes
    expect_value(__wrap_sqlite3_column_text, iCol, 13);
    will_return(__wrap_sqlite3_column_text, "uid"); // uid
    expect_value(__wrap_sqlite3_column_text, iCol, 14);
    will_return(__wrap_sqlite3_column_text, "gid"); // gid
    expect_value(__wrap_sqlite3_column_text, iCol, 15);
    will_return(__wrap_sqlite3_column_text, "user_name"); // user_name
    expect_value(__wrap_sqlite3_column_text, iCol, 16);
    will_return(__wrap_sqlite3_column_text, "group_name"); // group_name
    expect_value(__wrap_sqlite3_column_text, iCol, 17);
    will_return(__wrap_sqlite3_column_text, "hash_md5"); // hash_md5
    expect_value(__wrap_sqlite3_column_text, iCol, 18);
    will_return(__wrap_sqlite3_column_text, "hash_sha1"); // hash_sha1
    expect_value(__wrap_sqlite3_column_text, iCol, 19);
    will_return(__wrap_sqlite3_column_text, "hash_sha256"); // hash_sha256
    expect_value(__wrap_sqlite3_column_int, iCol, 20);
    will_return(__wrap_sqlite3_column_int, 12345678); // mtime
    fim_entry *ret = fim_db_get_path(test_data->fim_sql, test_data->entry->path);
    assert_non_null(ret);
    assert_string_equal("/some/random/path", ret->path);
    assert_int_equal(1, ret->data->mode);
    assert_int_equal(1000000, ret->data->last_event);
    assert_int_equal(2, ret->data->entry_type);
    assert_int_equal(1000001, ret->data->scanned);
    assert_int_equal(1000002, ret->data->options);
    assert_string_equal("checksum", ret->data->checksum);
    assert_int_equal(111, ret->data->dev);
    assert_int_equal(1024, ret->data->inode);
    assert_int_equal(4096, ret->data->size);
    assert_string_equal("perm", ret->data->perm);
    assert_string_equal("attributes", ret->data->attributes);
    assert_string_equal("uid", ret->data->uid);
    assert_string_equal("gid", ret->data->gid);
    assert_string_equal("user_name", ret->data->user_name);
    assert_string_equal("group_name", ret->data->group_name);
    assert_string_equal("hash_md5", ret->data->hash_md5);
    assert_string_equal("hash_sha1", ret->data->hash_sha1);
    assert_string_equal("hash_sha256", ret->data->hash_sha256);
    assert_int_equal(12345678, ret->data->mtime);
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
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_clean_error, test_fim_db_setup, test_fim_db_teardown),    
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_insert_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_update_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_insert_path_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_insert_data
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_no_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_one_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_multiple_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_failed_path, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_inode()
        cmocka_unit_test_setup_teardown(test_fim_db_get_inode_non_existent, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_inode_existent, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_path()
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_inexistent, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_existent, test_fim_db_setup, test_fim_db_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}