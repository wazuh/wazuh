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

extern const char *SQL_STMT[];

int fim_db_process_get_query(fdb_t *fim_sql, int index,
                                    void (*callback)(fdb_t *, fim_entry *, void *),
                                    void * arg);

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

int __wrap_printf(const char *fmt, ...) {
    // Printf should not exits, if found test will fail
    fail();
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


int __wrap_fim_send_sync_msg(char * msg) {
    return 1;
}

cJSON *__wrap_fim_entry_json(const char * path, fim_entry_data * data) {
    return mock_type(cJSON*);
}

char *__wrap_dbsync_state_msg(const char * component, cJSON * data) {
    check_expected(component);
    check_expected_ptr(data);

    return mock_type(char*);
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
    will_return_count(__wrap_sqlite3_prepare_v2, SQLITE_OK, FIMDB_STMT_SIZE);
}

/**
 * Successfully wrappes a fim_db_exec_simple_wquery() call
 * */
static void wraps_fim_db_exec_simple_wquery(const char *query) {
    expect_string(__wrap_sqlite3_exec, sql, query);
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
}

/**
 * Successfully wrappes a fim_db_check_transaction() call
 * */
static void wraps_fim_db_check_transaction() {
    wraps_fim_db_exec_simple_wquery("END;");
    wraps_fim_db_exec_simple_wquery("BEGIN;");
}

/**
 * Successfully wrappes a fim_db_decode_full_row() call
 * */
static void wraps_fim_db_decode_full_row() {
    expect_value_count(__wrap_sqlite3_column_text, iCol, 0, 2);
    will_return_count(__wrap_sqlite3_column_text, "/some/random/path", 2); // path
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
    expect_value_count(__wrap_sqlite3_column_text, iCol, 11, 2);
    will_return_count(__wrap_sqlite3_column_text, "perm",2); // perm
    expect_value_count(__wrap_sqlite3_column_text, iCol, 12, 2);
    will_return_count(__wrap_sqlite3_column_text, "attributes", 2); // attributes
    expect_value_count(__wrap_sqlite3_column_text, iCol, 13, 2);
    will_return_count(__wrap_sqlite3_column_text, "uid", 2); // uid
    expect_value_count(__wrap_sqlite3_column_text, iCol, 14, 2);
    will_return_count(__wrap_sqlite3_column_text, "gid", 2); // gid
    expect_value_count(__wrap_sqlite3_column_text, iCol, 15, 2);
    will_return_count(__wrap_sqlite3_column_text, "user_name", 2); // user_name
    expect_value_count(__wrap_sqlite3_column_text, iCol, 16, 2);
    will_return_count(__wrap_sqlite3_column_text, "group_name", 2); // group_name
    expect_value(__wrap_sqlite3_column_text, iCol, 17);
    will_return(__wrap_sqlite3_column_text, "hash_md5"); // hash_md5
    expect_value(__wrap_sqlite3_column_text, iCol, 18);
    will_return(__wrap_sqlite3_column_text, "hash_sha1"); // hash_sha1
    expect_value(__wrap_sqlite3_column_text, iCol, 19);
    will_return(__wrap_sqlite3_column_text, "hash_sha256"); // hash_sha256
    expect_value(__wrap_sqlite3_column_int, iCol, 20);
    will_return(__wrap_sqlite3_column_int, 12345678); // mtime
}
/*---------------SETUP/TEARDOWN------------------*/
typedef struct _test_fim_db_insert_data {
    fdb_t *fim_sql;
    fim_entry *entry;
} test_fim_db_insert_data;

typedef struct __test_fim_db_ctx_s {
    test_fim_db_insert_data *test_data;
    EVP_MD_CTX *ctx;
} test_fim_db_ctx_t;

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

static int setup_fim_db_with_ctx(void **state) {
    test_fim_db_ctx_t *data = calloc(1, sizeof(test_fim_db_ctx_t));

    if(data == NULL)
        return -1;

    if(test_fim_db_setup((void**)&data->test_data) != 0)
        return -1;

    data->ctx = EVP_MD_CTX_create();
    EVP_DigestInit(data->ctx, EVP_sha1());

    *state = data;

    return 0;
}

static int teardown_fim_db_with_ctx(void **state) {
    test_fim_db_ctx_t *data = *state;

    test_fim_db_teardown((void**)&data->test_data);

    EVP_MD_CTX_destroy(data->ctx);

    free(data);

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
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
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
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
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
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    wraps_fim_db_exec_simple_wquery("BEGIN;");
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
    wraps_fim_db_check_transaction();
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
    wraps_fim_db_decode_full_row();
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
/*----------------------------------------------*/
/*----------fim_db_set_all_unscanned()------------------*/
void test_fim_db_set_all_unscanned_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_string(__wrap_sqlite3_exec, sql, "UPDATE entry_path SET scanned = 0;");
    will_return(__wrap_sqlite3_exec, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR MESSAGE");
    wraps_fim_db_check_transaction();
    int ret = fim_db_set_all_unscanned(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_set_all_unscanned_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    wraps_fim_db_exec_simple_wquery("UPDATE entry_path SET scanned = 0;");
    wraps_fim_db_check_transaction();
    int ret = fim_db_set_all_unscanned(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_OK);
}
/*----------------------------------------------*/
/*----------fim_db_get_data_checksum()------------------*/
void test_fim_db_get_data_checksum_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    wraps_fim_db_check_transaction();
    int ret = fim_db_get_data_checksum(test_data->fim_sql, NULL);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_get_data_checksum_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    wraps_fim_db_check_transaction();
    fim_entry *entry = fim_db_get_path(test_data->fim_sql, test_data->entry->path);
    int ret = fim_db_get_data_checksum(test_data->fim_sql, NULL);
    assert_int_equal(ret, FIMDB_OK);
}
/*----------------------------------------------*/
/*----------fim_db_sync_path_range()------------------*/
void test_fim_db_sync_path_range(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    //will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_decode_full_row();
    wraps_fim_db_check_transaction();

    int ret = fim_db_sync_path_range(test_data->fim_sql, "init", "top");
    assert_int_equal(FIMDB_OK, ret);
}
/*----------------------------------------------*/
/*----------fim_db_check_transaction()------------------*/
void test_fim_db_check_transaction_last_commit_is_0(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->fim_sql->transaction.last_commit = 0;
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR MESSAGE");
    fim_db_check_transaction(test_data->fim_sql);
    assert_int_equal(test_data->fim_sql->transaction.last_commit, 0);
}

void test_fim_db_check_transaction_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR MESSAGE");
    const time_t commit_time = test_data->fim_sql->transaction.last_commit;
    fim_db_check_transaction(test_data->fim_sql);
    assert_int_equal(commit_time, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_check_transaction_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    wraps_fim_db_check_transaction();
    const time_t commit_time = test_data->fim_sql->transaction.last_commit;
    fim_db_check_transaction(test_data->fim_sql);
    assert_int_not_equal(commit_time, test_data->fim_sql->transaction.last_commit);
}
/*----------------------------------------------*/
/*----------fim_db_cache()------------------*/
void test_fim_db_cache_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
    expect_string(__wrap__merror, formatted_msg, "Error in fim_db_cache(): statement(0)'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);' REASON GOES HERE");
    int ret = fim_db_cache(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_cache_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    wraps_fim_db_cache();
    int ret = fim_db_cache(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_OK);
}
/*----------------------------------------------*/
/*----------fim_db_close()------------------*/
void test_fim_db_close_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    wraps_fim_db_check_transaction();
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return(__wrap_sqlite3_finalize, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
    expect_string(__wrap__merror, formatted_msg, "Error in fim_db_finalize_stmt(): statement(0)'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);' REASON GOES HERE");
    will_return(__wrap_sqlite3_close_v2, SQLITE_BUSY);
    expect_string(__wrap__merror, formatted_msg, "Error in fim_db_close(): Fim db couldn't close");
    fim_db_close(test_data->fim_sql);
}

void test_fim_db_close_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    wraps_fim_db_check_transaction();
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_close_v2, SQLITE_OK);
    fim_db_close(test_data->fim_sql);
}
/*----------------------------------------------*/
/*----------fim_db_clean()------------------*/
void test_fim_db_clean_no_db_file(void **state) {
    expect_string(__wrap_w_is_file, file, FIM_DB_DISK_PATH);
    will_return(__wrap_w_is_file, 0);
    int ret = fim_db_clean();
    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_clean_file_not_removed(void **state) {
    expect_string(__wrap_w_is_file, file, FIM_DB_DISK_PATH);
    will_return(__wrap_w_is_file, 1);
    expect_string(__wrap_remove, filename, FIM_DB_DISK_PATH);
    will_return(__wrap_remove, -1);
    int ret = fim_db_clean();
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_clean_succes(void **state) {
    wraps_fim_db_clean();
    int ret =  fim_db_clean();
    assert_int_equal(ret, FIMDB_OK);
}
/*----------------------------------------------*/
/*----------fim_db_finalize_stmt()------------------*/
void test_fim_db_finalize_stmt_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    int index;
    for (index = 0; index < FIMDB_STMT_SIZE; index++) {
        // Test failure in every index
        if ( index > 0) {
            will_return_count(__wrap_sqlite3_finalize, SQLITE_OK, index);
        }
        // Index of failure  SQL_SQMT[index]
        will_return(__wrap_sqlite3_finalize, SQLITE_ERROR);
        char buffer[OS_MAXSTR];
        will_return(__wrap_sqlite3_errmsg, "FINALIZE ERROR");
        snprintf(buffer, OS_MAXSTR, "Error in fim_db_finalize_stmt(): statement(%d)'%s' FINALIZE ERROR", index, SQL_STMT[index]);
        expect_string(__wrap__merror, formatted_msg, buffer);
        int ret = fim_db_finalize_stmt(test_data->fim_sql);
        assert_int_equal(ret, FIMDB_ERR);
    }
}

void test_fim_db_finalize_stmt_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_count(__wrap_sqlite3_finalize, SQLITE_OK, FIMDB_STMT_SIZE);
    int ret = fim_db_finalize_stmt(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_OK);
}
/*----------------------------------------------*/
/*----------fim_db_force_commit()------------------*/
void test_fim_db_force_commit_failed(void **state){
    test_fim_db_insert_data *test_data = *state;
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR_MESSAGE");
    fim_db_force_commit(test_data->fim_sql);
    // If commit fails last_commit should still be one
    assert_int_equal(1, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_force_commit_success(void **state){
    test_fim_db_insert_data *test_data = *state;
    wraps_fim_db_check_transaction();
    fim_db_force_commit(test_data->fim_sql);
    // If commit succeded last_comit time should be updated
    assert_int_not_equal(1, test_data->fim_sql->transaction.last_commit);
}
/*----------------------------------------------*/
/*----------fim_db_clean_stmt()------------------*/
void test_fim_db_clean_stmt_reset_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_ERROR);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    int ret = fim_db_clean_stmt(test_data->fim_sql, 0);
    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_clean_stmt_reset_and_prepare_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_ERROR);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Error in fim_db_cache(): ERROR");
    int ret = fim_db_clean_stmt(test_data->fim_sql, 0);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_clean_stmt_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    int ret = fim_db_clean_stmt(test_data->fim_sql, 0);
    assert_int_equal(ret, FIMDB_OK);
}
/*----------------------------------------------*/
/*----------fim_db_get_paths_from_inode()------------------*/
void test_fim_db_get_paths_from_inode_none_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    assert_null(paths);
}

void test_fim_db_get_paths_from_inode_single_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "Path 1");
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    assert_string_equal(paths[0], "Path 1");
    assert_null(paths[1]);
}

void test_fim_db_get_paths_from_inode_multiple_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    int i;
    char buffer[10];
    for(i = 0; i < 5; i++) {
        // Generate 5 paths
        will_return(__wrap_sqlite3_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        snprintf(buffer, 10, "Path %d", i + 1);
        will_return(__wrap_sqlite3_column_text, strdup(buffer));
    }
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    for(i=0; i<5; i++) {
        snprintf(buffer, 10, "Path %d", i + 1);
        assert_string_equal(paths[i], buffer);
    }
    assert_null(paths[5]);
}

/**
 * Test error message when number of iterated rows is larger than count
 * */
void test_fim_db_get_paths_from_inode_multiple_unamatched_rows(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    int i;
    char buffer[10];
    for(i = 0; i < 5; i++) {
        // Generate 5 paths
        will_return(__wrap_sqlite3_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        snprintf(buffer, 10, "Path %d", i + 1);
        will_return(__wrap_sqlite3_column_text, strdup(buffer));
    }
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "Error in fim_db_get_paths_from_inode(): Unmatched number of rows in queries");
    wraps_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    for(i=0; i<5; i++) {
        snprintf(buffer, 10, "Path %d", i + 1);
        assert_string_equal(paths[i], buffer);
    }
    assert_null(paths[5]);
}
/*----------------------------------------------*/
/*----------fim_db_data_checksum_range()------------------*/
void test_fim_db_data_checksum_range_first_half_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR MESSAGE");
    int ret;
    ret = fim_db_data_checksum_range(test_data->fim_sql, "init", "end", 1, 5);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_data_checksum_range_second_half_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: ERROR MESSAGE");
    int ret;
    ret = fim_db_data_checksum_range(test_data->fim_sql, "init", "end", 1, 2);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_data_checksum_range_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    int ret;
    ret = fim_db_data_checksum_range(test_data->fim_sql, "init", "end", 1, 2);
    assert_int_equal(ret, FIMDB_OK);
}

/*----------------------------------------------*/
/*----------fim_db_get_row_path()------------------*/
void test_fim_db_get_row_path_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    char *path = NULL;
    int ret;

    // Inside fim_db_clean_stmt
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "An error message.");

    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: An error message.");

    ret = fim_db_get_row_path(test_data->fim_sql, FIMDB_STMT_GET_FIRST_PATH, &path);

    assert_int_equal(ret, FIMDB_ERR);
    assert_null(path);
}

void test_fim_db_get_row_path_sqlite_row(void **state) {
    test_fim_db_insert_data *test_data = *state;
    char *path = NULL;
    int ret;

    // Inside fim_db_clean_stmt
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 0, 2);
    will_return_count(__wrap_sqlite3_column_text, "A query response", 2);

    ret = fim_db_get_row_path(test_data->fim_sql, FIMDB_STMT_GET_FIRST_PATH, &path);

    assert_int_equal(ret, FIMDB_OK);
    assert_string_equal(path, "A query response");
    free(path);
}

void test_fim_db_get_row_path_sqlite_done(void **state) {
    test_fim_db_insert_data *test_data = *state;
    char *path = NULL;
    int ret;

    // Inside fim_db_clean_stmt
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    ret = fim_db_get_row_path(test_data->fim_sql, FIMDB_STMT_GET_FIRST_PATH, &path);

    assert_int_equal(ret, FIMDB_OK);
    assert_null(path);
}
/*----------------------------------------------*/
/*----------fim_db_get_count_range()------------------*/
void test_fim_db_get_count_range_error_stepping(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret, count = -1;

    // Inside fim_db_clean_stmt
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    // Inside fim_db_bind_range
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "Some SQLite error");

    expect_string(__wrap__merror, formatted_msg, "SQL ERROR: Some SQLite error");

    ret = fim_db_get_count_range(test_data->fim_sql, "begin", "top", &count);

    assert_int_equal(ret, FIMDB_ERR);
    assert_int_equal(count, -1);
}

void test_fim_db_get_count_range_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret, count = -1;

    // Inside fim_db_clean_stmt
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    // Inside fim_db_bind_range
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 15);

    ret = fim_db_get_count_range(test_data->fim_sql, "begin", "top", &count);

    assert_int_equal(ret, FIMDB_OK);
    assert_int_equal(count, 15);
}
/*----------------------------------------------*/
/*----------fim_db_process_get_query()------------------*/
void auxiliar_callback(fdb_t *fim_sql, fim_entry *entry, void *arg) {
    // unused
}

void test_fim_db_process_get_query_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    wraps_fim_db_decode_full_row();

    wraps_fim_db_check_transaction();

    ret = fim_db_process_get_query(test_data->fim_sql, 0, auxiliar_callback, NULL);

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_process_get_query_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    wraps_fim_db_check_transaction();

    ret = fim_db_process_get_query(test_data->fim_sql, 0, auxiliar_callback, NULL);

    assert_int_equal(ret, FIMDB_ERR);
}
/*----------------------------------------------*/
/*----------fim_db_delete_range()------------------*/
void test_fim_db_delete_range_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    // Inside fim_db_clean_stmt
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    // Inside fim_db_bind_range
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);

    // Inside fim_db_process_get_query
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    wraps_fim_db_decode_full_row();

    // Inside fim_db_remove_path (callback)
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

    // Done with fim_db_process_get_query
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    wraps_fim_db_check_transaction();

    ret = fim_db_delete_range(test_data->fim_sql, "start", "top");

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_delete_range_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    // Inside fim_db_clean_stmt
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    // Inside fim_db_bind_range
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);

    // Inside fim_db_process_get_query
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    wraps_fim_db_check_transaction();

    ret = fim_db_delete_range(test_data->fim_sql, "start", "top");

    assert_int_equal(ret, FIMDB_ERR);
}

/*----------------------------------------------*/
/*----------fim_db_delete_not_scanned()------------------*/
void test_fim_db_delete_not_scanned_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    // Inside fim_db_process_get_query
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    wraps_fim_db_decode_full_row();

    // Inside fim_db_remove_path (callback)
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

    // Done with fim_db_process_get_query
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    wraps_fim_db_check_transaction();

    ret = fim_db_delete_not_scanned(test_data->fim_sql);

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_delete_not_scanned_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    // Inside fim_db_process_get_query
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    wraps_fim_db_check_transaction();

    ret = fim_db_delete_not_scanned(test_data->fim_sql);

    assert_int_equal(ret, FIMDB_ERR);
}

/*----------------------------------------------*/
/*----------fim_db_callback_sync_path_range()------------------*/
void test_fim_db_callback_sync_path_range(void **state) {
    test_fim_db_insert_data *test_data = *state;
    cJSON *root = cJSON_CreateObject();

    will_return(__wrap_fim_entry_json, root);

    expect_string(__wrap_dbsync_state_msg, component, "syscheck");
    expect_value(__wrap_dbsync_state_msg, data, root);
    will_return(__wrap_dbsync_state_msg, strdup("This is the returned JSON"));

    fim_db_callback_sync_path_range(test_data->fim_sql, test_data->entry, NULL);
}

/*----------------------------------------------*/
/*----------fim_db_callback_calculate_checksum()------------------*/
void test_fim_db_callback_calculate_checksum(void **state) {
    test_fim_db_ctx_t *data = *state;

    // Fill up a mock fim_entry
    data->test_data->entry->data->mode = 1;
    data->test_data->entry->data->last_event = 1234;
    data->test_data->entry->data->entry_type = 2;
    data->test_data->entry->data->scanned = 2345;
    data->test_data->entry->data->options = 3456;
    strcpy(data->test_data->entry->data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->test_data->entry->data->dev = 4567;
    data->test_data->entry->data->inode = 5678;
    data->test_data->entry->data->size = 4096;
    data->test_data->entry->data->perm = "perm";
    data->test_data->entry->data->attributes = "attributes";
    data->test_data->entry->data->uid = "uid";
    data->test_data->entry->data->gid = "gid";
    data->test_data->entry->data->user_name = "user_name";
    data->test_data->entry->data->group_name = "group_name";
    strcpy(data->test_data->entry->data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(data->test_data->entry->data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(data->test_data->entry->data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    data->test_data->entry->data->mtime = 6789;

    fim_db_callback_calculate_checksum(data->test_data->fim_sql, data->test_data->entry, data->ctx);

    assert_string_equal(data->test_data->entry->data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
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
        // fim_db_remove_path
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_no_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_one_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_multiple_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_failed_path, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_path
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_inexistent, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_existent, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_set_all_unscanned
        cmocka_unit_test_setup_teardown(test_fim_db_set_all_unscanned_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_set_all_unscanned_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_data_checksum
        cmocka_unit_test_setup_teardown(test_fim_db_get_data_checksum_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_data_checksum_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_sync_path_range
        cmocka_unit_test_setup_teardown(test_fim_db_sync_path_range, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_check_transaction
        cmocka_unit_test_setup_teardown(test_fim_db_check_transaction_last_commit_is_0, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_check_transaction_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_check_transaction_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_cache
        cmocka_unit_test_setup_teardown(test_fim_db_cache_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_cache_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_close
        cmocka_unit_test_setup_teardown(test_fim_db_close_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_close_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_clean
        cmocka_unit_test_setup_teardown(test_fim_db_clean_no_db_file, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_clean_file_not_removed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_clean_succes, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_finalize_stmt
        cmocka_unit_test_setup_teardown(test_fim_db_finalize_stmt_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_finalize_stmt_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_force_commit
        cmocka_unit_test_setup_teardown(test_fim_db_force_commit_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_force_commit_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_clean_stmt
        cmocka_unit_test_setup_teardown(test_fim_db_clean_stmt_reset_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_clean_stmt_reset_and_prepare_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_clean_stmt_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_paths_from_inode
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_none_path, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_single_path, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_multiple_path, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_multiple_unamatched_rows, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_data_checksum_range
        cmocka_unit_test_setup_teardown(test_fim_db_data_checksum_range_first_half_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_data_checksum_range_second_half_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_data_checksum_range_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_row_path
        cmocka_unit_test_setup_teardown(test_fim_db_get_row_path_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_row_path_sqlite_row, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_row_path_sqlite_done, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_count_range
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_range_error_stepping, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_range_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_process_get_query
        cmocka_unit_test_setup_teardown(test_fim_db_process_get_query_success, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_process_get_query_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_delete_range
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_success, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_delete_not_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_delete_not_scanned_success, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_not_scanned_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_callback_sync_path_range
        cmocka_unit_test_setup_teardown(test_fim_db_callback_sync_path_range, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_callback_calculate_checksum
        cmocka_unit_test_setup_teardown(test_fim_db_callback_calculate_checksum, setup_fim_db_with_ctx, teardown_fim_db_with_ctx),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
