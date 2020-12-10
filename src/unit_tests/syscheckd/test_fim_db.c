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

#include "../wrappers/common.h"
#include "../wrappers/externals/openssl/digest_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/os_utils_wrappers.h"
#include "../wrappers/wazuh/shared/string_op_wrappers.h"
#include "../wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "../wrappers/wazuh/shared/integrity_op_wrappers.h"
#include "../wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_check_wrappers.h"
#include "../wrappers/wazuh/syscheckd/seechanges_wrappers.h"

#include "../syscheckd/fim_db.h"
#include "../config/syscheck-config.h"

#ifdef TEST_WINAGENT
#define __mode_t int
#endif

extern const char *SQL_STMT[];

int fim_db_process_get_query(fdb_t *fim_sql, int index,
                                    void (*callback)(fdb_t *, fim_entry *, void *),
                                    void * arg);
int fim_db_exec_simple_wquery(fdb_t *fim_sql, const char *query);
fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt);
fim_tmp_file *fim_db_create_temp_file(int storage);
void fim_db_clean_file(fim_tmp_file **file, int storage);


/*--------------WRAPS-----------------------*/

#ifndef TEST_WINAGENT
extern unsigned long __real_time();
unsigned long __wrap_time() {
    if (test_mode) {
        return 192837465;
    }
    return __real_time();
}
#endif

/*-----------------------------------------*/

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
#ifndef TEST_WINAGENT
    expect_string(__wrap_sqlite3_open_v2, filename, "/var/ossec/queue/fim/db/fim.db");
#else
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/fim/db/fim.db");
#endif
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_close_v2,0);
#ifndef TEST_WINAGENT
    expect_string(__wrap_chmod, path, "/var/ossec/queue/fim/db/fim.db");
#else
    expect_string(__wrap_chmod, path, "queue/fim/db/fim.db");
#endif
    will_return(__wrap_chmod, 0);
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
    expect_string(__wrap__mdebug1, formatted_msg, "Database transaction completed.");
    wraps_fim_db_exec_simple_wquery("BEGIN;");
}

/**
 * Successfully wrappes a fim_db_decode_full_row() call
 * */
static void wraps_fim_db_decode_full_row() {
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
    expect_value(__wrap_sqlite3_column_int64, iCol, 9);
    will_return(__wrap_sqlite3_column_int64, 1024); // inode
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

#ifndef TEST_WINAGENT
/**
 * Successfully wrappes a wraps_fim_db_insert_data() call
 * */
static void wraps_fim_db_insert_data_success(int row_id) {
    if (row_id == 0) {
        expect_any(__wrap_sqlite3_bind_int64, index);
        expect_any(__wrap_sqlite3_bind_int64, value);
        will_return(__wrap_sqlite3_bind_int64, 0);
    }

    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_count(__wrap_sqlite3_bind_int, 0, 3);
    will_return_count(__wrap_sqlite3_bind_text, 0, 9);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    if (row_id == 0) {
        will_return(__wrap_sqlite3_last_insert_rowid, 1);
    }
}

/**
 * Successfully wrappes a wraps_fim_db_insert_data() call
 * */
static void wraps_fim_db_insert_path_success() {
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_count(__wrap_sqlite3_bind_int, 0, 6);
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
}
#endif
/*---------------SETUP/TEARDOWN------------------*/
static int setup_group(void **state) {
    (void) state;

    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    Read_Syscheck_Config("test_syscheck2.conf");

    syscheck.database_store = 0;    // disk
    w_mutex_init(&syscheck.fim_entry_mutex, NULL);
    test_mode = 1;

#ifdef TEST_WINAGENT
    time_mock_value = 192837465;
#endif
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    Free_Syscheck(&syscheck);
    w_mutex_destroy(&syscheck.fim_entry_mutex);
    test_mode = 0;
    return 0;
}

typedef struct _test_fim_db_insert_data {
    fdb_t *fim_sql;
    fim_entry *entry;
    fim_tmp_file *tmp_file;
    fim_entry_data *saved;
} test_fim_db_insert_data;

typedef struct __test_fim_db_ctx_s {
    test_fim_db_insert_data *test_data;
    EVP_MD_CTX *ctx;
} test_fim_db_ctx_t;

static int test_fim_db_setup(void **state) {
    test_fim_db_insert_data *test_data;
    test_data = calloc(1, sizeof(test_fim_db_insert_data));
    test_data->fim_sql = calloc(1, sizeof(fdb_t));
    test_data->entry = calloc(1, sizeof(fim_entry));
    test_data->entry->data = calloc(1, sizeof(fim_entry_data));
    test_data->entry->data->inode = 200;
    test_data->entry->data->dev = 100;
    test_data->entry->path =  strdup("/test/path");
    test_data->fim_sql->transaction.last_commit = 1; //Set a time diferent than 0
    test_data->saved = calloc(1, sizeof(fim_entry_data));
    test_data->saved->inode = 100;
    test_data->saved->dev = 100;
    *state = test_data;
    return 0;
}

static int test_fim_db_teardown(void **state) {
    test_fim_db_insert_data *test_data = *state;
    free(test_data->entry->path);
    free(test_data->entry->data->perm);
    free(test_data->entry->data->attributes);
    free(test_data->entry->data->uid);
    free(test_data->entry->data->gid);
    free(test_data->entry->data->user_name);
    free(test_data->entry->data->group_name);
    free(test_data->entry->data);
    free(test_data->entry);
    free(test_data->fim_sql);
    free(test_data->saved);
    free(test_data);
    return 0;
}

static int test_fim_tmp_file_setup_disk(void **state) {
    test_fim_db_insert_data *test_data;
    if (test_fim_db_setup((void**)&test_data) != 0) {
        return -1;
    }
    test_data->tmp_file = calloc(1, sizeof(fim_tmp_file));
    test_data->tmp_file->path = strdup("/tmp/file");
    *state = test_data;
    return 0;
}

static int test_fim_tmp_file_teardown_disk(void **state) {
    test_fim_db_insert_data *test_data = *state;
    free(test_data->tmp_file->path);
    free(test_data->tmp_file);
    return test_fim_db_teardown((void**)&test_data);
}

static int test_fim_tmp_file_setup_memory(void **state) {
    test_fim_db_insert_data *test_data;
    if (test_fim_db_setup((void**)&test_data) != 0) {
        return -1;
    }
    test_data->tmp_file = calloc(1, sizeof(fim_tmp_file));
    test_data->tmp_file->list = W_Vector_init(1);
    W_Vector_insert(test_data->tmp_file->list, "/tmp/file");

    *state = test_data;
    return 0;
}

static int test_fim_tmp_file_teardown_memory(void **state) {
    test_fim_db_insert_data *test_data = *state;
    W_Vector_free(test_data->tmp_file->list);
    free(test_data->tmp_file);
    return test_fim_db_teardown((void**)&test_data);
}

static int test_fim_db_paths_teardown(void **state) {
    test_fim_db_teardown(state);
    char **paths = state[1];
    if (paths) {
        int i;
        for(i = 0; paths[i]; i++) {
            free(paths[i]);
        }
        free(paths);
    }
    return 0;
}

static int test_fim_db_json_teardown(void **state) {
    test_fim_db_teardown(state);
    cJSON *json = state[1];
    if (json) {
        cJSON_Delete(json);
    }
    return 0;
}

static int test_fim_db_entry_teardown(void **state) {
    test_fim_db_teardown(state);
    fim_entry *entry = state[1];
    if (entry) {
        free_entry(entry);
    }
    return 0;
}

static int teardown_fim_tmp_file_disk(void **state) {
    fim_tmp_file *file = state[1];

    expect_value(__wrap_fclose, _File, file->fd);
    will_return(__wrap_fclose, 1);

    fim_db_clean_file(&file, FIM_DB_DISK);
    return 0;
}

static int teardown_fim_tmp_file_memory(void **state) {
    fim_tmp_file *file = state[1];
    fim_db_clean_file(&file, FIM_DB_MEMORY);
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
/*----------fim_db_exec_simple_wquery()----------*/
void test_fim_db_exec_simple_wquery_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_string(__wrap_sqlite3_exec, sql, "BEGIN;");
    will_return(__wrap_sqlite3_exec, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "Error executing simple query 'BEGIN;': ERROR_MESSAGE");

    int ret = fim_db_exec_simple_wquery(test_data->fim_sql, "BEGIN;");
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_exec_simple_wquery_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);

    int ret = fim_db_exec_simple_wquery(test_data->fim_sql, "PRAGMA synchronous = OFF");
    assert_int_equal(ret, FIMDB_OK);
}

/*-----------------------------------------*/
/*---------------fim_db_init()---------------*/
static int test_teardown_fim_db_init(void **state) {
    fdb_t *fim_db = (fdb_t *) *state;
    free(fim_db);
    return 0;
}

void test_fim_db_init_failed_file_creation(void **state) {
    wraps_fim_db_clean();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
#ifdef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database 'queue/fim/db/fim.db': ERROR MESSAGE");
#else
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database '/var/ossec/queue/fim/db/fim.db': ERROR MESSAGE");
#endif
    will_return(__wrap_sqlite3_close_v2, 0);
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_file_creation_prepare(void **state) {
    wraps_fim_db_clean();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement '/* * SQL Schema for FIM database * Copyright (C) 2015-2020, Wazuh Inc. * * This program is a free software, you can redistribute it * and/or modify it under the terms of GPLv2. */CREATE TABLE IF NOT EXISTS entry_path (    path TEXT NOT NULL,    inode_id INTEGER,    mode INTEGER,    last_event INTEGER,    entry_type INTEGER,    scanned INTEGER,    options INTEGER,    checksum TEXT NOT NULL,    PRIMARY KEY(path));CREATE INDEX IF NOT EXISTS path_index ON entry_path (path);CREATE INDEX IF NOT EXISTS inode_index ON entry_path (inode_id);CREATE TABLE IF NOT EXISTS entry_data (    dev INTEGER,    inode INTEGER,    size INTEGER,    perm TEXT,    attributes TEXT,    uid INTEGER,    gid INTEGER,    user_name TEXT,    group_name TEXT,    hash_md5 TEXT,    hash_sha1 TEXT,    hash_sha256 TEXT,    mtime INTEGER,    PRIMARY KEY(dev, inode));CREATE INDEX IF NOT EXISTS dev_inode_index ON entry_data (dev, inode);': ERROR MESSAGE");
    will_return(__wrap_sqlite3_close_v2, 0);
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_file_creation_step(void **state) {
    wraps_fim_db_clean();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Error stepping statement '/* * SQL Schema for FIM database * Copyright (C) 2015-2020, Wazuh Inc. * * This program is a free software, you can redistribute it * and/or modify it under the terms of GPLv2. */CREATE TABLE IF NOT EXISTS entry_path (    path TEXT NOT NULL,    inode_id INTEGER,    mode INTEGER,    last_event INTEGER,    entry_type INTEGER,    scanned INTEGER,    options INTEGER,    checksum TEXT NOT NULL,    PRIMARY KEY(path));CREATE INDEX IF NOT EXISTS path_index ON entry_path (path);CREATE INDEX IF NOT EXISTS inode_index ON entry_path (inode_id);CREATE TABLE IF NOT EXISTS entry_data (    dev INTEGER,    inode INTEGER,    size INTEGER,    perm TEXT,    attributes TEXT,    uid INTEGER,    gid INTEGER,    user_name TEXT,    group_name TEXT,    hash_md5 TEXT,    hash_sha1 TEXT,    hash_sha256 TEXT,    mtime INTEGER,    PRIMARY KEY(dev, inode));CREATE INDEX IF NOT EXISTS dev_inode_index ON entry_data (dev, inode);': ERROR MESSAGE");
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_close_v2, 0);
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_file_creation_chmod(void **state) {
    errno = 0;

    wraps_fim_db_clean();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_close_v2, 0);
#ifndef TEST_WINAGENT
    expect_string(__wrap_chmod, path, "/var/ossec/queue/fim/db/fim.db");
#else
    expect_string(__wrap_chmod, path, "queue/fim/db/fim.db");
#endif
    will_return(__wrap_chmod, -1);
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object '/var/ossec/queue/fim/db/fim.db' due to [(0)-(Success)].");
#else
    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object 'queue/fim/db/fim.db' due to [(0)-(Success)].");
#endif
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_open_db(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
#ifndef TEST_WINAGENT
    expect_string(__wrap_sqlite3_open_v2, filename, "/var/ossec/queue/fim/db/fim.db");
#else
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/fim/db/fim.db");
#endif
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_cache(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#else
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#endif
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_cache_memory(void **state) {
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_MEMORY_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#else
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#endif
    will_return(__wrap_sqlite3_close_v2, 0);
    fdb_t* fim_db;
    syscheck.database_store = 1;
    fim_db = fim_db_init(syscheck.database_store);
    syscheck.database_store = 0;
    assert_null(fim_db);
}

void test_fim_db_init_failed_execution(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF");
    will_return(__wrap_sqlite3_exec, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL error turning off synchronous mode: ERROR_MESSAGE");
    // fim_db_finalize_stmt()
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_finalize, SQLITE_OK);
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_simple_query(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    // Simple query fails
    expect_string(__wrap_sqlite3_exec, sql, "BEGIN;");
    will_return(__wrap_sqlite3_exec, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "Error executing simple query 'BEGIN;': ERROR_MESSAGE");
    // fim_db_finalize_stmt()
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_finalize, SQLITE_OK);
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_success(void **state) {
    wraps_fim_db_clean();
    wraps_fim_db_create_file();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    wraps_fim_db_exec_simple_wquery("BEGIN;");
    fdb_t* fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_non_null(fim_db);
    *state = fim_db;
}
/*-----------------------------------------*/
/*---------------fim_db_clean()----------------*/
void test_fim_db_clean_no_db_file(void **state) {
    expect_string(__wrap_w_is_file, file, FIM_DB_DISK_PATH);
    will_return(__wrap_w_is_file, 0);
    fim_db_clean();
}

void test_fim_db_clean_file_not_removed(void **state) {
    int i;
    expect_string(__wrap_w_is_file, file, FIM_DB_DISK_PATH);
    will_return(__wrap_w_is_file, 1);

#ifndef TEST_WINAGENT
    for(i = 1; i <= FIMDB_RM_MAX_LOOP; i++) {
        expect_any(__wrap__mdebug2, formatted_msg);
        expect_function_call(__wrap_usleep);
    }
#else
    for(i = 1; i <= FIMDB_RM_MAX_LOOP; i++) {
        expect_any(__wrap__mdebug2, formatted_msg);
        expect_value(wrap_Sleep, dwMilliseconds, FIMDB_RM_DEFAULT_TIME * i);
    }
#endif

    expect_string_count(__wrap_remove, filename, FIM_DB_DISK_PATH, FIMDB_RM_MAX_LOOP);
    will_return_count(__wrap_remove, -1, FIMDB_RM_MAX_LOOP);

    // Inside while loop
    expect_string(__wrap_remove, filename, FIM_DB_DISK_PATH);
    will_return(__wrap_remove, 0);

    fim_db_clean();
}

void test_fim_db_clean_success(void **state) {
    wraps_fim_db_clean();
    fim_db_clean();
}
/*-----------------------------------------*/
/*----------fim_db_insert_data()---------------*/
void test_fim_db_insert_data_no_rowid_error(void **state) {
    test_fim_db_insert_data *test_data = *state;

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    //Inside fim_db_bind_insert_data
    {
        expect_any_always(__wrap_sqlite3_bind_int, index);
        expect_any_always(__wrap_sqlite3_bind_int, value);
        will_return_always(__wrap_sqlite3_bind_int, 0);
#ifndef TEST_WINAGENT
        expect_any_always(__wrap_sqlite3_bind_int64, index);
        expect_any_always(__wrap_sqlite3_bind_int64, value);
        will_return_always(__wrap_sqlite3_bind_int64, 0);
#endif
        expect_any_always(__wrap_sqlite3_bind_text, pos);
        expect_any_always(__wrap_sqlite3_bind_text, buffer);
        will_return_always(__wrap_sqlite3_bind_text, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error inserting data row_id '0': ERROR MESSAGE");

    int row_id = 0;
    int ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->data, &row_id);

    assert_int_equal(row_id, 0);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_insert_data_no_rowid_success(void **state) {
    test_fim_db_insert_data *test_data = *state;

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    //Inside fim_db_bind_insert_data
    {
        expect_any_always(__wrap_sqlite3_bind_int, index);
        expect_any_always(__wrap_sqlite3_bind_int, value);
        will_return_always(__wrap_sqlite3_bind_int, 0);
#ifndef TEST_WINAGENT
        expect_any_always(__wrap_sqlite3_bind_int64, index);
        expect_any_always(__wrap_sqlite3_bind_int64, value);
        will_return_always(__wrap_sqlite3_bind_int64, 0);
#endif
        expect_any_always(__wrap_sqlite3_bind_text, pos);
        expect_any_always(__wrap_sqlite3_bind_text, buffer);
        will_return_always(__wrap_sqlite3_bind_text, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_last_insert_rowid, 1);

    int row_id = 0;
    int ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->data, &row_id);

    assert_int_equal(row_id, 1);
    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_insert_data_rowid_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error updating data row_id '1': ERROR MESSAGE");
    int ret;
    int row_id = 1;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->data, &row_id);
    assert_int_equal(row_id, 1);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_insert_data_rowid_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    int ret;
    int row_id = 1;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->data, &row_id);
    assert_int_equal(row_id, 1);
    assert_int_equal(ret, FIMDB_OK);
}
/*-----------------------------------------*/
/*----------fim_db_insert_path()---------------*/
void test_fim_db_insert_path_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_count(__wrap_sqlite3_bind_int, 0, 6);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error replacing path '/test/path': ERROR MESSAGE");
    int ret;
    ret = fim_db_insert_path(test_data->fim_sql, test_data->entry->path, test_data->entry->data, 1);
    assert_int_equal(ret, FIMDB_ERR);
}


void test_fim_db_insert_path_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_count(__wrap_sqlite3_bind_int, 0, 6);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    int ret;
    ret = fim_db_insert_path(test_data->fim_sql, test_data->entry->path, test_data->entry->data, 1);
    assert_int_equal(ret, FIMDB_OK);
}

/*-----------------------------------------*/
/*----------fim_db_insert()----------------*/

void test_fim_db_insert_db_full(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    // Inside fim_db_get_count_entry_path
    {
        // Inside fim_db_clean_stmt
        {
            will_return(__wrap_sqlite3_reset, SQLITE_OK);
            will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
        }
        will_return(__wrap_sqlite3_step, SQLITE_ROW);

        expect_value(__wrap_sqlite3_column_int, iCol, 0);
        will_return(__wrap_sqlite3_column_int, 50000);
    }

    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't insert '/test/path' entry into DB. The DB is full, please check your configuration.");

    syscheck.database = test_data->fim_sql;
    ret = fim_db_insert(test_data->fim_sql, test_data->entry->path, test_data->entry->data, NULL);
    syscheck.database = NULL;
    assert_int_equal(ret, FIMDB_FULL);
}

#ifndef TEST_WINAGENT
void test_fim_db_insert_inode_id_nonull(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    // Inside fim_db_bind_path
    {
        expect_any_always(__wrap_sqlite3_bind_int, index);
        expect_any_always(__wrap_sqlite3_bind_int, value);
        will_return(__wrap_sqlite3_bind_int, 0);

        expect_any_always(__wrap_sqlite3_bind_text, pos);
        expect_any_always(__wrap_sqlite3_bind_text, buffer);
        will_return(__wrap_sqlite3_bind_text, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    // Inside fim_db_bind_delete_data_id
    {
        will_return(__wrap_sqlite3_bind_int, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    // Inside fim_db_force_commit
    {
        wraps_fim_db_check_transaction();
    }

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    // Inside fim_db_bind_get_inode
    {
        expect_any(__wrap_sqlite3_bind_int64, index);
        expect_any(__wrap_sqlite3_bind_int64, value);
        will_return(__wrap_sqlite3_bind_int64, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    // Wrap functions for fim_db_insert_data() & fim_db_insert_path()
    int inode_id = 1;
    wraps_fim_db_insert_data_success(inode_id);
    wraps_fim_db_insert_path_success();

    wraps_fim_db_check_transaction();

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->path, test_data->entry->data, test_data->saved);
    assert_int_equal(ret, FIMDB_OK);   // Success
}

void test_fim_db_insert_inode_id_null(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    // Inside fim_db_bind_path
    {
        expect_any_always(__wrap_sqlite3_bind_int, index);
        expect_any_always(__wrap_sqlite3_bind_int, value);
        will_return(__wrap_sqlite3_bind_int, 0);

        expect_any_always(__wrap_sqlite3_bind_text, pos);
        expect_any_always(__wrap_sqlite3_bind_text, buffer);
        will_return(__wrap_sqlite3_bind_text, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 0);

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    // Inside fim_db_bind_delete_data_id
    {
        will_return(__wrap_sqlite3_bind_int, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    // Inside fim_db_force_commit
    {
        wraps_fim_db_check_transaction();
    }

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    // Inside fim_db_bind_get_inode
    {
        expect_any(__wrap_sqlite3_bind_int64, index);
        expect_any(__wrap_sqlite3_bind_int64, value);
        will_return(__wrap_sqlite3_bind_int64, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    // Wrap functions for fim_db_insert_data() & fim_db_insert_path()
    int inode_id = 0;
    wraps_fim_db_insert_data_success(inode_id);
    wraps_fim_db_insert_path_success();

    wraps_fim_db_check_transaction();

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->path, test_data->entry->data, test_data->saved);
    assert_int_equal(ret, FIMDB_OK);   // Success
}

void test_fim_db_insert_inode_id_null_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;
    test_data->entry->data->inode = 100;

    // Inside fim_db_clean_stmt
    {
        will_return(__wrap_sqlite3_reset, SQLITE_OK);
        will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    }

    // Inside fim_db_bind_get_inode
    {
        expect_any_always(__wrap_sqlite3_bind_int, index);
        expect_any_always(__wrap_sqlite3_bind_int, value);
        will_return(__wrap_sqlite3_bind_int, 0);

        expect_any(__wrap_sqlite3_bind_int64, index);
        expect_any(__wrap_sqlite3_bind_int64, value);
        will_return(__wrap_sqlite3_bind_int64, 0);
    }

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting data row: ERROR MESSAGE");

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->path, test_data->entry->data, test_data->saved);
    assert_int_equal(ret, FIMDB_ERR);
}

#endif

/*-----------------------------------------*/
/*----------fim_db_remove_path------------------*/
void test_fim_db_remove_path_no_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_one_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return_count(__wrap_sqlite3_step, SQLITE_DONE, 2);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_one_entry_step_fail(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_one_entry_alert_fail(void **state) {
    test_fim_db_insert_data *test_data = *state;
    cJSON * json = cJSON_CreateObject();

#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return_count(__wrap_sqlite3_step, SQLITE_DONE, 2);

#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return(__wrap_fim_json_event, json);
    expect_string(__wrap__mdebug2, formatted_msg, "(6220): Sending delete message for file: '/test/path'");
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    int alert = 1;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, &alert, (void *) FIM_WHODATA, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_one_entry_alert_fail_invalid_pos(void **state) {
    test_fim_db_insert_data *test_data = *state;

#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return_count(__wrap_sqlite3_step, SQLITE_DONE, 2);
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, -1);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    int alert = 1;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, &alert, (void *) FIM_WHODATA, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_one_entry_alert_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return_count(__wrap_sqlite3_step, SQLITE_DONE, 2);

#ifndef TEST_WINAGENT
    expect_string(__wrap_delete_target_file, path, test_data->entry->path);
    will_return(__wrap_delete_target_file, 0);
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    cJSON * json = cJSON_CreateObject();

    will_return(__wrap_fim_json_event, json);
    expect_string(__wrap__mdebug2, formatted_msg, "(6220): Sending delete message for file: '/test/path'");
    wraps_fim_db_check_transaction();

    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    int alert = 1;

    syscheck.opts[1] |= CHECK_SEECHANGES;

#ifndef TEST_WINAGENT
    char *diff_path;

    diff_path = (char *)malloc(sizeof(char) * (strlen("/var/ossec/queue/diff/local") +
                                                strlen(test_data->entry->path) + 1));

    snprintf(diff_path, (strlen("/var/ossec/queue/diff/local") + strlen(test_data->entry->path) + 1), "%s%s",
                "/var/ossec/queue/diff/local", test_data->entry->path);

    expect_string(__wrap_IsDir, file, diff_path);
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, diff_path);
    will_return(__wrap_DirSize, 200);
#endif

    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, &alert, (void *) FIM_WHODATA, NULL);

    syscheck.opts[1] &= ~CHECK_SEECHANGES;
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);

#ifndef TEST_WINAGENT
    if (diff_path) {
        free(diff_path);
    }
#endif
}

void test_fim_db_remove_path_multiple_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_multiple_entry_step_fail(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_failed_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 9);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "Error executing simple query 'END;': ERROR MESSAGE");
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);
    // Last commit time should change
    assert_int_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_no_configuration_file(void **state) {
    test_fim_db_insert_data *test_data = *state;

    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, -1);
    expect_string(__wrap__mdebug2, formatted_msg, "(6339): Delete event from path without configuration: '/test/path'");

    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_REALTIME, NULL);
}

void test_fim_db_remove_path_no_entry_realtime_file(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 3);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 7);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_REALTIME, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_remove_path_no_entry_scheduled_file(void **state) {
    test_fim_db_insert_data *test_data = *state;
#ifndef TEST_WINAGENT
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 4);
#else
    expect_string(__wrap_fim_configuration_directory, path, "/test/path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    wraps_fim_db_check_transaction();
    time_t last_commit =  test_data->fim_sql->transaction.last_commit;
    fim_db_remove_path(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_SCHEDULED, NULL);
    // Last commit time should change
    assert_int_not_equal(last_commit, test_data->fim_sql->transaction.last_commit);
}

/*----------------------------------------------*/
/*----------fim_db_get_path()------------------*/
void test_fim_db_get_path_inexistent(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    fim_entry *ret = fim_db_get_path(test_data->fim_sql, test_data->entry->path);
    state[1] = ret;
    assert_null(ret);
}

void test_fim_db_get_path_existent(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    fim_entry *ret = fim_db_get_path(test_data->fim_sql, test_data->entry->path);
    state[1] = ret;
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
    expect_string(__wrap__merror, formatted_msg, "Error executing simple query 'UPDATE entry_path SET scanned = 0;': ERROR MESSAGE");
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

void test_fim_db_get_path_range_failed(void **state) {

    test_fim_db_insert_data *test_data = *state;
    fim_tmp_file *file = NULL;

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 0);

    will_return(__wrap_os_random, 2345);

#ifndef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "/var/ossec/tmp/tmp_19283746523452345");
    expect_string(__wrap__merror, formatted_msg, "Failed to create temporal storage '/var/ossec/tmp/tmp_19283746523452345': Success (0)");
#else
    expect_string(__wrap_wfopen, __filename, "tmp/tmp_19283746523452345");
    expect_string(__wrap__merror, formatted_msg, "Failed to create temporal storage 'tmp/tmp_19283746523452345': Success (0)");
#endif

    int ret = fim_db_get_path_range(test_data->fim_sql, "start", "stop", &file, syscheck.database_store);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_get_path_range_success(void **state) {

    test_fim_db_insert_data *test_data = *state;
    fim_tmp_file *file = NULL;

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "/var/ossec/tmp/tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 1);

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();

#ifndef TEST_WINAGENT
    expect_string(__wrap_remove, filename, "/var/ossec/tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_remove, filename, "tmp/tmp_19283746523452345");
#endif

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    will_return(__wrap_remove, 0);

    int ret = fim_db_get_path_range(test_data->fim_sql, "start", "stop", &file, syscheck.database_store);
    assert_int_equal(ret, FIMDB_OK);
}

/*----------------------------------------------*/
/*----------fim_db_get_not_scanned()------------------*/

void test_fim_db_get_not_scanned_failed(void **state) {

    test_fim_db_insert_data *test_data = *state;
    fim_tmp_file *file = NULL;

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "/var/ossec/tmp/tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 0);
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Failed to create temporal storage '/var/ossec/tmp/tmp_19283746523452345': Success (0)");
#else
    expect_string(__wrap__merror, formatted_msg, "Failed to create temporal storage 'tmp/tmp_19283746523452345': Success (0)");
#endif

    int ret = fim_db_get_not_scanned(test_data->fim_sql, &file, syscheck.database_store);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_get_not_scanned_success(void **state) {

    test_fim_db_insert_data *test_data = *state;
    fim_tmp_file *file = NULL;

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "/var/ossec/tmp/tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();

#ifndef TEST_WINAGENT
    expect_string(__wrap_remove, filename, "/var/ossec/tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_remove, filename, "tmp/tmp_19283746523452345");
#endif

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    will_return(__wrap_remove, 0);

    int ret = fim_db_get_not_scanned(test_data->fim_sql, &file, syscheck.database_store);
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
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    expect_string(__wrap_EVP_DigestUpdate, data, "checksum");
    expect_value(__wrap_EVP_DigestUpdate, count, 8);
    will_return(__wrap_EVP_DigestUpdate, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);  // Ending the loop at fim_db_process_get_query()
    wraps_fim_db_check_transaction();
    int ret = fim_db_get_data_checksum(test_data->fim_sql, NULL);
    assert_int_equal(ret, FIMDB_OK);
}
/*----------------------------------------------*/
/*----------fim_db_check_transaction()------------------*/
void test_fim_db_check_transaction_last_commit_is_0(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->fim_sql->transaction.last_commit = 0;
    fim_db_check_transaction(test_data->fim_sql);
    assert_int_not_equal(test_data->fim_sql->transaction.last_commit, 0);
}

void test_fim_db_check_transaction_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "Error executing simple query 'END;': ERROR MESSAGE");
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
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#else
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#endif
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
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Error finalizing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#else
    expect_string(__wrap__merror, formatted_msg, "Error finalizing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#endif
    will_return(__wrap_sqlite3_close_v2, SQLITE_BUSY);
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
        snprintf(buffer, OS_MAXSTR, "Error finalizing statement '%s': FINALIZE ERROR", SQL_STMT[index]);
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
    expect_string(__wrap__merror, formatted_msg, "Error executing simple query 'END;': ERROR_MESSAGE");
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
    #ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': ERROR");
    #else
    expect_string(__wrap__merror, formatted_msg, "Error preparing statement 'INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);': ERROR");
    #endif
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
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_int64, index);
    expect_any_always(__wrap_sqlite3_bind_int64, value);
    will_return_always(__wrap_sqlite3_bind_int64, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    state[1] = paths;
    assert_null(paths);
}

void test_fim_db_get_paths_from_inode_single_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_int64, index);
    expect_any_always(__wrap_sqlite3_bind_int64, value);
    will_return_always(__wrap_sqlite3_bind_int64, 0);
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
    state[1] = paths;
    assert_string_equal(paths[0], "Path 1");
    assert_null(paths[1]);
}

void test_fim_db_get_paths_from_inode_multiple_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_int64, index);
    expect_any_always(__wrap_sqlite3_bind_int64, value);
    will_return_always(__wrap_sqlite3_bind_int64, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    int i;
    char buffers[5][10];
    for(i = 0; i < sizeof(buffers)/10; i++) {
        // Generate 5 paths
        will_return(__wrap_sqlite3_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        snprintf(buffers[i], 10, "Path %d", i + 1);
        will_return(__wrap_sqlite3_column_text, buffers[i]);
    }
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    state[1] = paths;
    for(i = 0; i < sizeof(buffers)/10; i++) {
        snprintf(buffers[i], 10, "Path %d", i + 1);
        assert_string_equal(paths[i], buffers[i]);
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
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_int64, index);
    expect_any_always(__wrap_sqlite3_bind_int64, value);
    will_return_always(__wrap_sqlite3_bind_int64, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    int i;
    char buffers[5][10];
    for(i = 0; i < sizeof(buffers)/10; i++) {
        // Generate 5 paths
        will_return(__wrap_sqlite3_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        snprintf(buffers[i], 10, "Path %d", i + 1);
        will_return(__wrap_sqlite3_column_text, buffers[i]);
    }
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_string(__wrap__minfo, formatted_msg, "The count returned is smaller than the actual elements. This shouldn't happen.");
    wraps_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    state[1] = paths;
    for(i = 0; i < sizeof(buffers)/10; i++) {
        snprintf(buffers[i], 10, "Path %d", i + 1);
        assert_string_equal(paths[i], buffers[i]);
    }
    assert_null(paths[5]);
}
/*----------------------------------------------*/
/*----------fim_db_data_checksum_range()------------------*/
void test_fim_db_data_checksum_range_first_half_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting path range, first half 'start init' 'top end' (i:0): ERROR MESSAGE");
    int ret;
    ret = fim_db_data_checksum_range(test_data->fim_sql, "init", "end", 1, 5, &syscheck.fim_entry_mutex);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_data_checksum_range_second_half_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);

    // First half
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    expect_string(__wrap_EVP_DigestUpdate, data, "checksum");
    expect_value(__wrap_EVP_DigestUpdate, count, 8);
    will_return(__wrap_EVP_DigestUpdate, 0);

    // Second half
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting path range, second half 'start init' 'top end' (i:1): ERROR MESSAGE");

    int ret;
    ret = fim_db_data_checksum_range(test_data->fim_sql, "init", "end", 1, 2, &syscheck.fim_entry_mutex);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_data_checksum_range_null_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);

    // Fist half
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    expect_string(__wrap_EVP_DigestUpdate, data, "checksum");
    expect_value(__wrap_EVP_DigestUpdate, count, 8);
    will_return(__wrap_EVP_DigestUpdate, 0);

    expect_string(__wrap__merror, formatted_msg, "Failed to obtain required paths in order to form message");

    int ret;
    ret = fim_db_data_checksum_range(test_data->fim_sql, "init", "end", 1, 1, &syscheck.fim_entry_mutex);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_data_checksum_range_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);

    // Fist half
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    expect_string(__wrap_EVP_DigestUpdate, data, "checksum");
    expect_value(__wrap_EVP_DigestUpdate, count, 8);
    will_return(__wrap_EVP_DigestUpdate, 0);

    // Second half
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
    expect_string(__wrap_EVP_DigestUpdate, data, "checksum");
    expect_value(__wrap_EVP_DigestUpdate, count, 8);
    will_return(__wrap_EVP_DigestUpdate, 0);

    expect_string(__wrap_fim_send_sync_msg, msg, "{\"component\":\"syscheck\",\"type\":\"integrity_check_left\",\"data\":{\"id\":1,\"begin\":\"init\",\"end\":\"/some/random/path\",\"tail\":\"/some/random/path\",\"checksum\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\"}}");
    expect_string(__wrap_fim_send_sync_msg, msg, "{\"component\":\"syscheck\",\"type\":\"integrity_check_right\",\"data\":{\"id\":1,\"begin\":\"/some/random/path\",\"end\":\"end\",\"checksum\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\"}}");

    int ret;
    ret = fim_db_data_checksum_range(test_data->fim_sql, "init", "end", 1, 2, &syscheck.fim_entry_mutex);
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

    expect_string(__wrap__merror, formatted_msg, "Step error getting row path '(null)': An error message.");

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

    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "/some/random/path");

    ret = fim_db_get_row_path(test_data->fim_sql, FIMDB_STMT_GET_FIRST_PATH, &path);

    assert_int_equal(ret, FIMDB_OK);
    assert_string_equal(path, "/some/random/path");
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
    expect_any_count(__wrap_sqlite3_bind_text, pos, 2);
    expect_any_count(__wrap_sqlite3_bind_text, buffer, 2);
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "Some SQLite error");

    expect_string(__wrap__merror, formatted_msg, "Step error getting count range 'start begin' 'top top': Some SQLite error");

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
    expect_any_count(__wrap_sqlite3_bind_text, pos, 2);
    expect_any_count(__wrap_sqlite3_bind_text, buffer, 2);
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
/*----------fim_db_sync_path_range()------------------*/
void test_fim_db_sync_path_range_disk(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value_count(wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(wrap_fgets, "00000000000000000000000000000010");
    will_return(wrap_fgets, "/tmp/file\n");
#else
    expect_value_count(__wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(__wrap_fgets, "00000000000000000000000000000010");
    will_return(__wrap_fgets, "/tmp/file\n");
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();

    // fim_db_callback_sync_path_range()
    cJSON *root = cJSON_CreateObject();
    state[1] = root;
    expect_string(__wrap_fim_entry_json, path, "/some/random/path");
    will_return(__wrap_fim_entry_json, root);
    expect_string(__wrap_dbsync_state_msg, component, "syscheck");
    expect_value(__wrap_dbsync_state_msg, data, root);
    will_return(__wrap_dbsync_state_msg, strdup("This is the returned JSON"));

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Sync Message for /some/random/path sent: This is the returned JSON");

    expect_string(__wrap_fim_send_sync_msg, msg, "This is the returned JSON");

    int ret = fim_db_sync_path_range(test_data->fim_sql, &syscheck.fim_entry_mutex, test_data->tmp_file, syscheck.database_store);
    assert_int_equal(FIMDB_OK, ret);
}

void test_fim_db_sync_path_range_memory(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->elements = 1;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();

    // fim_db_callback_sync_path_range()
    cJSON *root = cJSON_CreateObject();
    state[1] = root;
    expect_string(__wrap_fim_entry_json, path, "/some/random/path");
    will_return(__wrap_fim_entry_json, root);
    expect_string(__wrap_dbsync_state_msg, component, "syscheck");
    expect_value(__wrap_dbsync_state_msg, data, root);
    will_return(__wrap_dbsync_state_msg, strdup("This is the returned JSON"));

    expect_string(__wrap__mdebug1, formatted_msg, "Sync Message for /some/random/path sent: This is the returned JSON");

    expect_string(__wrap_fim_send_sync_msg, msg, "This is the returned JSON");

    syscheck.database_store = 1;
    int ret = fim_db_sync_path_range(test_data->fim_sql, &syscheck.fim_entry_mutex, test_data->tmp_file, syscheck.database_store);
    syscheck.database_store = 0;
    assert_int_equal(FIMDB_OK, ret);
}

/*----------------------------------------------*/
/*----------fim_db_delete_range()------------------*/
void test_fim_db_delete_range_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;
    int ret;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value_count(wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(wrap_fgets, "00000000000000000000000000000010");
    will_return(wrap_fgets, "/tmp/file\n");
#else
    expect_value_count(__wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(__wrap_fgets, "00000000000000000000000000000010");
    will_return(__wrap_fgets, "/tmp/file\n");
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();

    // Inside fim_db_remove_path (callback)
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex,
                              syscheck.database_store, FIM_SCHEDULED);

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_delete_range_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;
    int ret;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value_count(wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(wrap_fgets, "00000000000000000000000000000010");
    will_return(wrap_fgets, "/tmp/file\n");
#else
    expect_value_count(__wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(__wrap_fgets, "00000000000000000000000000000010");
    will_return(__wrap_fgets, "/tmp/file\n");
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();

    // Inside fim_db_remove_path (callback)
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    wraps_fim_db_check_transaction();

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex,
                              syscheck.database_store, FIM_SCHEDULED);

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_delete_range_path_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;
    int ret;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value_count(wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(wrap_fgets, "00000000000000000000000000000001");
    will_return(wrap_fgets, "\n");
#else
    expect_value_count(__wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(__wrap_fgets, "00000000000000000000000000000001");
    will_return(__wrap_fgets, "\n");
#endif

    expect_string(__wrap__merror, formatted_msg, "Temporary path file '/tmp/file' is corrupt: missing line end.");

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex,
                              syscheck.database_store, FIM_SCHEDULED);

    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_delete_range_fail_to_reposition_file(void **state) {
    char warning_message[OS_SIZE_256];
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;
    int ret;

    will_return(__wrap_fseek, -1);

    snprintf(warning_message, OS_SIZE_256, FIM_DB_TEMPORARY_FILE_POSITION, errno, strerror(errno));

    expect_string(__wrap__mwarn, formatted_msg, warning_message);

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex,
                              syscheck.database_store, FIM_SCHEDULED);

    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_delete_range_fail_to_read_line_length(void **state) {
    char debug_message[OS_SIZE_256];
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;
    int ret;

    will_return(__wrap_fseek, 0);

#ifdef WIN32
    expect_value(wrap_fgets, __stream, (FILE*)2345);
    will_return(wrap_fgets, NULL);
#else
    expect_value(__wrap_fgets, __stream, (FILE*)2345);
    will_return(__wrap_fgets, NULL);
#endif

    snprintf(debug_message, OS_SIZE_256, FIM_UNABLE_TO_READ_TEMP_FILE);

    expect_string(__wrap__mdebug1, formatted_msg, debug_message);

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex,
                              syscheck.database_store, FIM_SCHEDULED);

    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_delete_range_fail_to_read_line(void **state) {
    char debug_message[OS_SIZE_256];
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;
    int ret;

    will_return(__wrap_fseek, 0);

#ifdef WIN32
    expect_value_count(wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(wrap_fgets, "00000000000000000000000000000010");
    will_return(wrap_fgets, NULL);
#else
    expect_value_count(__wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(__wrap_fgets, "00000000000000000000000000000001");
    will_return(__wrap_fgets, NULL);
#endif

    snprintf(debug_message, OS_SIZE_256, FIM_UNABLE_TO_READ_TEMP_FILE);

    expect_string(__wrap__mdebug1, formatted_msg, debug_message);

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex,
                              syscheck.database_store, FIM_SCHEDULED);

    assert_int_equal(ret, FIMDB_ERR);
}

/*----------------------------------------------*/
/*----------fim_db_delete_not_scanned()------------------*/
void test_fim_db_delete_not_scanned(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;
    int ret;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value_count(wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(wrap_fgets, "00000000000000000000000000000010");
    will_return(wrap_fgets, "/tmp/file\n");
#else
    expect_value_count(__wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(__wrap_fgets, "00000000000000000000000000000010");
    will_return(__wrap_fgets, "/tmp/file\n");
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();

    // Inside fim_db_remove_path (callback)
    // Its return value is not checked so forcing the error is the simplest way to wrap it
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    wraps_fim_db_check_transaction();

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    ret = fim_db_delete_not_scanned(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex, syscheck.database_store);

    assert_int_equal(ret, FIMDB_OK);
}

/*----------------------------------------------*/
/*----------fim_db_process_missing_entry()------------------*/
void test_fim_db_process_missing_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    test_data->tmp_file->elements = 1;
    int ret;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value_count(wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(wrap_fgets, "00000000000000000000000000000010");
    will_return(wrap_fgets, "/tmp/file\n");
#else
    expect_value_count(__wrap_fgets, __stream, (FILE*)2345, 2);
    will_return(__wrap_fgets, "00000000000000000000000000000010");
    will_return(__wrap_fgets, "/tmp/file\n");
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();

    // Inside fim_db_remove_path (callback)
    // Its return value is not checked so force the error is the simplest way to wrap it
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    wraps_fim_db_check_transaction();

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    ret = fim_db_process_missing_entry(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex, syscheck.database_store, FIM_REALTIME, NULL);

    assert_int_equal(ret, FIMDB_OK);
}

/*----------------------------------------------*/
/*----------fim_db_callback_sync_path_range()------------------*/
void test_fim_db_callback_sync_path_range(void **state) {
    test_fim_db_insert_data *test_data = *state;
    cJSON *root = cJSON_CreateObject();
    state[1] = root;

    expect_string(__wrap_fim_entry_json, path, "/test/path");
    will_return(__wrap_fim_entry_json, root);

    expect_string(__wrap_dbsync_state_msg, component, "syscheck");
    expect_value(__wrap_dbsync_state_msg, data, root);
    will_return(__wrap_dbsync_state_msg, strdup("This is the returned JSON"));

    expect_string(__wrap__mdebug1, formatted_msg, "Sync Message for /test/path sent: This is the returned JSON");

    expect_string(__wrap_fim_send_sync_msg, msg, "This is the returned JSON");

    fim_db_callback_sync_path_range(test_data->fim_sql, test_data->entry, &syscheck.fim_entry_mutex, NULL, NULL, NULL);
}

/*----------------------------------------------*/
/*----------fim_db_callback_save_path()------------------*/
void test_fim_db_callback_save_path_null(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return(__wrap_wstr_escape_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error escaping '/test/path'");

    fim_db_callback_save_path(test_data->fim_sql, test_data->entry, syscheck.database_store, test_data->tmp_file);

    assert_int_equal(test_data->tmp_file->elements, 0);
}

void test_fim_db_callback_save_path_disk(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;

    will_return(__wrap_wstr_escape_json, strdup("/test/path"));

#ifndef TEST_WINAGENT
    expect_value(__wrap_fprintf, __stream, 2345);
    expect_string(__wrap_fprintf, formatted_msg, "00000000000000000000000000000011/test/path\n");
    will_return(__wrap_fprintf, 11);
#else
    expect_value(wrap_fprintf, __stream, 2345);
    expect_string(wrap_fprintf, formatted_msg, "00000000000000000000000000000011/test/path\n");
    will_return(wrap_fprintf, 11);
#endif

    fim_db_callback_save_path(test_data->fim_sql, test_data->entry, syscheck.database_store, test_data->tmp_file);
    assert_int_equal(test_data->tmp_file->elements, 1);
}

void test_fim_db_callback_save_path_disk_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;

    will_return(__wrap_wstr_escape_json, strdup("/test/path"));

#ifndef TEST_WINAGENT
    expect_value(__wrap_fprintf, __stream, 2345);
    expect_string(__wrap_fprintf, formatted_msg, "00000000000000000000000000000011/test/path\n");
    will_return(__wrap_fprintf, -1);
#else
    expect_value(wrap_fprintf, __stream, 2345);
    expect_string(wrap_fprintf, formatted_msg, "00000000000000000000000000000011/test/path\n");
    will_return(wrap_fprintf, -1);
#endif

    errno = 0;

    expect_string(__wrap__merror, formatted_msg, "/test/path - Success");

    fim_db_callback_save_path(test_data->fim_sql, test_data->entry, syscheck.database_store, test_data->tmp_file);
    assert_int_equal(test_data->tmp_file->elements, 0);
}

void test_fim_db_callback_save_path_memory(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return(__wrap_wstr_escape_json, strdup("/test/path"));

    syscheck.database_store = 1;
    fim_db_callback_save_path(test_data->fim_sql, test_data->entry, syscheck.database_store, test_data->tmp_file);
    syscheck.database_store = 0;

    assert_non_null(test_data->tmp_file->list->vector);
    assert_string_equal(test_data->tmp_file->list->vector[1], "/test/path");
    assert_int_equal(test_data->tmp_file->list->used, 2);
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
    data->test_data->entry->data->perm = strdup("perm");
    data->test_data->entry->data->attributes = strdup("attributes");
    data->test_data->entry->data->uid = strdup("uid");
    data->test_data->entry->data->gid = strdup("gid");
    data->test_data->entry->data->user_name = strdup("user_name");
    data->test_data->entry->data->group_name = strdup("group_name");
    strcpy(data->test_data->entry->data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(data->test_data->entry->data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(data->test_data->entry->data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    data->test_data->entry->data->mtime = 6789;

    // Mock EVP_DigestUpdate()
    expect_string(__wrap_EVP_DigestUpdate, data, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);

    fim_db_callback_calculate_checksum(data->test_data->fim_sql, data->test_data->entry, syscheck.database_store, data->ctx);

    assert_string_equal(data->test_data->entry->data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}

/*----------------------------------------------*/
/*----------fim_db_get_count_entry_data()------------------*/
void test_fim_db_get_count_entry_data(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    int ret = fim_db_get_count_entry_data(test_data->fim_sql);

    assert_int_equal(ret, 1);
}

void test_fim_db_get_count_entry_data_error(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting count entry data: ERROR MESSAGE");

    int ret = fim_db_get_count_entry_data(test_data->fim_sql);

    assert_int_equal(ret, -1);
}

/*----------------------------------------------*/
/*----------fim_db_get_count_entry_path()------------------*/
void test_fim_db_get_count_entry_path(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    int ret = fim_db_get_count_entry_path(test_data->fim_sql);

    assert_int_equal(ret, 1);
}

void test_fim_db_get_count_entry_path_error(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting count entry path: ERROR MESSAGE");

    int ret = fim_db_get_count_entry_path(test_data->fim_sql);

    assert_int_equal(ret, -1);
}

/*----------------------------------------------*/
/*----------fim_db_decode_full_row()------------*/
void test_fim_db_decode_full_row(void **state) {
    test_fim_db_insert_data *test_data;
    test_data = calloc(1, sizeof(test_fim_db_insert_data));
    test_data->fim_sql = calloc(1, sizeof(fdb_t));
    wraps_fim_db_decode_full_row();
    test_data->entry = fim_db_decode_full_row(test_data->fim_sql->stmt[FIMDB_STMT_GET_PATH]);
    *state = test_data;
    assert_non_null(test_data->entry);
    assert_string_equal(test_data->entry->path, "/some/random/path");
    assert_int_equal(test_data->entry->data->mode, 1);
    assert_int_equal(test_data->entry->data->last_event, 1000000);
    assert_int_equal(test_data->entry->data->entry_type, 2);
    assert_int_equal(test_data->entry->data->scanned, 1000001);
    assert_int_equal(test_data->entry->data->options, 1000002);
    assert_string_equal(test_data->entry->data->checksum, "checksum");
    assert_int_equal(test_data->entry->data->dev, 111);
    assert_int_equal(test_data->entry->data->inode, 1024);
    assert_int_equal(test_data->entry->data->size, 4096);
    assert_string_equal(test_data->entry->data->perm, "perm");
    assert_string_equal(test_data->entry->data->attributes, "attributes");
    assert_string_equal(test_data->entry->data->uid, "uid");
    assert_string_equal(test_data->entry->data->gid, "gid");
    assert_string_equal(test_data->entry->data->user_name, "user_name");
    assert_string_equal(test_data->entry->data->group_name, "group_name");
    assert_string_equal(test_data->entry->data->hash_md5, "hash_md5");
    assert_string_equal(test_data->entry->data->hash_sha1, "hash_sha1");
    assert_string_equal(test_data->entry->data->hash_sha256, "hash_sha256");
    assert_int_equal(test_data->entry->data->mtime, 12345678);
}

/*----------------------------------------------*/
/*----------fim_db_set_scanned_error()------------*/
void test_fim_db_set_scanned_error(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any(__wrap_sqlite3_bind_text, pos);
    expect_any(__wrap_sqlite3_bind_text, buffer);
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error setting scanned path '/test/path': ERROR MESSAGE");

    int ret = fim_db_set_scanned(test_data->fim_sql, test_data->entry->path);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_set_scanned_success(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any(__wrap_sqlite3_bind_text, pos);
    expect_any(__wrap_sqlite3_bind_text, buffer);
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    wraps_fim_db_check_transaction();

    int ret = fim_db_set_scanned(test_data->fim_sql, test_data->entry->path);
    assert_int_equal(ret, FIMDB_OK);
}

/*----------------------------------------------------*/
/*---------------fim_db_create_temp_file()----------------*/
void test_fim_db_create_temp_file_disk(void **state) {

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "/var/ossec/tmp/tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 1);

#ifdef TEST_WINAGENT
    expect_string(__wrap_remove, filename, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_remove, filename, "/var/ossec/tmp/tmp_19283746523452345");
#endif
    will_return(__wrap_remove, 0);

    fim_tmp_file *ret = fim_db_create_temp_file(FIM_DB_DISK);
    state[1] = ret;

    assert_non_null(ret);
    assert_non_null(ret->fd);
    assert_string_equal(ret->path, FIM_DB_TMPDIR"tmp_19283746523452345");
}

void test_fim_db_create_temp_file_disk_error(void **state) {

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "/var/ossec/tmp/tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Failed to create temporal storage 'tmp/tmp_19283746523452345': Success (0)");
#else
    expect_string(__wrap__merror, formatted_msg, "Failed to create temporal storage '/var/ossec/tmp/tmp_19283746523452345': Success (0)");
#endif


    fim_tmp_file *ret = fim_db_create_temp_file(FIM_DB_DISK);

    assert_null(ret);
}

void test_fim_db_create_temp_file_disk_fail_to_remove_open_file(void **state) {

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "/var/ossec/tmp/tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 1);

#ifdef TEST_WINAGENT
    expect_string(__wrap_remove, filename, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_remove, filename, "/var/ossec/tmp/tmp_19283746523452345");
#endif
    will_return(__wrap_remove, -1);

#ifdef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Failed to remove 'tmp/tmp_19283746523452345': Success (0)");
#else
    expect_string(__wrap__merror, formatted_msg, "Failed to remove '/var/ossec/tmp/tmp_19283746523452345': Success (0)");
#endif

    fim_tmp_file *ret = fim_db_create_temp_file(FIM_DB_DISK);

    assert_null(ret);
}

void test_fim_db_create_temp_file_memory(void **state) {
    fim_tmp_file *ret = fim_db_create_temp_file(FIM_DB_MEMORY);
    state[1] = ret;

    assert_non_null(ret);
    assert_non_null(ret->list);
    assert_non_null(ret->list->vector);
    assert_int_equal(ret->list->size, 100);
    assert_null(ret->path);
}

/*----------------------------------------------------*/
/*---------------fim_db_clean_file()----------------*/
void test_fim_db_clean_file_disk() {
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->path = calloc(PATH_MAX, sizeof(char));
    sprintf(file->path, "test");

    expect_value(__wrap_fclose, _File, file->fd);
    will_return(__wrap_fclose, 1);

    fim_db_clean_file(&file, FIM_DB_DISK);

    assert_null(file);
}

void test_fim_db_clean_file_memory() {
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->list = calloc(1, sizeof(W_Vector));
    file->list->vector = calloc(1, sizeof(char *));

    fim_db_clean_file(&file, FIM_DB_MEMORY);

    assert_null(file);
}

/*-----------------------------------------*/
int main(void) {
    const struct CMUnitTest tests[] = {
        // fim_db_exec_simple_wquery
        cmocka_unit_test_setup_teardown(test_fim_db_exec_simple_wquery_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_exec_simple_wquery_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_init
        cmocka_unit_test(test_fim_db_init_failed_file_creation),
        cmocka_unit_test(test_fim_db_init_failed_file_creation_prepare),
        cmocka_unit_test(test_fim_db_init_failed_file_creation_step),
        cmocka_unit_test(test_fim_db_init_failed_file_creation_chmod),
        cmocka_unit_test(test_fim_db_init_failed_open_db),
        cmocka_unit_test(test_fim_db_init_failed_cache),
        cmocka_unit_test(test_fim_db_init_failed_cache_memory),
        cmocka_unit_test(test_fim_db_init_failed_execution),
        cmocka_unit_test(test_fim_db_init_failed_simple_query),
        cmocka_unit_test_teardown(test_fim_db_init_success, test_teardown_fim_db_init),
        // fim_db_clean
        cmocka_unit_test_setup_teardown(test_fim_db_clean_no_db_file, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_clean_file_not_removed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_clean_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_insert_data
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_no_rowid_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_no_rowid_success, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_rowid_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_data_rowid_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_insert_path
        cmocka_unit_test_setup_teardown(test_fim_db_insert_path_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_path_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_insert
        cmocka_unit_test_setup_teardown(test_fim_db_insert_db_full, test_fim_db_setup, test_fim_db_teardown),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_fim_db_insert_inode_id_nonull, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_inode_id_null, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_inode_id_null_error, test_fim_db_setup, test_fim_db_teardown),
#endif
        // fim_db_remove_path
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_no_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_one_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_one_entry_step_fail, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_one_entry_alert_fail, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_one_entry_alert_fail_invalid_pos, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_one_entry_alert_success, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_multiple_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_multiple_entry_step_fail, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_failed_path, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_no_configuration_file, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_no_entry_realtime_file, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_path_no_entry_scheduled_file, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_path
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_inexistent, test_fim_db_setup, test_fim_db_entry_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_existent, test_fim_db_setup, test_fim_db_entry_teardown),
        // fim_db_set_all_unscanned
        cmocka_unit_test_setup_teardown(test_fim_db_set_all_unscanned_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_set_all_unscanned_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_path_range
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_range_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_range_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_not_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_get_not_scanned_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_not_scanned_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_data_checksum
        cmocka_unit_test_setup_teardown(test_fim_db_get_data_checksum_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_data_checksum_success, test_fim_db_setup, test_fim_db_teardown),
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
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_none_path, test_fim_db_setup, test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_single_path, test_fim_db_setup, test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_multiple_path, test_fim_db_setup, test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_multiple_unamatched_rows, test_fim_db_setup, test_fim_db_paths_teardown),
        // fim_db_data_checksum_range
        cmocka_unit_test_setup_teardown(test_fim_db_data_checksum_range_first_half_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_data_checksum_range_second_half_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_data_checksum_range_null_path, test_fim_db_setup, test_fim_db_teardown),
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
        // fim_db_sync_path_range
        cmocka_unit_test_setup_teardown(test_fim_db_sync_path_range_disk, test_fim_tmp_file_setup_disk, test_fim_db_json_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_sync_path_range_memory, test_fim_tmp_file_setup_memory, test_fim_db_json_teardown),
        // fim_db_delete_range
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_success, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_error, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_path_error, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_fail_to_reposition_file, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_fail_to_read_line_length, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_fail_to_read_line, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        // fim_db_delete_not_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_delete_not_scanned, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        // fim_db_process_missing_entry
        cmocka_unit_test_setup_teardown(test_fim_db_process_missing_entry, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        // fim_db_callback_sync_path_range
        cmocka_unit_test_setup_teardown(test_fim_db_callback_sync_path_range, test_fim_db_setup, test_fim_db_json_teardown),
        // fim_db_callback_save_path
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_path_null, test_fim_tmp_file_setup_disk, test_fim_tmp_file_teardown_disk),
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_path_disk, test_fim_tmp_file_setup_disk, test_fim_tmp_file_teardown_disk),
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_path_disk_error, test_fim_tmp_file_setup_disk, test_fim_tmp_file_teardown_disk),
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_path_memory, test_fim_tmp_file_setup_memory, test_fim_tmp_file_teardown_memory),
        // fim_db_callback_calculate_checksum
        cmocka_unit_test_setup_teardown(test_fim_db_callback_calculate_checksum, setup_fim_db_with_ctx, teardown_fim_db_with_ctx),
        // fim_db_get_count_entry_data
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_entry_data, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_entry_data_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_count_entry_path
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_entry_path, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_entry_path_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_decode_full_row
        cmocka_unit_test_teardown(test_fim_db_decode_full_row, test_fim_db_teardown),
        // fim_db_set_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_set_scanned_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_set_scanned_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_create_temp_file
        cmocka_unit_test_teardown(test_fim_db_create_temp_file_disk, teardown_fim_tmp_file_disk),
        cmocka_unit_test(test_fim_db_create_temp_file_disk_error),
        cmocka_unit_test(test_fim_db_create_temp_file_disk_fail_to_remove_open_file),
        cmocka_unit_test_teardown(test_fim_db_create_temp_file_memory, teardown_fim_tmp_file_memory),
        // fim_db_clean_file
        cmocka_unit_test(test_fim_db_clean_file_disk),
        cmocka_unit_test(test_fim_db_clean_file_memory),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
