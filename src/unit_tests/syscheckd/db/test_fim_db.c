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

#include "wrappers/common.h"
#include "wrappers/externals/openssl/digest_wrappers.h"
#include "wrappers/libc/stdio_wrappers.h"
#include "wrappers/posix/stat_wrappers.h"
#include "wrappers/posix/unistd_wrappers.h"
#include "wrappers/wazuh/shared/file_op_wrappers.h"
#include "wrappers/wazuh/shared/os_utils_wrappers.h"
#include "wrappers/wazuh/shared/string_op_wrappers.h"
#include "wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "wrappers/wazuh/shared/integrity_op_wrappers.h"
#include "wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "wrappers/wazuh/syscheckd/run_check_wrappers.h"
#include "wrappers/wazuh/syscheckd/fim_diff_changes_wrappers.h"

#include "db/fim_db.h"

#include "test_fim_db.h"

#ifdef TEST_WINAGENT
#define __mode_t int
#endif

extern const char *SQL_STMT[];


int fim_db_process_get_query(fdb_t *fim_sql,
                             int type,
                             int index,
                             void (*callback)(fdb_t *, fim_entry *, int, void *),
                             int storage,
                             void *arg);
int fim_db_exec_simple_wquery(fdb_t *fim_sql, const char *query);
fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt);
fim_tmp_file *fim_db_create_temp_file(int storage);
void fim_db_clean_file(fim_tmp_file **file, int storage);

/**********************************************************************************************************************\
 * Auxiliar callback functions
\**********************************************************************************************************************/
static void callback(fdb_t *fim_sql, fim_entry *entry, int storage, void *arg) {
    function_called();
}


static void
read_file_callback(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *mutex, void *alert, void *mode, void *w_evt) {
}

static void *decode(sqlite3_stmt *stmt) {
    function_called();
    return mock_type(void *);
}

static void free_row(void *row) {
    function_called();
}

/**********************************************************************************************************************\
 * Local wrappers
\**********************************************************************************************************************/

#ifndef TEST_WINAGENT
extern unsigned long __real_time();
unsigned long __wrap_time() {
    if (test_mode) {
        return 192837465;
    }
    return __real_time();
}
#endif

/**********************************************************************************************************************\
 * Auxiliar expect functions
\**********************************************************************************************************************/

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
static void expect_fim_db_create_file_success() {
#ifndef TEST_WINAGENT
    expect_string(__wrap_sqlite3_open_v2, filename, "./fim.db");
#else
    expect_string(__wrap_sqlite3_open_v2, filename, ".\\fim.db");
#endif
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_close_v2, 0);
#ifndef TEST_WINAGENT
    expect_string(__wrap_chmod, path, "./fim.db");
#else
    expect_string(__wrap_chmod, path, ".\\fim.db");
#endif
    will_return(__wrap_chmod, 0);
}

void expect_fim_db_bind_range(const char *start, const char *top, int retval) {
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, start);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, top);
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);
}

/**
 * Successfully wrappes a fim_db_cache() call
 * */
static void wraps_fim_db_cache() {
    will_return_count(__wrap_sqlite3_prepare_v2, SQLITE_OK, FIMDB_STMT_SIZE);
}

void expect_fim_db_decode_string_array(int column_count, const char **array) {
    int it;

    will_return(__wrap_sqlite3_column_count, column_count);

    for (it = 0; it < column_count && array[it]; it++) {
        expect_value(__wrap_sqlite3_column_text, iCol, it);
        will_return(__wrap_sqlite3_column_text, array[it]);
    }
}

void expect_fim_db_decode_string(const char *str) {
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, str);
}

void expect_fim_db_callback_save_string(const FILE *fd, const char *str, const char *formatted_str, int storage) {
    char *escaped_string = strdup(str);

    if (escaped_string == NULL) {
        fail_msg("%s:%d - %s: Failed to duplicate string", __FILE__, __LINE__, __func__);
    }

    will_return(__wrap_wstr_escape_json, escaped_string);

    if (storage == FIM_DB_DISK) {
#ifndef TEST_WINAGENT
        expect_value(__wrap_fprintf, __stream, fd);
        expect_string(__wrap_fprintf, formatted_msg, formatted_str);
        will_return(__wrap_fprintf, strlen(formatted_str));
#else
        expect_value(wrap_fprintf, __stream, fd);
        expect_string(wrap_fprintf, formatted_msg, formatted_str);
        will_return(wrap_fprintf, strlen(formatted_str));
#endif
    }
}

void expect_fim_db_create_temp_file_fail(int storage) {
    if (storage != FIM_DB_DISK) {
        fail_msg("'fim_db_create_temp_file' can only fail when using disk storage");
    }

    will_return(__wrap_os_random, 2345);

#ifndef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "./tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, ".\\tmp_19283746523452345");
#endif
    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg,
                  "Failed to create temporal storage './tmp_19283746523452345': Success (0)");
#else
    expect_string(__wrap__merror, formatted_msg,
                  "Failed to create temporal storage '.\\tmp_19283746523452345': Success (0)");
#endif
}

void expect_fim_db_create_temp_file_success(int storage) {
    if (storage == FIM_DB_DISK) {
        will_return(__wrap_os_random, 2345);

#ifndef TEST_WINAGENT
        expect_string(__wrap_wfopen, __filename, "./tmp_19283746523452345");
#else
        expect_string(__wrap_wfopen, __filename, ".\\tmp_19283746523452345");
#endif
        expect_string(__wrap_wfopen, __modes, "w+");
        will_return(__wrap_wfopen, 1);

#ifndef TEST_WINAGENT
        expect_string(__wrap_remove, filename, "./tmp_19283746523452345");
#else
        expect_string(__wrap_remove, filename, ".\\tmp_19283746523452345");
#endif
        will_return(__wrap_remove, 1);
    }
}

void expect_fim_db_clean_file(const FILE *fd, int storage) {
    if (storage == FIM_DB_DISK) {
        expect_value(__wrap_fclose, _File, fd);
        will_return(__wrap_fclose, 1);
    }
}

void expect_fim_db_read_line_from_file(FILE *fd, int storage, int it, const char *str) {
    if (storage == FIM_DB_DISK) {
        if (it == 0) {
            will_return(__wrap_fseek, 0);
        }

        expect_value(__wrap_fgets, __stream, fd);
        will_return(__wrap_fgets, str);
    }
}

/**********************************************************************************************************************\
 * Setup and teardown functions
\**********************************************************************************************************************/
static int test_fim_tmp_file_setup_memory(void **state) {
    test_fim_db_insert_data *test_data;
    if (test_fim_db_setup((void **)&test_data) != 0) {
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
    return test_fim_db_teardown((void **)&test_data);
}

static int teardown_fim_tmp_file_disk(void **state) {
    fim_tmp_file *file = *state;

    expect_value(__wrap_fclose, _File, file->fd);
    will_return(__wrap_fclose, 1);

    fim_db_clean_file(&file, FIM_DB_DISK);
    return 0;
}

static int teardown_fim_tmp_file_memory(void **state) {
    fim_tmp_file *file = *state;
    fim_db_clean_file(&file, FIM_DB_MEMORY);
    return 0;
}

static int teardown_string(void **state) {
    if (*state) {
        free(*state);
    }

    return 0;
}

static int teardown_string_array(void **state) {
    free_strarray(*state);

    return 0;
}

static int setup_vector(void **state) {
    W_Vector *vector = W_Vector_init(1);

    if (vector == NULL) {
        return -1;
    }

    *state = vector;

    return 0;
}

static int teardown_vector(void **state) {
    W_Vector *vector = *state;

    W_Vector_free(vector);

    return 0;
}

/**********************************************************************************************************************\
 * fim_db_exec_simple_wquery() tests
\**********************************************************************************************************************/
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

/**********************************************************************************************************************\
 * fim_db_init() tests
\**********************************************************************************************************************/
static int test_teardown_fim_db_init(void **state) {
    fdb_t *fim_db = (fdb_t *)*state;
    free(fim_db);
    return 0;
}

void test_fim_db_init_failed_file_creation(void **state) {
    fdb_t *fim_db;

    wraps_fim_db_clean();

    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

#ifdef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database '.\\fim.db': ERROR MESSAGE");
#else
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database './fim.db': ERROR MESSAGE");
#endif

    will_return(__wrap_sqlite3_close_v2, 0);

    fim_db = fim_db_init(syscheck.database_store);

    assert_null(fim_db);
}

void test_fim_db_init_failed_file_creation_prepare(void **state) {
    fdb_t *fim_db;
    wraps_fim_db_clean();

    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_any(__wrap__merror, formatted_msg);

    will_return(__wrap_sqlite3_close_v2, 0);

    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_file_creation_step(void **state) {
    fdb_t *fim_db;
    wraps_fim_db_clean();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_any(__wrap__merror, formatted_msg);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_close_v2, 0);
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_file_creation_chmod(void **state) {
    fdb_t *fim_db;
    errno = 0;

    wraps_fim_db_clean();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_close_v2, 0);
#ifndef TEST_WINAGENT
    expect_string(__wrap_chmod, path, "./fim.db");
#else
    expect_string(__wrap_chmod, path, ".\\fim.db");
#endif
    will_return(__wrap_chmod, -1);
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object './fim.db' due to [(0)-(Success)].");
#else
    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object '.\\fim.db' due to [(0)-(Success)].");
#endif
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_open_db(void **state) {
    wraps_fim_db_clean();
    expect_fim_db_create_file_success();
#ifndef TEST_WINAGENT
    expect_string(__wrap_sqlite3_open_v2, filename, "./fim.db");
#else
    expect_string(__wrap_sqlite3_open_v2, filename, ".\\fim.db");
#endif
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);
    fdb_t *fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_cache(void **state) {
    wraps_fim_db_clean();
    expect_fim_db_create_file_success();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg,
                  "Error preparing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?);': REASON GOES HERE");
#else
    expect_string(__wrap__merror, formatted_msg,
                  "Error preparing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#endif
    fdb_t *fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_cache_memory(void **state) {
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_MEMORY_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, 0);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg,
                  "Error preparing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?);': REASON GOES HERE");
#else
    expect_string(__wrap__merror, formatted_msg,
                  "Error preparing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#endif
    will_return(__wrap_sqlite3_close_v2, 0);
    fdb_t *fim_db;
    syscheck.database_store = 1;
    fim_db = fim_db_init(syscheck.database_store);
    syscheck.database_store = 0;
    assert_null(fim_db);
}

void test_fim_db_init_failed_execution(void **state) {
    fdb_t *fim_db;
    wraps_fim_db_clean();
    expect_fim_db_create_file_success();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF; PRAGMA foreign_keys = ON;");
    will_return(__wrap_sqlite3_exec, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "SQL error turning off synchronous mode: ERROR_MESSAGE");
    // fim_db_finalize_stmt()
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_finalize, SQLITE_OK);
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_failed_simple_query(void **state) {
    wraps_fim_db_clean();
    expect_fim_db_create_file_success();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF; PRAGMA foreign_keys = ON;");
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
    fdb_t *fim_db;
    fim_db = fim_db_init(syscheck.database_store);
    assert_null(fim_db);
}

void test_fim_db_init_success(void **state) {
    fdb_t *fim_db;
    wraps_fim_db_clean();
    expect_fim_db_create_file_success();
    expect_string(__wrap_sqlite3_open_v2, filename, FIM_DB_DISK_PATH);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    wraps_fim_db_cache();
    expect_string(__wrap_sqlite3_exec, sql, "PRAGMA synchronous = OFF; PRAGMA foreign_keys = ON;");
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
    expect_fim_db_exec_simple_wquery("BEGIN;");
    fim_db = fim_db_init(syscheck.database_store);
    assert_non_null(fim_db);
    *state = fim_db;
}

/**********************************************************************************************************************\
 * fim_db_clean() tests
\**********************************************************************************************************************/
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
    for (i = 1; i <= FIMDB_RM_MAX_LOOP; i++) {
        expect_any(__wrap__mdebug2, formatted_msg);
        expect_function_call(__wrap_usleep);
    }
#else
    for (i = 1; i <= FIMDB_RM_MAX_LOOP; i++) {
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

/**********************************************************************************************************************\
 * fim_db_get_path_range() tests
\**********************************************************************************************************************/
void test_fim_db_get_path_range_fail_to_create_temporary_file(void **state) {
    fdb_t fim_sql;
    fim_tmp_file *file = NULL;

    expect_fim_db_create_temp_file_fail(FIM_DB_DISK);

    int ret = fim_db_get_path_range(&fim_sql, FIM_TYPE_FILE, "start", "stop", &file, FIM_DB_DISK);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_get_path_range_query_failed(void **state) {
    fdb_t fim_sql = { .transaction.last_commit = 192837465, .transaction.interval = 20 };
    fim_tmp_file *file = NULL;
    const char *start = "start", *top = "top";

    expect_fim_db_create_temp_file_success(FIM_DB_DISK);

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_range(start, top, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

#ifndef TEST_WINAGENT
    expect_fim_db_clean_file((FILE *)1, FIM_DB_DISK);
#else
    expect_fim_db_clean_file((FILE *)1, FIM_DB_DISK);
#endif

    int ret = fim_db_get_path_range(&fim_sql, FIM_TYPE_FILE, start, top, &file, FIM_DB_DISK);

    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_get_path_range_no_elements_in_range(void **state) {
    fdb_t fim_sql = { .transaction.last_commit = 192837465, .transaction.interval = 20 };
    fim_tmp_file *file = NULL;
    const char *start = "start", *top = "top";

    expect_fim_db_create_temp_file_success(FIM_DB_DISK);

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_range(start, top, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

#ifndef TEST_WINAGENT
    expect_fim_db_clean_file((FILE *)1, FIM_DB_DISK);
#else
    expect_fim_db_clean_file((FILE *)1, FIM_DB_DISK);
#endif

    int ret = fim_db_get_path_range(&fim_sql, FIM_TYPE_FILE, start, top, &file, FIM_DB_DISK);

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_get_path_range_success(void **state) {
    fdb_t fim_sql = { .transaction.last_commit = 192837465, .transaction.interval = 20 };
    fim_tmp_file *file = NULL;
    const char *start = "start", *top = "top";
#ifndef TEST_WINAGENT
    const char *path = "/some/random/path";
    char *expected_str = "00000000000000000000000000000018/some/random/path\n";
#else
    const char *path = "c:\\some\\random\\path";
    char *expected_str = "00000000000000000000000000000020c:\\some\\random\\path\n";
#endif

    expect_fim_db_create_temp_file_success(FIM_DB_DISK);

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_range(start, top, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_string(path);
    expect_fim_db_callback_save_string((FILE *)1, path, expected_str, FIM_DB_DISK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    int ret = fim_db_get_path_range(&fim_sql, FIM_TYPE_FILE, start, top, &file, FIM_DB_DISK);

    *state = file;

    assert_int_equal(ret, FIMDB_OK);
    assert_non_null(file);
    assert_int_equal(file->elements, 1);
}

/**********************************************************************************************************************\
 * fim_db_get_data_checksum() tests
\**********************************************************************************************************************/
void test_fim_db_get_data_checksum_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_fim_db_check_transaction();

    int ret = fim_db_get_data_checksum(test_data->fim_sql, FIM_TYPE_FILE, NULL);

    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_get_data_checksum_success(void **state) {
    test_fim_db_insert_data *test_data = *state;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_string("0123456789abcdef0123456789abcdef01234567");

    expect_string(__wrap_EVP_DigestUpdate, data, "0123456789abcdef0123456789abcdef01234567");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE); // Ending the loop at fim_db_process_get_query()

    expect_fim_db_check_transaction();

    int ret = fim_db_get_data_checksum(test_data->fim_sql, FIM_TYPE_FILE, NULL);

    assert_int_equal(ret, FIMDB_OK);
}

/**********************************************************************************************************************\
 * fim_db_check_transaction() tests
\**********************************************************************************************************************/
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
    expect_fim_db_check_transaction();
    const time_t commit_time = test_data->fim_sql->transaction.last_commit;
    fim_db_check_transaction(test_data->fim_sql);
    assert_int_not_equal(commit_time, test_data->fim_sql->transaction.last_commit);
}

/**********************************************************************************************************************\
 * fim_db_cache() tests
\**********************************************************************************************************************/
void test_fim_db_cache_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg,
                  "Error preparing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?);': REASON GOES HERE");
#else
    expect_string(__wrap__merror, formatted_msg,
                  "Error preparing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?, ?, ?);': REASON GOES HERE");
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

/**********************************************************************************************************************\
 * fim_db_close() tests
\**********************************************************************************************************************/
void test_fim_db_close_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_fim_db_check_transaction();
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return(__wrap_sqlite3_finalize, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "REASON GOES HERE");
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg,
                  "Error finalizing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?);': REASON GOES HERE");
#else
    expect_string(__wrap__merror, formatted_msg,
                  "Error finalizing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?, ?, ?);': REASON GOES HERE");
#endif
    will_return(__wrap_sqlite3_close_v2, SQLITE_BUSY);
    fim_db_close(test_data->fim_sql);
}

void test_fim_db_close_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_fim_db_check_transaction();
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_always(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_close_v2, SQLITE_OK);
    fim_db_close(test_data->fim_sql);
}

/**********************************************************************************************************************\
 * fim_db_finalize_stmt() tests
\**********************************************************************************************************************/
void test_fim_db_finalize_stmt_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    int index;
    for (index = 0; index < FIMDB_STMT_SIZE; index++) {
        // Test failure in every index
        if (index > 0) {
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

/**********************************************************************************************************************\
 * fim_db_force_commit() tests
\**********************************************************************************************************************/
void test_fim_db_force_commit_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_string(__wrap_sqlite3_exec, sql, "END;");
    will_return(__wrap_sqlite3_exec, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "Error executing simple query 'END;': ERROR_MESSAGE");
    fim_db_force_commit(test_data->fim_sql);
    // If commit fails last_commit should still be one
    assert_int_equal(1, test_data->fim_sql->transaction.last_commit);
}

void test_fim_db_force_commit_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_fim_db_check_transaction();
    fim_db_force_commit(test_data->fim_sql);
    // If commit succeded last_comit time should be updated
    assert_int_not_equal(1, test_data->fim_sql->transaction.last_commit);
}

/**********************************************************************************************************************\
 * fim_db_clean_stmt() tests
\**********************************************************************************************************************/
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
    expect_string(__wrap__merror, formatted_msg,
                  "Error preparing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?);': ERROR");
#else
    expect_string(__wrap__merror, formatted_msg,
                  "Error preparing statement 'INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, "
                  "user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, "
                  "?, ?, ?, ?, ?, ?);': ERROR");
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

/**********************************************************************************************************************\
 * fim_db_get_checksum_range() tests
\**********************************************************************************************************************/
static void fim_db_get_checksum_range_null_ctx_left(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_right = (EVP_MD_CTX *)234567;
    char *lower_half_path, *higher_half_path;
    int retval;

    retval = fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 1, NULL, ctx_right, &lower_half_path,
                                       &higher_half_path);

    assert_int_equal(retval, FIMDB_ERR);
}

static void fim_db_get_checksum_range_null_ctx_right(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_left = (EVP_MD_CTX *)123456;
    char *lower_half_path, *higher_half_path;
    int retval;

    retval = fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 1, ctx_left, NULL, &lower_half_path,
                                       &higher_half_path);

    assert_int_equal(retval, FIMDB_ERR);
}

static void fim_db_get_checksum_range_null_path_lower_half(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_left = (EVP_MD_CTX *)123456, *ctx_right = (EVP_MD_CTX *)234567;
    char *higher_half_path = NULL;
    int retval;

    retval =
    fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 1, ctx_left, ctx_right, NULL, &higher_half_path);

    assert_int_equal(retval, FIMDB_ERR);
}

static void fim_db_get_checksum_range_null_path_upper_half(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_left = (EVP_MD_CTX *)123456, *ctx_right = (EVP_MD_CTX *)234567;
    char *lower_half_path = NULL;
    int retval;

    retval =
    fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 1, ctx_left, ctx_right, &lower_half_path, NULL);

    assert_int_equal(retval, FIMDB_ERR);
}

static void fim_db_get_checksum_range_fail_step_on_first_half(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_left = (EVP_MD_CTX *)123456, *ctx_right = (EVP_MD_CTX *)234567;
    char *lower_half_path = NULL, *higher_half_path = NULL;
    int retval;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_range(start, top, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg,
                  "Step error getting path range, first half 'start start' 'top top' (i:0): ERROR MESSAGE");

    retval = fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 2, ctx_left, ctx_right, &lower_half_path,
                                       &higher_half_path);
    assert_int_equal(retval, FIMDB_ERR);
}

static void fim_db_get_checksum_range_fail_to_decode_string_array_on_first_half(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_left = (EVP_MD_CTX *)123456, *ctx_right = (EVP_MD_CTX *)234567;
    char *lower_half_path = NULL, *higher_half_path = NULL;
    int retval;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_range(start, top, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_string_array(-1, NULL);

    expect_string(__wrap__merror, formatted_msg, "Failed to decode checksum range query");

    retval = fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 2, ctx_left, ctx_right, &lower_half_path,
                                       &higher_half_path);
    assert_int_equal(retval, FIMDB_ERR);
}

static void fim_db_get_checksum_range_fail_step_on_second_half(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_left = (EVP_MD_CTX *)123456, *ctx_right = (EVP_MD_CTX *)234567;
    char *lower_half_path = NULL, *higher_half_path = NULL;
    const char *array[] = { "/some/path", "0123456789ABCDEF0123456789ABCDEF01234567", NULL };
    int retval;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_range(start, top, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_string_array(2, array);

    expect_string(__wrap_EVP_DigestUpdate, data, "0123456789ABCDEF0123456789ABCDEF01234567");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg,
                  "Step error getting path range, second half 'start start' 'top top' (i:1): ERROR MESSAGE");

    retval = fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 2, ctx_left, ctx_right, &lower_half_path,
                                       &higher_half_path);
    assert_int_equal(retval, FIMDB_ERR);
}

static void fim_db_get_checksum_range_fail_to_decode_string_array_on_second_half(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_left = (EVP_MD_CTX *)123456, *ctx_right = (EVP_MD_CTX *)234567;
    char *lower_half_path = NULL, *higher_half_path = NULL;
    const char *array[] = { "/some/path", "0123456789ABCDEF0123456789ABCDEF01234567", NULL };
    int retval;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_range(start, top, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_string_array(2, array);

    expect_string(__wrap_EVP_DigestUpdate, data, "0123456789ABCDEF0123456789ABCDEF01234567");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_string_array(-1, NULL);

    expect_string(__wrap__merror, formatted_msg, "Failed to decode checksum range query");

    retval = fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 2, ctx_left, ctx_right, &lower_half_path,
                                       &higher_half_path);
    assert_int_equal(retval, FIMDB_ERR);
}

static void fim_db_get_checksum_range_success(void **state) {
    fdb_t fim_sql;
    const char *start = "start";
    const char *top = "top";
    EVP_MD_CTX *ctx_left = (EVP_MD_CTX *)123456, *ctx_right = (EVP_MD_CTX *)234567;
    char *lower_half_path = NULL, *higher_half_path = NULL;
    const char *lower_array[] = { "/some/path", "0123456789ABCDEF0123456789ABCDEF01234567", NULL };
    const char *higher_array[] = { "/some/other/path", "123456789ABCDEF0123456789ABCDEF012345678", NULL };
    int retval;
    char **strarray;

    strarray = calloc(3, sizeof(char *));

    if (strarray == NULL) {
        fail();
    }

    *state = strarray;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_range(start, top, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_string_array(2, lower_array);

    expect_string(__wrap_EVP_DigestUpdate, data, "0123456789ABCDEF0123456789ABCDEF01234567");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_string_array(2, higher_array);

    expect_string(__wrap_EVP_DigestUpdate, data, "123456789ABCDEF0123456789ABCDEF012345678");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);

    retval = fim_db_get_checksum_range(&fim_sql, FIM_TYPE_FILE, start, top, 2, ctx_left, ctx_right, &lower_half_path,
                                       &higher_half_path);

    strarray[0] = lower_half_path;
    strarray[1] = higher_half_path;

    assert_int_equal(retval, FIMDB_OK);
}

/**********************************************************************************************************************\
 * fim_db_get_count_range() tests
\**********************************************************************************************************************/
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

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "Some SQLite error");

    expect_string(__wrap__merror, formatted_msg,
                  "Step error getting count range 'start begin' 'top top': Some SQLite error");

    ret = fim_db_get_count_range(test_data->fim_sql, FIM_TYPE_FILE, "begin", "top", &count);

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

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 15);

    ret = fim_db_get_count_range(test_data->fim_sql, FIM_TYPE_FILE, "begin", "top", &count);

    assert_int_equal(ret, FIMDB_OK);
    assert_int_equal(count, 15);
}

/**********************************************************************************************************************\
 * fim_db_process_get_query() tests
\**********************************************************************************************************************/
void test_fim_db_process_get_query_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_decode_full_row();

    expect_function_call(callback);

    expect_fim_db_check_transaction();

    ret = fim_db_process_get_query(test_data->fim_sql, 0, 0, callback, FIM_DB_DISK, NULL);

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_process_get_query_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_fim_db_check_transaction();

    ret = fim_db_process_get_query(test_data->fim_sql, 0, 0, callback, FIM_DB_DISK, NULL);

    assert_int_equal(ret, FIMDB_ERR);
}

/**********************************************************************************************************************\
 * fim_db_callback_save_path() tests
\**********************************************************************************************************************/
void test_fim_db_callback_save_path_null(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return(__wrap_wstr_escape_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error escaping '/test/path'");

    fim_db_callback_save_path(test_data->fim_sql, test_data->entry, syscheck.database_store, test_data->tmp_file);

    assert_int_equal(test_data->tmp_file->elements, 0);
}

void test_fim_db_callback_save_path_disk(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE *)2345;

    will_return(__wrap_wstr_escape_json, strdup("/test/path"));

#ifndef TEST_WINAGENT
    expect_value(__wrap_fprintf, __stream, 2345);
    expect_string(__wrap_fprintf, formatted_msg, "00000000000000000000000000000011/test/path\n");
    will_return(__wrap_fprintf, 43);
#else
    expect_value(wrap_fprintf, __stream, 2345);
    expect_string(wrap_fprintf, formatted_msg, "00000000000000000000000000000011/test/path\n");
    will_return(wrap_fprintf, 43);
#endif

    fim_db_callback_save_path(test_data->fim_sql, test_data->entry, syscheck.database_store, test_data->tmp_file);
    assert_int_equal(test_data->tmp_file->elements, 1);
}

#ifdef TEST_WINAGENT
void test_fim_db_callback_save_path_disk_registry(void **state) {
    fdb_t fim_sql;
    fim_registry_key key = { .arch = ARCH_64BIT, .path = "HKEY_LOCAL_MACHINE\\some\\random\\key" };
    fim_entry entry = { .type = FIM_TYPE_REGISTRY, .registry_entry.key = &key };
    fim_tmp_file file = { .fd = (FILE *)2345, .elements = 0 };

    will_return(__wrap_wstr_escape_json, strdup("HKEY_LOCAL_MACHINE\\\\some\\\\random\\\\key"));

    expect_value(wrap_fprintf, __stream, 2345);
    expect_string(wrap_fprintf, formatted_msg,
                  "000000000000000000000000000000401 HKEY_LOCAL_MACHINE\\\\some\\\\random\\\\key\n");
    will_return(wrap_fprintf, 72);

    fim_db_callback_save_path(&fim_sql, &entry, FIM_DB_DISK, &file);
    assert_int_equal(file.elements, 1);
}
#endif

void test_fim_db_callback_save_path_disk_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE *)2345;

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

    expect_string(__wrap__merror, formatted_msg, "Can't save entry: /test/path Success");

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

/**********************************************************************************************************************\
 * fim_db_callback_calculate_checksum() tests
\**********************************************************************************************************************/
void test_fim_db_callback_calculate_checksum(void **state) {
    fdb_t fim_sql;
    EVP_MD_CTX *ctx = (EVP_MD_CTX *)123456;

    // Mock EVP_DigestUpdate()
    expect_string(__wrap_EVP_DigestUpdate, data, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);

    fim_db_callback_calculate_checksum(&fim_sql, "07f05add1049244e7e71ad0f54f24d8094cd8f8b", FIM_DB_DISK, ctx);
}

/**********************************************************************************************************************\
 * fim_db_create_temp_file() tests
\**********************************************************************************************************************/
void test_fim_db_create_temp_file_disk(void **state) {

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, ".\\tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "./tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 1);

#ifdef TEST_WINAGENT
    expect_string(__wrap_remove, filename, ".\\tmp_19283746523452345");
#else
    expect_string(__wrap_remove, filename, "./tmp_19283746523452345");
#endif
    will_return(__wrap_remove, 1);

    fim_tmp_file *ret = fim_db_create_temp_file(FIM_DB_DISK);
    *state = ret;

    assert_non_null(ret);
    assert_non_null(ret->fd);
#ifndef TEST_WINAGENT
    assert_string_equal(ret->path, "./tmp_19283746523452345");
#else
    assert_string_equal(ret->path, ".\\tmp_19283746523452345");
#endif
}

void test_fim_db_create_temp_file_disk_error(void **state) {

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, ".\\tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "./tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg,
                  "Failed to create temporal storage '.\\tmp_19283746523452345': Success (0)");
#else
    expect_string(__wrap__merror, formatted_msg,
                  "Failed to create temporal storage './tmp_19283746523452345': Success (0)");
#endif

    fim_tmp_file *ret = fim_db_create_temp_file(FIM_DB_DISK);

    assert_null(ret);
}

void test_fim_db_create_temp_file_memory(void **state) {
    fim_tmp_file *ret = fim_db_create_temp_file(FIM_DB_MEMORY);
    *state = ret;

    assert_non_null(ret);
    assert_non_null(ret->list);
    assert_non_null(ret->list->vector);
    assert_int_equal(ret->list->size, 100);
    assert_null(ret->path);
}

/**********************************************************************************************************************\
 * fim_db_clean_file() tests
\**********************************************************************************************************************/
void test_fim_db_clean_file_disk() {
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->path = calloc(PATH_MAX, sizeof(char));
    sprintf(file->path, "test");

    expect_value(__wrap_fclose, _File, file->fd);
    will_return(__wrap_fclose, 1);

    fim_db_clean_file(&file, FIM_DB_DISK);

    assert_null(file);
}

void test_fim_db_clean_file_disk_error() {
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->path = calloc(PATH_MAX, sizeof(char));
    sprintf(file->path, "test");

    expect_value(__wrap_fclose, _File, file->fd);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap_remove, filename, file->path);
    will_return(__wrap_remove, -1);

    expect_string(__wrap__merror, formatted_msg, "Failed to remove 'test': No such file or directory (2)");

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

/**********************************************************************************************************************\
 * fim_db_multiple_row_query()
\**********************************************************************************************************************/
static void test_fim_db_multiple_row_query_null_decode_function(void **state) {
    fdb_t fim_sql;
    int retval;

    retval = fim_db_multiple_row_query(&fim_sql, 1, NULL, free_row, FIM_DB_CALLBACK_TYPE(callback), FIM_DB_DISK, NULL);

    assert_int_equal(retval, FIMDB_ERR);
}

static void test_fim_db_multiple_row_query_null_callback_function(void **state) {
    fdb_t fim_sql;
    int retval;

    retval = fim_db_multiple_row_query(&fim_sql, 1, decode, free_row, NULL, FIM_DB_DISK, NULL);

    assert_int_equal(retval, FIMDB_ERR);
}

static void test_fim_db_multiple_row_query_null_free_function(void **state) {
    fdb_t fim_sql;
    int retval;

    retval = fim_db_multiple_row_query(&fim_sql, 1, decode, NULL, FIM_DB_CALLBACK_TYPE(callback), FIM_DB_DISK, NULL);

    assert_int_equal(retval, FIMDB_ERR);
}

static void test_fim_db_multiple_row_query_fail_to_step(void **state) {
    fdb_t fim_sql = { .transaction.last_commit = 192837445, .transaction.interval = 20 };
    int retval;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_fim_db_check_transaction();

    retval =
    fim_db_multiple_row_query(&fim_sql, 1, decode, free_row, FIM_DB_CALLBACK_TYPE(callback), FIM_DB_DISK, NULL);

    assert_int_equal(retval, FIMDB_ERR);
}

static void test_fim_db_multiple_row_query_no_data_returned(void **state) {
    fdb_t fim_sql = { .transaction.last_commit = 192837445, .transaction.interval = 20 };
    int retval;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_check_transaction();

    retval =
    fim_db_multiple_row_query(&fim_sql, 1, decode, free_row, FIM_DB_CALLBACK_TYPE(callback), FIM_DB_DISK, NULL);

    assert_int_equal(retval, FIMDB_OK);
}

static void test_fim_db_multiple_row_query_fail_to_decode(void **state) {
    fdb_t fim_sql = { .transaction.last_commit = 192837445, .transaction.interval = 20 };
    int retval;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_function_call(decode);
    will_return(decode, NULL);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_check_transaction();

    retval =
    fim_db_multiple_row_query(&fim_sql, 1, decode, free_row, FIM_DB_CALLBACK_TYPE(callback), FIM_DB_DISK, NULL);

    assert_int_equal(retval, FIMDB_OK);
}

static void test_fim_db_multiple_row_query_success(void **state) {
    fdb_t fim_sql = { .transaction.last_commit = 192837445, .transaction.interval = 20 };
    int data;
    int retval;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_function_call(decode);
    will_return(decode, &data);

    expect_function_call(callback);

    expect_function_call(free_row);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_check_transaction();

    retval =
    fim_db_multiple_row_query(&fim_sql, 1, decode, free_row, FIM_DB_CALLBACK_TYPE(callback), FIM_DB_DISK, NULL);

    assert_int_equal(retval, FIMDB_OK);
}

/**********************************************************************************************************************\
 * fim_db_callback_save_string()
\**********************************************************************************************************************/

static void test_fim_db_callback_save_string_null_input_string(void **state) {
    fdb_t fim_sql;
    fim_tmp_file file;

    fim_db_callback_save_string(&fim_sql, NULL, FIM_DB_DISK, &file);
}

static void test_fim_db_callback_save_string_fail_to_escape_string(void **state) {
    fdb_t fim_sql;
    fim_tmp_file file;
    char *str = "test string";

    will_return(__wrap_wstr_escape_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error escaping 'test string'");

    fim_db_callback_save_string(&fim_sql, str, FIM_DB_DISK, &file);
}

static void test_fim_db_callback_save_string_disk_fail_to_print(void **state) {
    fdb_t fim_sql;
    fim_tmp_file file = { .fd = (FILE *)1234 };
    char *str = "test string";
    char *escaped_string = strdup("test string");

    if (escaped_string == NULL) {
        fail_msg("%s:%d - %s: Failed to duplicate string", __FILE__, __LINE__, __func__);
    }

    *state = escaped_string;

    will_return(__wrap_wstr_escape_json, escaped_string);

#ifndef TEST_WINAGENT
    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "00000000000000000000000000000012test string\n");
    will_return(__wrap_fprintf, -1);
#else
    expect_value(wrap_fprintf, __stream, 1234);
    expect_string(wrap_fprintf, formatted_msg, "00000000000000000000000000000012test string\n");
    will_return(wrap_fprintf, -1);
#endif

    expect_string(__wrap__merror, formatted_msg, "Can't save entry: test string Success");

    fim_db_callback_save_string(&fim_sql, str, FIM_DB_DISK, &file);

    *state = NULL;
}

static void test_fim_db_callback_save_string_disk_success(void **state) {
    fdb_t fim_sql;
    fim_tmp_file file = { .fd = (FILE *)1234, .elements = 0 };
    char *str = "test string";
    char *escaped_string = strdup("test string");

    if (escaped_string == NULL) {
        fail_msg("%s:%d - %s: Failed to duplicate string", __FILE__, __LINE__, __func__);
    }

    *state = escaped_string;

    will_return(__wrap_wstr_escape_json, escaped_string);

#ifndef TEST_WINAGENT
    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "00000000000000000000000000000012test string\n");
    will_return(__wrap_fprintf, 44);
#else
    expect_value(wrap_fprintf, __stream, 1234);
    expect_string(wrap_fprintf, formatted_msg, "00000000000000000000000000000012test string\n");
    will_return(wrap_fprintf, 44);
#endif

    fim_db_callback_save_string(&fim_sql, str, FIM_DB_DISK, &file);

    *state = NULL;

    assert_int_equal(file.elements, 1);
}

static void test_fim_db_callback_save_string_memory(void **state) {
    fdb_t fim_sql;
    fim_tmp_file file = { .list = *state, .elements = 0 };
    char *str = "test string";
    char *escaped_string = strdup("test string");

    if (escaped_string == NULL) {
        fail_msg("%s:%d - %s: Failed to duplicate string", __FILE__, __LINE__, __func__);
    }

    will_return(__wrap_wstr_escape_json, escaped_string);

    fim_db_callback_save_string(&fim_sql, str, FIM_DB_MEMORY, &file);

    assert_int_equal(file.elements, 1);
    assert_string_equal(W_Vector_get(file.list, 0), "test string");
}

/**********************************************************************************************************************\
 * fim_db_get_count()
\**********************************************************************************************************************/
static void test_fim_db_get_count_invalid_index(void **state) {
    fdb_t fim_sql;
    int retval;

    retval = fim_db_get_count(&fim_sql, -1);

    assert_int_equal(retval, FIMDB_ERR);
}

static void test_fim_db_get_count_fail_to_query_count(void **state) {
    fdb_t fim_sql;
    int retval;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    retval = fim_db_get_count(&fim_sql, FIMDB_STMT_GET_COUNT_PATH);

    assert_int_equal(retval, FIMDB_ERR);
}

static void test_fim_db_get_count_success(void **state) {
    fdb_t fim_sql;
    int retval;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    retval = fim_db_get_count(&fim_sql, FIMDB_STMT_GET_COUNT_PATH);

    assert_int_equal(retval, 1);
}

/**********************************************************************************************************************\
 * fim_db_get_last_path()
\**********************************************************************************************************************/
static void test_fim_db_get_last_path_fail_to_step_query(void **state) {
    fdb_t fim_sql;
    char *path = NULL;
    int retval;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "SQLITE error");

    expect_string(__wrap__merror, formatted_msg, "Step error getting row string: SQLITE error");

    retval = fim_db_get_last_path(&fim_sql, FIM_TYPE_FILE, &path);

    assert_int_equal(retval, FIMDB_ERR);
    assert_null(path);
}

static void test_fim_db_get_last_path_query_returns_no_string(void **state) {
    fdb_t fim_sql;
    char *path = NULL;
    int retval;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    retval = fim_db_get_last_path(&fim_sql, FIM_TYPE_FILE, &path);

    assert_int_equal(retval, FIMDB_OK);
    assert_null(path);
}

static void test_fim_db_get_last_path_success(void **state) {
    fdb_t fim_sql;
    char *path = NULL;
    int retval;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "/some/random/path");

    retval = fim_db_get_last_path(&fim_sql, FIM_TYPE_FILE, &path);

    *state = path;

    assert_int_equal(retval, FIMDB_OK);
    assert_string_equal(path, "/some/random/path");
}

/**********************************************************************************************************************\
 * fim_db_read_line_from_file()
\**********************************************************************************************************************/
static void test_fim_db_read_line_from_file_already_done_reading(void **state) {
    fim_tmp_file file = { .elements = 3 };
    char *line = NULL;
    int retval;

    retval = fim_db_read_line_from_file(&file, FIM_DB_DISK, 3, &line);

    assert_int_equal(retval, 1);
    assert_null(line);
}

static void test_fim_db_read_line_from_file_disk_fail_to_fseek(void **state) {
    fim_tmp_file file = { .elements = 3, .path = "/some/random/path" };
    char warning_message[OS_SIZE_256];
    char *line = NULL;
    int retval;

    will_return(__wrap_fseek, -1);

    snprintf(warning_message, OS_SIZE_256, FIM_DB_TEMPORARY_FILE_POSITION, 0, "Success");
    expect_string(__wrap__mwarn, formatted_msg, warning_message);

    retval = fim_db_read_line_from_file(&file, FIM_DB_DISK, 0, &line);

    assert_int_equal(retval, -1);
    assert_null(line);
}

static void test_fim_db_read_line_from_file_disk_fail_to_read_line_length(void **state) {
    fim_tmp_file file = { .elements = 3, .path = "/some/random/path", .fd = (FILE *)2345 };
    char *line = NULL;
    int retval;

    will_return(__wrap_fseek, 0);

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, (FILE *)2345);
    will_return(__wrap_fgets, NULL);
#else
    expect_value(wrap_fgets, __stream, (FILE *)2345);
    will_return(wrap_fgets, NULL);
#endif

    expect_string(__wrap__mdebug1, formatted_msg, FIM_UNABLE_TO_READ_TEMP_FILE);

    retval = fim_db_read_line_from_file(&file, FIM_DB_DISK, 0, &line);

    assert_int_equal(retval, -1);
    assert_null(line);
}

static void test_fim_db_read_line_from_file_disk_fail_to_read_line(void **state) {
    fim_tmp_file file = { .elements = 3, .path = "/some/random/path", .fd = (FILE *)2345 };
    char *line = NULL;
    int retval;

    will_return(__wrap_fseek, 0);

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, (FILE *)2345);
    will_return(__wrap_fgets, "00000000000000000000000000000018");
#else
    expect_value(wrap_fgets, __stream, (FILE *)2345);
    will_return(wrap_fgets, "00000000000000000000000000000018");
#endif

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, (FILE *)2345);
    will_return(__wrap_fgets, NULL);
#else
    expect_value(wrap_fgets, __stream, (FILE *)2345);
    will_return(wrap_fgets, NULL);
#endif

    expect_string(__wrap__mdebug1, formatted_msg, FIM_UNABLE_TO_READ_TEMP_FILE);

    retval = fim_db_read_line_from_file(&file, FIM_DB_DISK, 0, &line);

    assert_int_equal(retval, -1);
    assert_null(line);
}

static void test_fim_db_read_line_from_file_disk_read_corrupt_line(void **state) {
    fim_tmp_file file = { .elements = 3, .path = "/some/random/path", .fd = (FILE *)2345 };
    char *line = NULL;
    int retval;

    will_return(__wrap_fseek, 0);

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, (FILE *)2345);
    will_return(__wrap_fgets, "00000000000000000000000000000014");
#else
    expect_value(wrap_fgets, __stream, (FILE *)2345);
    will_return(wrap_fgets, "00000000000000000000000000000014");
#endif

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, (FILE *)2345);
    will_return(__wrap_fgets, "/corrupt/path");
#else
    expect_value(wrap_fgets, __stream, (FILE *)2345);
    will_return(wrap_fgets, "/corrupt/path");
#endif

    expect_string(__wrap__merror, formatted_msg,
                  "Temporary path file '/some/random/path' is corrupt: missing line end.");

    retval = fim_db_read_line_from_file(&file, FIM_DB_DISK, 0, &line);

    assert_int_equal(retval, -1);
    assert_null(line);
}

static void test_fim_db_read_line_from_file_disk_line_read(void **state) {
    fim_tmp_file file = { .elements = 3, .path = "/some/random/path", .fd = (FILE *)2345 };
    char *line = NULL;
    int retval;

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, (FILE *)2345);
    will_return(__wrap_fgets, "00000000000000000000000000000011");
#else
    expect_value(wrap_fgets, __stream, (FILE *)2345);
    will_return(wrap_fgets, "00000000000000000000000000000011");
#endif

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, (FILE *)2345);
    will_return(__wrap_fgets, "/read/path\n");
#else
    expect_value(wrap_fgets, __stream, (FILE *)2345);
    will_return(wrap_fgets, "/read/path\n");
#endif

    retval = fim_db_read_line_from_file(&file, FIM_DB_DISK, 1, &line);

    *state = line;

    assert_int_equal(retval, 0);
    assert_string_equal(line, "/read/path");
}

static void test_fim_db_read_line_from_file_memory_attempt_to_read_out_of_bounds(void **state) {
    W_Vector list = { .size = 3 };
    fim_tmp_file file = { .elements = 3, .list = &list };
    char *line = NULL;
    int retval;

    expect_string(__wrap__merror, formatted_msg, "Attempted to retrieve an out of bounds line.");

    retval = fim_db_read_line_from_file(&file, FIM_DB_MEMORY, 4, &line);

    assert_int_equal(retval, 1);
    assert_null(line);
}

static void test_fim_db_read_line_from_file_memory_line_read(void **state) {
    char *vector[] = { "/some/random/path", NULL };
    W_Vector list = { .size = 10, .vector = vector, .used = 1 };
    fim_tmp_file file = { .elements = 1, .list = &list };
    char *line = NULL;
    int retval;

    retval = fim_db_read_line_from_file(&file, FIM_DB_MEMORY, 0, &line);

    assert_int_equal(retval, 0);
    assert_string_equal(line, "/some/random/path");
}

/**********************************************************************************************************************\
 * fim_db_process_read_file()
\**********************************************************************************************************************/
static void test_fim_db_process_read_file_fail_to_read_line(void **state) {
    fdb_t fim_sql;
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    int retval;

    if (file == NULL) {
        fail();
    }

    file->elements = 1;
    file->path = strdup("/some/random/path");
    file->fd = (FILE *)1234;

    expect_fim_db_read_line_from_file_fail();
    expect_fim_db_clean_file(file->fd, FIM_DB_DISK);

    retval = fim_db_process_read_file(&fim_sql, file, FIM_TYPE_FILE, &syscheck.fim_entry_mutex, read_file_callback,
                                      FIM_DB_DISK, NULL, NULL, NULL);

    assert_int_equal(retval, FIMDB_ERR);
}

static void test_fim_db_process_read_file_success(void **state) {
    fdb_t fim_sql;
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    fim_file_data data = DEFAULT_FILE_DATA;
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = "/media/some/path", .file_entry.data = &data };
    int retval;

    if (file == NULL) {
        fail();
    }

    file->elements = 1;
    file->path = strdup("/some/random/path");
    file->fd = (FILE *)1234;

    expect_fim_db_read_line_from_file_disk_success(0, file->fd, "/media/some/path\n",
                                                   "00000000000000000000000000000017");

    expect_fim_db_get_path_success("/media/some/path", &entry);

    expect_fim_db_clean_file(file->fd, FIM_DB_DISK);

    retval = fim_db_process_read_file(&fim_sql, file, FIM_TYPE_FILE, &syscheck.fim_entry_mutex, read_file_callback,
                                      FIM_DB_DISK, NULL, NULL, NULL);

    assert_int_equal(retval, FIMDB_OK);
}

#ifdef TEST_WINAGENT
void test_fim_db_process_read_file_fail_to_read_registry_entry(void **state) {
    fdb_t fim_sql;
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    int retval;

    if (file == NULL) {
        fail();
    }

    file->elements = 1;
    file->path = strdup("/some/random/path");
    file->fd = (FILE *)1234;

    expect_fim_db_read_line_from_file_disk_success(0, file->fd, "HKEY_WRONG_FORMAT\\\n",
                                                   "00000000000000000000000000000019");

    expect_string(__wrap__merror, formatted_msg, "Temporary path file '/some/random/path' is corrupt: Wrong format");

    expect_fim_db_clean_file(file->fd, FIM_DB_DISK);

    retval = fim_db_process_read_file(&fim_sql, file, FIM_TYPE_REGISTRY, &syscheck.fim_entry_mutex, read_file_callback,
                                      FIM_DB_DISK, NULL, NULL, NULL);

    assert_int_equal(retval, FIMDB_OK);
}

void test_fim_db_process_read_registry_entry_fail_to_get_key(void **state) {
    fdb_t fim_sql;
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    fim_registry_key data = DEFAULT_REGISTRY_KEY;
    int retval;

    if (file == NULL) {
        fail();
    }

    file->elements = 1;
    file->path = strdup("/some/random/path");
    file->fd = (FILE *)1234;

    expect_fim_db_read_line_from_file_disk_success(0, file->fd, "1 HKEY_LOCAL_MACHINE\\software\\some:\\key\n",
                                                   "00000000000000000000000000000040");

    expect_fim_db_get_registry_key_fail(&data);

    expect_fim_db_clean_file(file->fd, FIM_DB_DISK);

    retval = fim_db_process_read_file(&fim_sql, file, FIM_TYPE_REGISTRY, &syscheck.fim_entry_mutex, read_file_callback,
                                      FIM_DB_DISK, NULL, NULL, NULL);

    assert_int_equal(retval, FIMDB_OK);
}

void test_fim_db_process_read_registry_entry_success(void **state) {
    fdb_t fim_sql;
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    fim_registry_key data = DEFAULT_REGISTRY_KEY;
    int retval;

    if (file == NULL) {
        fail();
    }

    file->elements = 1;
    file->path = strdup("/some/random/path");
    file->fd = (FILE *)1234;

    expect_fim_db_read_line_from_file_disk_success(0, file->fd, "1 HKEY_LOCAL_MACHINE\\software\\some:\\key\n",
                                                   "00000000000000000000000000000040");

    expect_fim_db_get_registry_key(&data);

    expect_fim_db_clean_file(file->fd, FIM_DB_DISK);

    retval = fim_db_process_read_file(&fim_sql, file, FIM_TYPE_REGISTRY, &syscheck.fim_entry_mutex, read_file_callback,
                                      FIM_DB_DISK, NULL, NULL, NULL);

    assert_int_equal(retval, FIMDB_OK);
}

/**********************************************************************************************************************\
 * fim_db_get_count_entries()
\**********************************************************************************************************************/
static void test_fim_db_get_count_entries_query_failed(void **state) {
    fdb_t fim_sql;
    int retval;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "SQLITE some error");

    expect_string(__wrap__merror, formatted_msg, "Step error getting count entry path: SQLITE some error");

    retval = fim_db_get_count_entries(&fim_sql);

    assert_int_equal(retval, FIMDB_ERR);
}

static void test_fim_db_get_count_entries_success(void **state) {
    fdb_t fim_sql;
    int retval;

    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    retval = fim_db_get_count_entries(&fim_sql);

    assert_int_equal(retval, 1);
}

/**********************************************************************************************************************\
 * fim_db_get_entry_from_sync_msg()
\**********************************************************************************************************************/
void test_fim_db_get_entry_from_sync_msg_get_file(void **state) {
    fdb_t fim_sql;
    fim_file_data data = DEFAULT_FILE_DATA;
    fim_entry base_entry = { .type = FIM_TYPE_FILE,
                             .file_entry.path = "c:\\windows\\system32\\windowspowershell\\v1.0",
                             .file_entry.data = &data };
    fim_entry *entry;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_path("c:\\windows\\system32\\windowspowershell\\v1.0");

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_full_row_from_entry(&base_entry);

    entry = fim_db_get_entry_from_sync_msg(&fim_sql, FIM_TYPE_FILE, "c:\\windows\\system32\\windowspowershell\\v1.0");

    *state = entry;

    assert_non_null(entry);
    assert_int_equal(entry->type, FIM_TYPE_FILE);
    assert_string_equal(entry->file_entry.path, "c:\\windows\\system32\\windowspowershell\\v1.0");
    assert_non_null(entry->file_entry.data);
}

void test_fim_db_get_entry_from_sync_msg_get_registry_key(void **state) {
    fdb_t fim_sql;
    fim_registry_key data = DEFAULT_REGISTRY_KEY;
    fim_entry *entry;

    expect_fim_db_get_registry_key(&data);

    entry =
    fim_db_get_entry_from_sync_msg(&fim_sql, FIM_TYPE_REGISTRY, "[x64] HKEY_LOCAL_MACHINE\\software\\some::\\key");

    *state = entry;

    assert_non_null(entry);
    assert_int_equal(entry->type, FIM_TYPE_REGISTRY);
    assert_non_null(entry->registry_entry.key);
    assert_string_equal(entry->registry_entry.key->path, "HKEY_LOCAL_MACHINE\\software\\some:\\key");
    assert_int_equal(entry->registry_entry.key->arch, ARCH_64BIT);
    assert_null(entry->registry_entry.value);
}

void test_fim_db_get_entry_from_sync_msg_get_registry_value_fail_to_get_data(void **state) {
    fdb_t fim_sql;
    fim_registry_key key_data = DEFAULT_REGISTRY_KEY;
    fim_entry *entry;

    expect_fim_db_get_registry_key(&key_data);
    expect_fim_db_get_registry_data_fail("some:value", key_data.id);

    entry = fim_db_get_entry_from_sync_msg(&fim_sql, FIM_TYPE_REGISTRY,
                                           "[x64] HKEY_LOCAL_MACHINE\\software\\some::\\key:some::value");

    *state = entry;

    assert_null(entry);
}

void test_fim_db_get_entry_from_sync_msg_get_registry_value_success(void **state) {
    fdb_t fim_sql;
    fim_registry_key key_data = DEFAULT_REGISTRY_KEY;
    fim_registry_value_data value_data = DEFAULT_REGISTRY_VALUE;
    fim_entry *entry;

    expect_fim_db_get_registry_key(&key_data);
    expect_fim_db_get_registry_data("some:value", key_data.id, &value_data);

    entry = fim_db_get_entry_from_sync_msg(&fim_sql, FIM_TYPE_REGISTRY,
                                           "[x64] HKEY_LOCAL_MACHINE\\software\\some::\\key:some::value");

    *state = entry;

    assert_non_null(entry);
    assert_int_equal(entry->type, FIM_TYPE_REGISTRY);
    assert_non_null(entry->registry_entry.key);
    assert_string_equal(entry->registry_entry.key->path, "HKEY_LOCAL_MACHINE\\software\\some:\\key");
    assert_int_equal(entry->registry_entry.key->arch, ARCH_64BIT);
    assert_non_null(entry->registry_entry.value);
    assert_string_equal(entry->registry_entry.value->name, "some:value");
    assert_int_equal(entry->registry_entry.value->id, entry->registry_entry.key->id);
}

#endif

/**********************************************************************************************************************\
 * main()
\**********************************************************************************************************************/
int main(void) {
    const struct CMUnitTest tests[] = {

        // fim_db_exec_simple_wquery
        cmocka_unit_test_setup_teardown(test_fim_db_exec_simple_wquery_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_exec_simple_wquery_success, test_fim_db_setup,
                                        test_fim_db_teardown),
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
        // fim_db_get_path_range
        cmocka_unit_test(test_fim_db_get_path_range_fail_to_create_temporary_file),
        cmocka_unit_test(test_fim_db_get_path_range_query_failed),
        cmocka_unit_test(test_fim_db_get_path_range_no_elements_in_range),
        cmocka_unit_test_teardown(test_fim_db_get_path_range_success, teardown_fim_tmp_file_disk),
        // fim_db_get_data_checksum
        cmocka_unit_test_setup_teardown(test_fim_db_get_data_checksum_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_data_checksum_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_check_transaction
        cmocka_unit_test_setup_teardown(test_fim_db_check_transaction_last_commit_is_0, test_fim_db_setup,
                                        test_fim_db_teardown),
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
        cmocka_unit_test_setup_teardown(test_fim_db_clean_stmt_reset_and_prepare_failed, test_fim_db_setup,
                                        test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_clean_stmt_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_checksum_range
        cmocka_unit_test(fim_db_get_checksum_range_null_ctx_left),
        cmocka_unit_test(fim_db_get_checksum_range_null_ctx_right),
        cmocka_unit_test(fim_db_get_checksum_range_null_path_lower_half),
        cmocka_unit_test(fim_db_get_checksum_range_null_path_upper_half),
        cmocka_unit_test(fim_db_get_checksum_range_fail_step_on_first_half),
        cmocka_unit_test(fim_db_get_checksum_range_fail_to_decode_string_array_on_first_half),
        cmocka_unit_test(fim_db_get_checksum_range_fail_step_on_second_half),
        cmocka_unit_test(fim_db_get_checksum_range_fail_to_decode_string_array_on_second_half),
        cmocka_unit_test_teardown(fim_db_get_checksum_range_success, teardown_string_array),
        // fim_db_get_count_range
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_range_error_stepping, test_fim_db_setup,
                                        test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_range_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_process_get_query
        cmocka_unit_test_setup_teardown(test_fim_db_process_get_query_success, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_process_get_query_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_callback_save_path
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_path_null, test_fim_tmp_file_setup_disk,
                                        test_fim_tmp_file_teardown_disk),
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_path_disk, test_fim_tmp_file_setup_disk,
                                        test_fim_tmp_file_teardown_disk),
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_path_disk_error, test_fim_tmp_file_setup_disk,
                                        test_fim_tmp_file_teardown_disk),
#ifdef TEST_WINAGENT
        cmocka_unit_test(test_fim_db_callback_save_path_disk_registry),
#endif
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_path_memory, test_fim_tmp_file_setup_memory,
                                        test_fim_tmp_file_teardown_memory),
        // fim_db_callback_calculate_checksum
        cmocka_unit_test(test_fim_db_callback_calculate_checksum),
        // fim_db_create_temp_file
        cmocka_unit_test_teardown(test_fim_db_create_temp_file_disk, teardown_fim_tmp_file_disk),
        cmocka_unit_test(test_fim_db_create_temp_file_disk_error),
        cmocka_unit_test_teardown(test_fim_db_create_temp_file_memory, teardown_fim_tmp_file_memory),
        // fim_db_clean_file
        cmocka_unit_test(test_fim_db_clean_file_disk),
        // cmocka_unit_test(test_fim_db_clean_file_disk_error),
        cmocka_unit_test(test_fim_db_clean_file_memory),
        // fim_db_multiple_row_query
        cmocka_unit_test(test_fim_db_multiple_row_query_null_decode_function),
        cmocka_unit_test(test_fim_db_multiple_row_query_null_callback_function),
        cmocka_unit_test(test_fim_db_multiple_row_query_null_free_function),
        cmocka_unit_test(test_fim_db_multiple_row_query_fail_to_step),
        cmocka_unit_test(test_fim_db_multiple_row_query_no_data_returned),
        cmocka_unit_test(test_fim_db_multiple_row_query_fail_to_decode),
        cmocka_unit_test(test_fim_db_multiple_row_query_success),
        // fim_db_callback_save_string
        cmocka_unit_test(test_fim_db_callback_save_string_null_input_string),
        cmocka_unit_test(test_fim_db_callback_save_string_fail_to_escape_string),
        cmocka_unit_test_teardown(test_fim_db_callback_save_string_disk_fail_to_print, teardown_string),
        cmocka_unit_test_teardown(test_fim_db_callback_save_string_disk_success, teardown_string),
        cmocka_unit_test_setup_teardown(test_fim_db_callback_save_string_memory, setup_vector, teardown_vector),
        // fim_db_get_count
        cmocka_unit_test(test_fim_db_get_count_invalid_index),
        cmocka_unit_test(test_fim_db_get_count_fail_to_query_count),
        cmocka_unit_test(test_fim_db_get_count_success),
        // fim_db_get_last_path
        cmocka_unit_test(test_fim_db_get_last_path_fail_to_step_query),
        cmocka_unit_test(test_fim_db_get_last_path_query_returns_no_string),
        cmocka_unit_test_teardown(test_fim_db_get_last_path_success, teardown_string),
        // fim_db_read_line_from_file
        cmocka_unit_test(test_fim_db_read_line_from_file_already_done_reading),
        cmocka_unit_test(test_fim_db_read_line_from_file_disk_fail_to_fseek),
        cmocka_unit_test(test_fim_db_read_line_from_file_disk_fail_to_read_line_length),
        cmocka_unit_test(test_fim_db_read_line_from_file_disk_fail_to_read_line),
        cmocka_unit_test(test_fim_db_read_line_from_file_disk_read_corrupt_line),
        cmocka_unit_test_teardown(test_fim_db_read_line_from_file_disk_line_read, teardown_string),
        cmocka_unit_test(test_fim_db_read_line_from_file_memory_attempt_to_read_out_of_bounds),
        cmocka_unit_test(test_fim_db_read_line_from_file_memory_line_read),
        // fim_db_process_read_file
        cmocka_unit_test(test_fim_db_process_read_file_fail_to_read_line),
        cmocka_unit_test(test_fim_db_process_read_file_success),
#ifdef TEST_WINAGENT
        cmocka_unit_test(test_fim_db_process_read_file_fail_to_read_registry_entry),
        cmocka_unit_test(test_fim_db_process_read_registry_entry_fail_to_get_key),
        cmocka_unit_test(test_fim_db_process_read_registry_entry_success),
        // fim_db_get_count_entries
        cmocka_unit_test(test_fim_db_get_count_entries_query_failed),
        cmocka_unit_test(test_fim_db_get_count_entries_success),
        // fim_db_get_entry_from_sync_msg
        cmocka_unit_test_teardown(test_fim_db_get_entry_from_sync_msg_get_file, teardown_fim_entry),
        cmocka_unit_test_teardown(test_fim_db_get_entry_from_sync_msg_get_registry_key, teardown_fim_entry),
        cmocka_unit_test_teardown(test_fim_db_get_entry_from_sync_msg_get_registry_value_fail_to_get_data, teardown_fim_entry),
        cmocka_unit_test_teardown(test_fim_db_get_entry_from_sync_msg_get_registry_value_success, teardown_fim_entry),
#endif
    };
    return cmocka_run_group_tests(tests, setup_fim_db_group, teardown_fim_db_group);
}
