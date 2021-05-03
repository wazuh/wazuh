/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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

#include "test_fim_db.h"

/**********************************************************************************************************************\
 * Auxiliar constants and variables
\**********************************************************************************************************************/
const fim_file_data DEFAULT_FILE_DATA = {
    // Checksum attributes
    .size = 0,
    .perm = "rw-rw-r--",
    .attributes = NULL,
    .uid = "1000",
    .gid = "1000",
    .user_name = "root",
    .group_name = "root",
    .mtime = 123456789,
    .inode = 1,
    .hash_md5 = "0123456789abcdef0123456789abcdef",
    .hash_sha1 = "0123456789abcdef0123456789abcdef01234567",
    .hash_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",

    // Options
    .mode = FIM_REALTIME,
    .last_event = 0,
    .dev = 100,
    .scanned = 0,
    .options = (CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_INODE | CHECK_MD5SUM |
                CHECK_SHA1SUM | CHECK_SHA256SUM),
    .checksum = "0123456789abcdef0123456789abcdef01234567",
};

#ifdef TEST_WINAGENT
const fim_registry_key DEFAULT_REGISTRY_KEY = {
    .id = 1,
    .path = "HKEY_LOCAL_MACHINE\\software\\some:\\key",
    .perm = "perm",
    .uid = "",
    .gid = "",
    .user_name = "",
    .group_name = "",
    .mtime = 12345678,
    .arch = ARCH_64BIT,
    .scanned = 1,
    .last_event = 12345679,
    .checksum = "0123456789abcdef0123456789abcdef01234567"
};

const fim_registry_value_data DEFAULT_REGISTRY_VALUE = {
    .id = 1,
    .name = "some:value",
    .type = REG_SZ,
    .size = 10,
    .hash_md5 = "0123456789abcdef0123456789abcdef",
    .hash_sha1 = "0123456789abcdef0123456789abcdef01234567",
    .hash_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    .scanned = 1,
    .last_event = 123456487,
    .checksum = "0123456789abcdef0123456789abcdef01234567",
    .mode = FIM_SCHEDULED
};
#endif

/**********************************************************************************************************************\
 * Auxiliar expect functions
\**********************************************************************************************************************/
/**
 * Successfully wrappes a fim_db_check_transaction() call
 * */
void expect_fim_db_check_transaction() {
    expect_fim_db_exec_simple_wquery("END;");
    expect_string(__wrap__mdebug1, formatted_msg, "Database transaction completed.");
    expect_fim_db_exec_simple_wquery("BEGIN;");
}

/**
 * Successfully wrappes a fim_db_exec_simple_wquery() call
 * */
void expect_fim_db_exec_simple_wquery(const char *query) {
    expect_string(__wrap_sqlite3_exec, sql, query);
    will_return(__wrap_sqlite3_exec, NULL);
    will_return(__wrap_sqlite3_exec, SQLITE_OK);
}

/**
 * Successfully wrappes a fim_db_clean_stmt() call
 * */
void expect_fim_db_clean_stmt() {
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
}

void expect_fim_db_get_count_entries(int retval) {
    expect_fim_db_clean_stmt();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, retval);
}

void expect_fim_db_force_commit() {
    expect_fim_db_check_transaction();
}

void expect_fim_db_read_line_from_file_fail() {
    will_return(__wrap_fseek, -1);

    expect_any(__wrap__mwarn, formatted_msg);
}

void expect_fim_db_read_line_from_file_disk_success(int index, FILE *fd, const char *line, const char *line_length) {
    if (index == 0) {
        will_return(__wrap_fseek, 0);
    }

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, fd);
    will_return(__wrap_fgets, line_length);
#else
    expect_value(wrap_fgets, __stream, fd);
    will_return(wrap_fgets, line_length);
#endif

#ifndef TEST_WINAGENT
    expect_value(__wrap_fgets, __stream, fd);
    will_return(__wrap_fgets, line);
#else
    expect_value(wrap_fgets, __stream, fd);
    will_return(wrap_fgets, line);
#endif
}

void expect_fim_db_get_path_success(const char *path, const fim_entry *entry) {
    expect_fim_db_clean_stmt();
    expect_fim_db_bind_path(path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_full_row_from_entry(entry);
}

/**********************************************************************************************************************\
 * Setup and teardown functions
\**********************************************************************************************************************/
int setup_fim_db_group(void **state) {
    (void)state;

    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifndef TEST_SERVER
    will_return_always(__wrap_getDefine_Int, 0);
#endif

    Read_Syscheck_Config("../test_syscheck2.conf");

    syscheck.database_store = 0; // disk
    w_mutex_init(&syscheck.fim_entry_mutex, NULL);
    test_mode = 1;

#ifdef TEST_WINAGENT
    time_mock_value = 192837465;
#endif
    return 0;
}

int teardown_fim_db_group(void **state) {
    Free_Syscheck(&syscheck);
    w_mutex_destroy(&syscheck.fim_entry_mutex);
    test_mode = 0;
    return 0;
}

int test_fim_db_setup(void **state) {
    test_fim_db_insert_data *test_data;
    test_data = calloc(1, sizeof(test_fim_db_insert_data));

    test_data->fim_sql = calloc(1, sizeof(fdb_t));
    test_data->fim_sql->transaction.last_commit = 1; // Set a time diferent than 0

    test_data->entry = calloc(1, sizeof(fim_entry));
    test_data->entry->type = FIM_TYPE_FILE;

    test_data->entry->file_entry.data = calloc(1, sizeof(fim_file_data));
    test_data->entry->file_entry.data->inode = 200;
    test_data->entry->file_entry.data->dev = 100;
    test_data->entry->file_entry.path = strdup("/test/path");


    test_data->saved = calloc(1, sizeof(fim_file_data));
    test_data->saved->inode = 100;
    test_data->saved->dev = 100;

    *state = test_data;
    return 0;
}

int test_fim_db_teardown(void **state) {
    test_fim_db_insert_data *test_data = *state;
    free(test_data->entry->file_entry.path);
    free(test_data->entry->file_entry.data->perm);
    free(test_data->entry->file_entry.data->attributes);
    free(test_data->entry->file_entry.data->uid);
    free(test_data->entry->file_entry.data->gid);
    free(test_data->entry->file_entry.data->user_name);
    free(test_data->entry->file_entry.data->group_name);
    free(test_data->entry->file_entry.data);
    free(test_data->entry);
    free(test_data->fim_sql);
    free(test_data->saved);
    free(test_data);
    return 0;
}

int test_fim_tmp_file_setup_disk(void **state) {
    test_fim_db_insert_data *test_data;
    if (test_fim_db_setup((void **)&test_data) != 0) {
        return -1;
    }
    test_data->tmp_file = calloc(1, sizeof(fim_tmp_file));
    test_data->tmp_file->path = strdup("/tmp/file");
    *state = test_data;
    return 0;
}

int test_fim_tmp_file_teardown_disk(void **state) {
    test_fim_db_insert_data *test_data = *state;
    free(test_data->tmp_file->path);
    free(test_data->tmp_file);
    return test_fim_db_teardown((void **)&test_data);
}

int teardown_fim_entry(void **state) {
    free_entry((fim_entry *)*state);

    return 0;
}
