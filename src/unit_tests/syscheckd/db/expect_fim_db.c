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

#include "test_fim_db.h"

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
 * Successfully wrappes a fim_db_decode_full_row() call
 * */
void expect_fim_db_decode_full_row() {
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "/some/random/path"); // path
    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, 1); // mode
    expect_value(__wrap_sqlite3_column_int, iCol, 3);
    will_return(__wrap_sqlite3_column_int, 1000000); // last_event
    expect_value(__wrap_sqlite3_column_int, iCol, 4);
    will_return(__wrap_sqlite3_column_int, 1000001); // scanned
    expect_value(__wrap_sqlite3_column_int, iCol, 5);
    will_return(__wrap_sqlite3_column_int, 1000002); // options
    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, "checksum"); // checksum
    expect_value(__wrap_sqlite3_column_int, iCol, 7);
    will_return(__wrap_sqlite3_column_int, 111); // dev
    expect_value(__wrap_sqlite3_column_int64, iCol, 8);
    will_return(__wrap_sqlite3_column_int64, 1024); // inode
    expect_value(__wrap_sqlite3_column_int, iCol, 9);
    will_return(__wrap_sqlite3_column_int, 4096); // size
    expect_value_count(__wrap_sqlite3_column_text, iCol, 10, 2);
    will_return_count(__wrap_sqlite3_column_text, "perm", 2); // perm
    expect_value_count(__wrap_sqlite3_column_text, iCol, 11, 2);
    will_return_count(__wrap_sqlite3_column_text, "attributes", 2); // attributes
    expect_value_count(__wrap_sqlite3_column_text, iCol, 12, 2);
    will_return_count(__wrap_sqlite3_column_text, "uid", 2); // uid
    expect_value_count(__wrap_sqlite3_column_text, iCol, 13, 2);
    will_return_count(__wrap_sqlite3_column_text, "gid", 2); // gid
    expect_value_count(__wrap_sqlite3_column_text, iCol, 14, 2);
    will_return_count(__wrap_sqlite3_column_text, "user_name", 2); // user_name
    expect_value_count(__wrap_sqlite3_column_text, iCol, 15, 2);
    will_return_count(__wrap_sqlite3_column_text, "group_name", 2); // group_name
    expect_value(__wrap_sqlite3_column_text, iCol, 16);
    will_return(__wrap_sqlite3_column_text, "hash_md5"); // hash_md5
    expect_value(__wrap_sqlite3_column_text, iCol, 17);
    will_return(__wrap_sqlite3_column_text, "hash_sha1"); // hash_sha1
    expect_value(__wrap_sqlite3_column_text, iCol, 18);
    will_return(__wrap_sqlite3_column_text, "hash_sha256"); // hash_sha256
    expect_value(__wrap_sqlite3_column_int, iCol, 19);
    will_return(__wrap_sqlite3_column_int, 12345678); // mtime
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

/**********************************************************************************************************************\
 * Setup and teardown functions
\**********************************************************************************************************************/
int setup_group(void **state) {
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

int teardown_group(void **state) {
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
