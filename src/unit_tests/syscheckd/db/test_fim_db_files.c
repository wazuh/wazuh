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
#include "wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "wrappers/libc/stdio_wrappers.h"
#include "wrappers/posix/stat_wrappers.h"
#include "wrappers/posix/unistd_wrappers.h"
#include "wrappers/wazuh/shared/file_op_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/os_utils_wrappers.h"
#include "wrappers/wazuh/shared/string_op_wrappers.h"
#include "wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "wrappers/wazuh/shared/integrity_op_wrappers.h"
#include "wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "wrappers/wazuh/syscheckd/run_check_wrappers.h"
#include "wrappers/wazuh/syscheckd/fim_diff_changes_wrappers.h"

#include "db/fim_db_files.h"
#include "config/syscheck-config.h"

#include "test_fim_db.h"

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
 * Setup and teardown functions
\**********************************************************************************************************************/
static int teardown_fim_db(void **state) {
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

static int teardown_fim_db_entry(void **state) {
    teardown_fim_db(state);
    fim_entry *entry = state[1];
    if (entry) {
        free_entry(entry);
    }
    return 0;
}

#ifndef TEST_WINAGENT
static int test_fim_db_paths_teardown(void **state) {
    teardown_fim_db(state);
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
#endif

/**********************************************************************************************************************\
 * fim_db_insert_data()
\**********************************************************************************************************************/
void test_fim_db_insert_data_no_rowid_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int row_id = 0;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_insert_data(3);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error inserting data row_id '0': ERROR MESSAGE");

    int ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->file_entry.data, &row_id);

    assert_int_equal(row_id, 0);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_insert_data_no_rowid_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int row_id = 0;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_insert_data(3);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_last_insert_rowid, 1);

    int ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->file_entry.data, &row_id);

    assert_int_equal(row_id, 1);
    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_insert_data_rowid_error(void **state) {
    test_fim_db_insert_data *test_data = *state;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_update_data(3);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error updating data row_id '1': ERROR MESSAGE");
    int ret;
    int row_id = 1;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->file_entry.data, &row_id);
    assert_int_equal(row_id, 1);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_insert_data_rowid_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;
    int row_id = 1;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_update_data(3);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->file_entry.data, &row_id);

    assert_int_equal(row_id, 1);
    assert_int_equal(ret, FIMDB_OK);
}

/**********************************************************************************************************************\
 * fim_db_insert_path()
\**********************************************************************************************************************/
void test_fim_db_insert_path_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_replace_path(2);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "Step error replacing path '/test/path': ERROR MESSAGE");

    ret = fim_db_insert_path(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, 1);

    assert_int_equal(ret, FIMDB_ERR);
}


void test_fim_db_insert_path_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_replace_path(2);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    ret = fim_db_insert_path(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, 1);

    assert_int_equal(ret, FIMDB_OK);
}

/**********************************************************************************************************************\
 * fim_db_insert()
\**********************************************************************************************************************/
void test_fim_db_insert_db_full(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    expect_fim_db_get_count_entries(50000);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Couldn't insert '/test/path' entry into DB. The DB is full, please check your configuration.");

    syscheck.database = test_data->fim_sql;

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, NULL);

    syscheck.database = NULL;

    assert_int_equal(ret, FIMDB_FULL);
}

#ifndef TEST_WINAGENT
void test_fim_db_insert_fail_to_remove_existing_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_path("/test/path");

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_delete_data_id(1);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg,"ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "Step error deleting data: ERROR MESSAGE");

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data,
                        test_data->saved);

    assert_int_equal(ret, FIMDB_ERR);
}
#endif

void test_fim_db_insert_update_inode_with_single_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_path("/test/path");

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

#ifndef TEST_WINAGENT
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_delete_data_id(1);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_force_commit();

    expect_fim_db_clean_stmt();

    expect_fim_db_bind_get_inode();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
#endif

    // Wrap functions for fim_db_insert_data() & fim_db_insert_path()
    expect_fim_db_insert_data_success(0);
    expect_fim_db_insert_path_success();

    expect_fim_db_check_transaction();

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data,
                        test_data->saved);

    assert_int_equal(ret, FIMDB_OK);   // Success
    assert_int_equal(test_data->fim_sql->transaction.last_commit, 192837465);
}

void test_fim_db_insert_update_inode_with_multiple_entries(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_path("/test/path");

#ifndef TEST_WINAGENT
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 2);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_clean_stmt();

    expect_fim_db_bind_get_inode();
#endif

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    // Wrap functions for fim_db_insert_data() & fim_db_insert_path()
    expect_fim_db_insert_data_success(1);
    expect_fim_db_insert_path_success();

    expect_fim_db_check_transaction();

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data,
                        test_data->saved);

    assert_int_equal(ret, FIMDB_OK);   // Success
    assert_int_equal(test_data->fim_sql->transaction.last_commit, 192837465);
}

#ifndef TEST_WINAGENT
void test_fim_db_insert_inode_id_null(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_path("/test/path");

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 0);

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_delete_data_id(0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_force_commit();

    expect_fim_db_clean_stmt();

    expect_fim_db_bind_get_inode();

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    // Wrap functions for fim_db_insert_data() & fim_db_insert_path()
    int inode_id = 0;
    expect_fim_db_insert_data_success(inode_id);
    expect_fim_db_insert_path_success();

    expect_fim_db_check_transaction();

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data,
                        test_data->saved);
    assert_int_equal(ret, FIMDB_OK); // Success
}
#endif

void test_fim_db_insert_inode_id_null_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;
    test_data->entry->file_entry.data->inode = 100;

    expect_fim_db_clean_stmt();

#ifndef TEST_WINAGENT
    expect_fim_db_bind_get_inode();
#else
    expect_fim_db_bind_path("/test/path");
#endif

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting data row: ERROR MESSAGE");

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data,
                        test_data->saved);
    assert_int_equal(ret, FIMDB_ERR);
}

/**********************************************************************************************************************\
 * fim_db_remove_path()
\**********************************************************************************************************************/
void test_fim_db_remove_path_no_entry(void **state) {
    fim_file_data data;
#ifndef TEST_WINAGENT
    char *entry_path = "/etc/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\windowspowershell\\v1.0";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }
    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 0);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 0);

    expect_fim_db_check_transaction();

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_one_entry(void **state) {
    fim_file_data data;
#ifndef TEST_WINAGENT
    char *entry_path = "/etc/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\windowspowershell\\v1.0";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_bind_delete_data_id(1);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_check_transaction();

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *)FIM_WHODATA, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_one_entry_step_fail(void **state) {
    fim_file_data data;
#ifndef TEST_WINAGENT
    char *entry_path = "/etc/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\windowspowershell\\v1.0";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_bind_delete_data_id(1);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_fim_db_check_transaction();

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *)FIM_WHODATA, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_one_entry_alert_success(void **state) {
    fim_file_data data = DEFAULT_FILE_DATA;
#ifndef TEST_WINAGENT
    char *entry_path = "/etc/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\windowspowershell\\v1.0";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };
    int alert = 1;

    syscheck.database = &fim_sql;

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_bind_delete_data_id(1);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

#ifndef TEST_WINAGENT
    expect_fim_db_get_paths_from_inode(NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "(6220): Sending delete message for file: '/etc/some/path'");
#else
    expect_string(__wrap__mdebug2, formatted_msg,
                  "(6220): Sending delete message for file: 'c:\\windows\\system32\\windowspowershell\\v1.0'");

    expect_fim_db_check_transaction();
#endif

    expect_send_syscheck_msg(NULL);

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, &alert, (void *)FIM_WHODATA, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_one_entry_alert_success_with_seechanges(void **state) {
    fim_file_data data = DEFAULT_FILE_DATA;
#ifndef TEST_WINAGENT
    char *entry_path = "/etc/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\windowspowershell\\v1.0";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };
    int alert = 1;
    struct dirent dir = { .d_name = "mock_name" };
    int config_directory = fim_configuration_directory(entry_path, "file");

    if (config_directory < 0) {
        fail();
    }

    syscheck.database = &fim_sql;

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_bind_delete_data_id(1);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

#ifndef TEST_WINAGENT
    expect_fim_db_get_paths_from_inode(NULL);
#else
    expect_fim_db_check_transaction();
#endif

    syscheck.opts[config_directory] |= CHECK_SEECHANGES;

    expect_fim_diff_delete_compress_folder(&dir);

#ifndef TEST_WINAGENT
    expect_string(__wrap__mdebug2, formatted_msg, "(6220): Sending delete message for file: '/etc/some/path'");
#else
    expect_string(__wrap__mdebug2, formatted_msg,
                  "(6220): Sending delete message for file: 'c:\\windows\\system32\\windowspowershell\\v1.0'");
#endif

    expect_send_syscheck_msg(NULL);

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, &alert, (void *)FIM_WHODATA, NULL);

    syscheck.opts[config_directory] &= ~CHECK_SEECHANGES;
    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_multiple_entry(void **state) {
    fim_file_data data = DEFAULT_FILE_DATA;
#ifndef TEST_WINAGENT
    char *entry_path = "/etc/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\windowspowershell\\v1.0";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_check_transaction();

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_multiple_entry_step_fail(void **state) {
    fim_file_data data = DEFAULT_FILE_DATA;
#ifndef TEST_WINAGENT
    char *entry_path = "/etc/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\windowspowershell\\v1.0";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_fim_db_check_transaction();

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_failed_path(void **state) {
    fim_file_data data = DEFAULT_FILE_DATA;
#ifndef TEST_WINAGENT
    char *entry_path = "/etc/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\windowspowershell\\v1.0";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    expect_fim_db_check_transaction();

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_no_configuration_file(void **state) {
    fim_file_data data = DEFAULT_FILE_DATA;
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = "/non/configured/path", .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/non/configured/path'");

    expect_string(__wrap__mdebug2, formatted_msg, "(6339): Delete event from path without configuration: '/non/configured/path'");


    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_WHODATA, NULL);
}

void test_fim_db_remove_path_no_entry_realtime_file(void **state) {
    fim_file_data data = DEFAULT_FILE_DATA;
#ifndef TEST_WINAGENT
    char *entry_path = "/media/some/path";
#else
    char *entry_path = "c:\\windows\\system32\\wbem\\some\\path";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_check_transaction();

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_REALTIME, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}

void test_fim_db_remove_path_no_entry_scheduled_file(void **state) {
    fim_file_data data = DEFAULT_FILE_DATA;
#ifndef TEST_WINAGENT
    char *entry_path = "/root/some/path";
#else
    char *entry_path = "c:\\windows\\sysnative\\drivers\\etc\\some\\path";
#endif
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = entry_path, .file_entry.data = &data };
    fdb_t fim_sql = { .transaction.last_commit = 1, .transaction.interval = 1 };

    for (int i = 0; i < 3; i++) {
        expect_fim_db_clean_stmt();
    }

    expect_fim_db_bind_path(entry_path);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);

    expect_fim_db_check_transaction();

    fim_db_remove_path(&fim_sql, &entry, &syscheck.fim_entry_mutex, NULL, (void *) FIM_SCHEDULED, NULL);

    // Last commit time should change
    assert_int_equal(fim_sql.transaction.last_commit, 192837465);
}


/*----------fim_db_get_path()------------------*/
void test_fim_db_get_path_inexistent(void **state) {
    test_fim_db_insert_data *test_data = *state;

    expect_fim_db_clean_stmt();


    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    fim_entry *ret = fim_db_get_path(test_data->fim_sql, test_data->entry->file_entry.path);
    state[1] = ret;
    assert_null(ret);
}

void test_fim_db_get_path_existent(void **state) {
    test_fim_db_insert_data *test_data = *state;

    expect_fim_db_clean_stmt();
    expect_fim_db_bind_path("/test/path");

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_full_row();

    fim_entry *ret = fim_db_get_path(test_data->fim_sql, test_data->entry->file_entry.path);

    state[1] = ret;
    assert_non_null(ret);
    assert_string_equal("/some/random/path", ret->file_entry.path);
    assert_int_equal(1, ret->file_entry.data->mode);
    assert_int_equal(1000000, ret->file_entry.data->last_event);
    assert_int_equal(1000001, ret->file_entry.data->scanned);
    assert_int_equal(1000002, ret->file_entry.data->options);
    assert_string_equal("checksum", ret->file_entry.data->checksum);
    assert_int_equal(111, ret->file_entry.data->dev);
    assert_int_equal(1024, ret->file_entry.data->inode);
    assert_int_equal(4096, ret->file_entry.data->size);
    assert_string_equal("perm", ret->file_entry.data->perm);
    assert_string_equal("attributes", ret->file_entry.data->attributes);
    assert_string_equal("uid", ret->file_entry.data->uid);
    assert_string_equal("gid", ret->file_entry.data->gid);
    assert_string_equal("user_name", ret->file_entry.data->user_name);
    assert_string_equal("group_name", ret->file_entry.data->group_name);
    assert_string_equal("hash_md5", ret->file_entry.data->hash_md5);
    assert_string_equal("hash_sha1", ret->file_entry.data->hash_sha1);
    assert_string_equal("hash_sha256", ret->file_entry.data->hash_sha256);
    assert_int_equal(12345678, ret->file_entry.data->mtime);
}

/*----------fim_db_set_all_unscanned()------------------*/
void test_fim_db_set_all_unscanned_failed(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_string(__wrap_sqlite3_exec, sql, "UPDATE file_entry SET scanned = 0;");
    will_return(__wrap_sqlite3_exec, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_exec, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "Error executing simple query 'UPDATE file_entry SET scanned = 0;': ERROR MESSAGE");
    expect_fim_db_check_transaction();
    int ret = fim_db_set_all_unscanned(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_set_all_unscanned_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    expect_fim_db_exec_simple_wquery("UPDATE file_entry SET scanned = 0;");
    expect_fim_db_check_transaction();
    int ret = fim_db_set_all_unscanned(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_OK);
}

/**********************************************************************************************************************\
 * fim_db_get_not_scanned()
\**********************************************************************************************************************/
void test_fim_db_get_not_scanned_failed(void **state) {

    test_fim_db_insert_data *test_data = *state;
    fim_tmp_file *file = NULL;

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, ".\\tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "./tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 0);
#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "Failed to create temporal storage './tmp_19283746523452345': Success (0)");
#else
    expect_string(__wrap__merror, formatted_msg, "Failed to create temporal storage '.\\tmp_19283746523452345': Success (0)");
#endif

    int ret = fim_db_get_not_scanned(test_data->fim_sql, &file, syscheck.database_store);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_get_not_scanned_success(void **state) {

    test_fim_db_insert_data *test_data = *state;
    fim_tmp_file *file = NULL;

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, ".\\tmp_19283746523452345");
#else
    expect_string(__wrap_wfopen, __filename, "./tmp_19283746523452345");
#endif

    expect_string(__wrap_wfopen, __modes, "w+");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    expect_fim_db_check_transaction();

#ifndef TEST_WINAGENT
    expect_string(__wrap_remove, filename, "./tmp_19283746523452345");
#else
    expect_string(__wrap_remove, filename, ".\\tmp_19283746523452345");
#endif

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    will_return(__wrap_remove, 0);

    int ret = fim_db_get_not_scanned(test_data->fim_sql, &file, syscheck.database_store);
    assert_int_equal(ret, FIMDB_OK);
}

#ifndef TEST_WINAGENT
/* fim_db_get_paths_from_inode() is only used in *nix systems */
/*----------fim_db_get_paths_from_inode()------------------*/
void test_fim_db_get_paths_from_inode_none_path(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_count(__wrap_sqlite3_reset, SQLITE_OK, 2);
    will_return_count(__wrap_sqlite3_clear_bindings, SQLITE_OK, 2);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
#ifndef TEST_WINAGENT
    expect_any_always(__wrap_sqlite3_bind_int64, index);
    expect_any_always(__wrap_sqlite3_bind_int64, value);
    will_return_always(__wrap_sqlite3_bind_int64, 0);
#endif
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    expect_fim_db_check_transaction();
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
#ifndef TEST_WINAGENT
    expect_any_always(__wrap_sqlite3_bind_int64, index);
    expect_any_always(__wrap_sqlite3_bind_int64, value);
    will_return_always(__wrap_sqlite3_bind_int64, 0);
#endif
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "Path 1");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    expect_fim_db_check_transaction();
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
#ifndef TEST_WINAGENT
    expect_any_always(__wrap_sqlite3_bind_int64, index);
    expect_any_always(__wrap_sqlite3_bind_int64, value);
    will_return_always(__wrap_sqlite3_bind_int64, 0);
#endif
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    int i;
    char buffers[5][10];
    for(i = 0; i < sizeof(buffers)/10; i++) {
        // Generate 5 paths
    will_return(__wrap_sqlite3_step, 0);
        will_return(__wrap_sqlite3_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        snprintf(buffers[i], 10, "Path %d", i + 1);
        will_return(__wrap_sqlite3_column_text, buffers[i]);
    }
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    expect_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    state[1] = paths;
    for(i = 0; i < sizeof(buffers)/10; i++) {
        snprintf(buffers[i], 10, "Path %d", i + 1);
        assert_string_equal(paths[i], buffers[i]);
    }
    assert_null(paths[5]);
}

#endif
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
#ifndef TEST_WINAGENT
    expect_any_always(__wrap_sqlite3_bind_int64, index);
    expect_any_always(__wrap_sqlite3_bind_int64, value);
    will_return_always(__wrap_sqlite3_bind_int64, 0);
#endif
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    int i;
    char buffers[5][10];
    for(i = 0; i < sizeof(buffers)/10; i++) {
        // Generate 5 paths
    will_return(__wrap_sqlite3_step, 0);
        will_return(__wrap_sqlite3_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        snprintf(buffers[i], 10, "Path %d", i + 1);
        will_return(__wrap_sqlite3_column_text, buffers[i]);
    }
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_string(__wrap__minfo, formatted_msg, "The count returned is smaller than the actual elements. This shouldn't happen.");
    expect_fim_db_check_transaction();
    char **paths;
    paths = fim_db_get_paths_from_inode(test_data->fim_sql, 1, 1);
    state[1] = paths;
    for(i = 0; i < sizeof(buffers)/10; i++) {
        snprintf(buffers[i], 10, "Path %d", i + 1);
        assert_string_equal(paths[i], buffers[i]);
    }
    assert_null(paths[5]);
}

/*----------fim_db_get_count_file_data()------------------*/
void test_fim_db_get_count_file_data(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    int ret = fim_db_get_count_file_data(test_data->fim_sql);

    assert_int_equal(ret, 1);
}

void test_fim_db_get_count_file_data_error(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting count entry data: ERROR MESSAGE");

    int ret = fim_db_get_count_file_data(test_data->fim_sql);

    assert_int_equal(ret, -1);
}

/*----------fim_db_get_count_file_entry()------------------*/
void test_fim_db_get_count_file_entry(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    int ret = fim_db_get_count_file_entry(test_data->fim_sql);

    assert_int_equal(ret, 1);
}

void test_fim_db_get_count_file_entry_error(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting count entry path: ERROR MESSAGE");

    int ret = fim_db_get_count_file_entry(test_data->fim_sql);

    assert_int_equal(ret, -1);
}

/*----------fim_db_decode_full_row()------------*/
void test_fim_db_decode_full_row(void **state) {
    test_fim_db_insert_data *test_data;
    test_data = calloc(1, sizeof(test_fim_db_insert_data));
    test_data->fim_sql = calloc(1, sizeof(fdb_t));
    expect_fim_db_decode_full_row();
    test_data->entry = fim_db_decode_full_row(test_data->fim_sql->stmt[FIMDB_STMT_GET_PATH]);
    *state = test_data;
    assert_non_null(test_data->entry);
    assert_string_equal(test_data->entry->file_entry.path, "/some/random/path");
    assert_int_equal(test_data->entry->file_entry.data->mode, 1);
    assert_int_equal(test_data->entry->file_entry.data->last_event, 1000000);
    assert_int_equal(test_data->entry->file_entry.data->scanned, 1000001);
    assert_int_equal(test_data->entry->file_entry.data->options, 1000002);
    assert_string_equal(test_data->entry->file_entry.data->checksum, "checksum");
    assert_int_equal(test_data->entry->file_entry.data->dev, 111);
    assert_int_equal(test_data->entry->file_entry.data->inode, 1024);
    assert_int_equal(test_data->entry->file_entry.data->size, 4096);
    assert_string_equal(test_data->entry->file_entry.data->perm, "perm");
    assert_string_equal(test_data->entry->file_entry.data->attributes, "attributes");
    assert_string_equal(test_data->entry->file_entry.data->uid, "uid");
    assert_string_equal(test_data->entry->file_entry.data->gid, "gid");
    assert_string_equal(test_data->entry->file_entry.data->user_name, "user_name");
    assert_string_equal(test_data->entry->file_entry.data->group_name, "group_name");
    assert_string_equal(test_data->entry->file_entry.data->hash_md5, "hash_md5");
    assert_string_equal(test_data->entry->file_entry.data->hash_sha1, "hash_sha1");
    assert_string_equal(test_data->entry->file_entry.data->hash_sha256, "hash_sha256");
    assert_int_equal(test_data->entry->file_entry.data->mtime, 12345678);
}

/*----------fim_db_set_scanned_error()------------*/
void test_fim_db_set_scanned_error(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any(__wrap_sqlite3_bind_text, pos);
    expect_any(__wrap_sqlite3_bind_text, buffer);
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error setting scanned path '/test/path': ERROR MESSAGE");

    int ret = fim_db_set_scanned(test_data->fim_sql, test_data->entry->file_entry.path);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_set_scanned_success(void **state) {
    test_fim_db_insert_data *test_data = *state;

    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any(__wrap_sqlite3_bind_text, pos);
    expect_any(__wrap_sqlite3_bind_text, buffer);
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_fim_db_check_transaction();

    int ret = fim_db_set_scanned(test_data->fim_sql, test_data->entry->file_entry.path);
    assert_int_equal(ret, FIMDB_OK);
}

/*-----------------------------------------*/
int main(void) {
    const struct CMUnitTest tests[] = {
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
        cmocka_unit_test_setup_teardown(test_fim_db_insert_fail_to_remove_existing_entry, test_fim_db_setup,
                                        test_fim_db_teardown),
#endif
        cmocka_unit_test_setup_teardown(test_fim_db_insert_update_inode_with_single_entry, test_fim_db_setup,
                                        test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_update_inode_with_multiple_entries, test_fim_db_setup,
                                        test_fim_db_teardown),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_fim_db_insert_inode_id_null, test_fim_db_setup, test_fim_db_teardown),
#endif
        cmocka_unit_test_setup_teardown(test_fim_db_insert_inode_id_null_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_remove_path
        cmocka_unit_test(test_fim_db_remove_path_no_entry),
        cmocka_unit_test(test_fim_db_remove_path_one_entry),
        cmocka_unit_test(test_fim_db_remove_path_one_entry_step_fail),
        cmocka_unit_test(test_fim_db_remove_path_one_entry_alert_success),
        cmocka_unit_test(test_fim_db_remove_path_one_entry_alert_success_with_seechanges),
        cmocka_unit_test(test_fim_db_remove_path_multiple_entry),
        cmocka_unit_test(test_fim_db_remove_path_multiple_entry_step_fail),
        cmocka_unit_test(test_fim_db_remove_path_failed_path),
        cmocka_unit_test(test_fim_db_remove_path_no_configuration_file),
        cmocka_unit_test(test_fim_db_remove_path_no_entry_realtime_file),
        cmocka_unit_test(test_fim_db_remove_path_no_entry_scheduled_file),
        // fim_db_get_path
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_inexistent, test_fim_db_setup, teardown_fim_db_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_existent, test_fim_db_setup, teardown_fim_db_entry),
        // fim_db_set_all_unscanned
        cmocka_unit_test_setup_teardown(test_fim_db_set_all_unscanned_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_set_all_unscanned_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_not_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_get_not_scanned_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_not_scanned_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_paths_from_inode
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_none_path, test_fim_db_setup,
                                        test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_single_path, test_fim_db_setup,
                                        test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_multiple_path, test_fim_db_setup,
                                        test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_multiple_unamatched_rows, test_fim_db_setup,
                                        test_fim_db_paths_teardown),
#endif
        // fim_db_get_count_file_data
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_file_data, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_file_data_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_count_file_entry
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_file_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_file_entry_error, test_fim_db_setup,
                                        test_fim_db_teardown),
        // fim_db_decode_full_row
        cmocka_unit_test_teardown(test_fim_db_decode_full_row, test_fim_db_teardown),
        // fim_db_set_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_set_scanned_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_set_scanned_success, test_fim_db_setup, test_fim_db_teardown),
    };
    return cmocka_run_group_tests(tests, setup_fim_db_group, teardown_fim_db_group);
}
