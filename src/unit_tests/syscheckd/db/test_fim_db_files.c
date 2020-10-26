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
#include "wrappers/wazuh/syscheckd/seechanges_wrappers.h"

#include "db/fim_db_files.h"
#include "config/syscheck-config.h"

/**********************************************************************************************************************\
 * Auxiliar expect functions
\**********************************************************************************************************************/
static void expect_fim_db_insert_path_success() {
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_count(__wrap_sqlite3_bind_int, 0, 6);
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
}

static void expect_fim_db_insert_data_success(int row_id) {
    if (row_id == 0) {
        expect_any(__wrap_sqlite3_bind_int64, index);
        expect_any(__wrap_sqlite3_bind_int64, value);
        will_return(__wrap_sqlite3_bind_int64, 0);
    }

    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    will_return_count(__wrap_sqlite3_bind_int, 0, 3);
    will_return_count(__wrap_sqlite3_bind_text, 0, 9);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    if (row_id == 0) {
        will_return(__wrap_sqlite3_last_insert_rowid, 1);
    }
}

/**********************************************************************************************************************\
 * Setup and teardown functions
\**********************************************************************************************************************/
static int setup_group(void **state) {
    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    Read_Syscheck_Config("../test_syscheck2.conf");

    syscheck.database_store = 0;    // disk
    w_mutex_init(&syscheck.fim_entry_mutex, NULL);
    test_mode = 1;

#ifdef TEST_WINAGENT
    time_mock_value = 192837465;
#endif
    return 0;
}

static int teardown_group(void **state) {
    Free_Syscheck(&syscheck);
    w_mutex_destroy(&syscheck.fim_entry_mutex);
    test_mode = 0;
    return 0;
}

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

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error inserting data row_id '0': ERROR MESSAGE");

    int row_id = 0;
    int ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->file_entry.data, &row_id);

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

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_last_insert_rowid, 1);

    int row_id = 0;
    int ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->file_entry.data, &row_id);

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
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, 0);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    int ret;
    int row_id = 1;
    ret = fim_db_insert_data(test_data->fim_sql, test_data->entry->file_entry.data, &row_id);
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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error replacing path '/test/path': ERROR MESSAGE");
    int ret;
    ret = fim_db_insert_path(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, 1);
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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    int ret;
    ret = fim_db_insert_path(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, 1);
    assert_int_equal(ret, FIMDB_OK);
}

/*-----------------------------------------*/
/*----------fim_db_insert()----------------*/

void test_fim_db_insert_db_full(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;

    // Inside fim_db_get_count_file_entry
    {
        // Inside fim_db_clean_stmt
        {
            will_return(__wrap_sqlite3_reset, SQLITE_OK);
            will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);
        }
    will_return(__wrap_sqlite3_step, 0);
        will_return(__wrap_sqlite3_step, SQLITE_ROW);

        expect_value(__wrap_sqlite3_column_int, iCol, 0);
        will_return(__wrap_sqlite3_column_int, 50000);
    }

    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't insert '/test/path' entry into DB. The DB is full, please check your configuration.");

    syscheck.database = test_data->fim_sql;
    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, NULL);
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

    will_return(__wrap_sqlite3_step, 0);
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

    will_return(__wrap_sqlite3_step, 0);
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

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);

    // Wrap functions for fim_db_insert_data() & fim_db_insert_path()
    int inode_id = 1;
    expect_fim_db_insert_data_success(inode_id);
    expect_fim_db_insert_path_success();

    wraps_fim_db_check_transaction();

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, test_data->saved);
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

    will_return(__wrap_sqlite3_step, 0);
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

    will_return(__wrap_sqlite3_step, 0);
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

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    // Wrap functions for fim_db_insert_data() & fim_db_insert_path()
    int inode_id = 0;
    expect_fim_db_insert_data_success(inode_id);
    expect_fim_db_insert_path_success();

    wraps_fim_db_check_transaction();

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, test_data->saved);
    assert_int_equal(ret, FIMDB_OK);   // Success
}

void test_fim_db_insert_inode_id_null_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    int ret;
    test_data->entry->file_entry.data->inode = 100;

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

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Step error getting data row: ERROR MESSAGE");

    ret = fim_db_insert(test_data->fim_sql, test_data->entry->file_entry.path, test_data->entry->file_entry.data, test_data->saved);
    assert_int_equal(ret, FIMDB_ERR);
}

#endif

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
    will_return(__wrap_sqlite3_step, 0);
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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

#ifndef TEST_WINAGENT
    expect_string(__wrap_delete_target_file, path, test_data->entry->file_entry.path);
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
                                                strlen(test_data->entry->file_entry.path) + 1));

    snprintf(diff_path, (strlen("/var/ossec/queue/diff/local") + strlen(test_data->entry->file_entry.path) + 1), "%s%s",
                "/var/ossec/queue/diff/local", test_data->entry->file_entry.path);

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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
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
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
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
    will_return(__wrap_sqlite3_step, 0);
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
    will_return(__wrap_sqlite3_step, 0);
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
    will_return(__wrap_sqlite3_step, 0);
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


/*----------fim_db_get_path()------------------*/
void test_fim_db_get_path_inexistent(void **state) {
    test_fim_db_insert_data *test_data = *state;
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
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
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();
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
    wraps_fim_db_check_transaction();
    int ret = fim_db_set_all_unscanned(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_ERR);
}

void test_fim_db_set_all_unscanned_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    wraps_fim_db_exec_simple_wquery("UPDATE file_entry SET scanned = 0;");
    wraps_fim_db_check_transaction();
    int ret = fim_db_set_all_unscanned(test_data->fim_sql);
    assert_int_equal(ret, FIMDB_OK);
}

/*----------fim_db_get_not_scanned()------------------*/
void test_fim_db_get_not_scanned_failed(void **state) {

    test_fim_db_insert_data *test_data = *state;
    fim_tmp_file *file = NULL;

    will_return(__wrap_os_random, 2345);

#ifdef TEST_WINAGENT
    expect_string(__wrap_fopen, path, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_fopen, path, "/var/ossec/tmp/tmp_19283746523452345");
#endif

    expect_string(__wrap_fopen, mode, "w+");
    will_return(__wrap_fopen, 0);
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
    expect_string(__wrap_fopen, path, "tmp/tmp_19283746523452345");
#else
    expect_string(__wrap_fopen, path, "/var/ossec/tmp/tmp_19283746523452345");
#endif

    expect_string(__wrap_fopen, mode, "w+");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_sqlite3_step, 0);
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
    will_return(__wrap_sqlite3_step, 0);
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

/*----------fim_db_delete_range()------------------*/
void test_fim_db_delete_range_success(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    int ret;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value(wrap_fgets, __stream, (FILE*)2345);
    will_return(wrap_fgets, "/tmp/file\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)2345);
    will_return(__wrap_fgets, "/tmp/file\n");
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();

    // Inside fim_db_remove_path (callback)
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 5);
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
    wraps_fim_db_check_transaction();

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap_remove, filename, "/tmp/file");
    will_return(__wrap_remove, 0);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex, syscheck.database_store);

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_delete_range_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    int ret;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value(wrap_fgets, __stream, (FILE*)2345);
    will_return(wrap_fgets, "/tmp/file\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)2345);
    will_return(__wrap_fgets, "/tmp/file\n");
#endif
    will_return_always(__wrap_sqlite3_reset, SQLITE_OK);
    will_return_always(__wrap_sqlite3_clear_bindings, SQLITE_OK);
    expect_any_always(__wrap_sqlite3_bind_text, pos);
    expect_any_always(__wrap_sqlite3_bind_text, buffer);
    will_return_always(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    wraps_fim_db_decode_full_row();

    // Inside fim_db_remove_path (callback)
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    wraps_fim_db_check_transaction();

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap_remove, filename, "/tmp/file");
    will_return(__wrap_remove, 0);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex, syscheck.database_store);

    assert_int_equal(ret, FIMDB_OK);
}

void test_fim_db_delete_range_path_error(void **state) {
    test_fim_db_insert_data *test_data = *state;
    test_data->tmp_file->fd = (FILE*)2345;
    int ret;

    will_return(__wrap_fseek, 0);
#ifdef WIN32
    expect_value(wrap_fgets, __stream, (FILE*)2345);
    will_return(wrap_fgets, "\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)2345);
    will_return(__wrap_fgets, "\n");
#endif

    expect_string(__wrap__merror, formatted_msg, "Temporary path file '/tmp/file' is corrupt: missing line end.");

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap_remove, filename, "/tmp/file");
    will_return(__wrap_remove, 0);

    ret = fim_db_delete_range(test_data->fim_sql, test_data->tmp_file, &syscheck.fim_entry_mutex, syscheck.database_store);

    assert_int_equal(ret, FIMDB_OK);
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
    wraps_fim_db_decode_full_row();
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

    wraps_fim_db_check_transaction();

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
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_inexistent, test_fim_db_setup, teardown_fim_db_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_get_path_existent, test_fim_db_setup, teardown_fim_db_entry),
        // fim_db_set_all_unscanned
        cmocka_unit_test_setup_teardown(test_fim_db_set_all_unscanned_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_set_all_unscanned_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_not_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_get_not_scanned_failed, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_not_scanned_success, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_paths_from_inode
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_none_path, test_fim_db_setup, test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_single_path, test_fim_db_setup, test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_multiple_path, test_fim_db_setup, test_fim_db_paths_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_paths_from_inode_multiple_unamatched_rows, test_fim_db_setup, test_fim_db_paths_teardown),
        // fim_db_delete_range
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_success, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_error, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_delete_range_path_error, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        // fim_db_delete_not_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_delete_not_scanned, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        // fim_db_process_missing_entry
        cmocka_unit_test_setup_teardown(test_fim_db_process_missing_entry, test_fim_tmp_file_setup_disk, test_fim_db_teardown),
        // fim_db_get_count_file_data
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_file_data, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_file_data_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_get_count_file_entry
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_file_entry, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_get_count_file_entry_error, test_fim_db_setup, test_fim_db_teardown),
        // fim_db_decode_full_row
        cmocka_unit_test_teardown(test_fim_db_decode_full_row, test_fim_db_teardown),
        // fim_db_set_scanned
        cmocka_unit_test_setup_teardown(test_fim_db_set_scanned_error, test_fim_db_setup, test_fim_db_teardown),
        cmocka_unit_test_setup_teardown(test_fim_db_set_scanned_success, test_fim_db_setup, test_fim_db_teardown),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
