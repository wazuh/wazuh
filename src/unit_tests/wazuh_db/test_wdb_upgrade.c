/*
 * Copyright (C) 2015, Wazuh Inc.
 * September, 2020.
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
#include <string.h>
#include <stdlib.h>

#include "../wazuh_db/wdb.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_metadata_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"

extern int test_mode;

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

/* redefinitons/wrapping */

time_t __wrap_time(time_t *__timer) {
    return 1;
}

/* setup/teardown */

int setup_wdb(void **state) {
    test_mode = 1;
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("global",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    init_data->wdb->enabled = true;
    *state = init_data;
    return 0;
}

int teardown_wdb(void **state) {
    test_mode = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

/* Tests test_wdb_recreate_global */

void test_wdb_recreate_global_error_closing_wdb_struct(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    // Error closing the wdb struct
    will_return(__wrap_wdb_close, 0);
    will_return(__wrap_wdb_close, OS_INVALID);

    ret = wdb_recreate_global(data->wdb);

    assert_memory_equal(data->wdb, ret, sizeof(ret));
}

void test_wdb_recreate_global_error_creating_global_db(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    // Closing the wdb struct and removing the current database file
    will_return(__wrap_wdb_close, 1);
    will_return(__wrap_wdb_close, OS_SUCCESS);
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);

    // Error creating global.db
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db'");

    ret = wdb_recreate_global(data->wdb);

    assert_null(ret);
}

void test_wdb_recreate_global_error_opening_global_db(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    // Closing the wdb struct and removing the current database file
    will_return(__wrap_wdb_close, 1);
    will_return(__wrap_wdb_close, OS_SUCCESS);
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);

    // Creating global.db
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);

    // Error opening new global.db
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Can't open SQLite backup database \
'queue/db/global.db': ERROR MESSAGE");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    ret = wdb_recreate_global(data->wdb);

    assert_null(ret);
}

void test_wdb_recreate_global_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    sqlite3 *new_db = NULL;
    os_calloc(1,sizeof(sqlite3 *),new_db);

    // Closing the wdb struct and removing the current database file
    will_return(__wrap_wdb_close, 1);
    will_return(__wrap_wdb_close, OS_SUCCESS);
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);

    // Creating global.db
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);

    // Opening new global.db
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, new_db);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    ret = wdb_recreate_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_ptr_equal(new_db, ret->db);
}

/* Tests wdb_upgrade_global */

void test_wdb_upgrade_global_error_checking_metadata_table(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 0);
    will_return(__wrap_wdb_count_tables_with_name, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "DB(global) Error trying to find metadata table");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_false(ret->enabled);
}

void test_wdb_upgrade_global_error_backingup_legacy_db(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 0);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // wdb_upgrade_check_manager_keepalive (returns OS_SUCCESS
    // to indicate that is a legacy database)
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // Error backing up the database
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Creating pre-upgrade \
Global DB snapshot failed: global.db-pre_upgrade");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_false(ret->enabled);
}

void test_wdb_upgrade_global_success_regenerating_legacy_db(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    sqlite3 *new_db = NULL;
    os_calloc(1,sizeof(sqlite3 *),new_db);

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 0);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // wdb_upgrade_check_manager_keepalive (returns OS_SUCCESS
    // to indicate that is a legacy database)
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // Success backing up the database
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Recreating the database
    // Closing the wdb struct and removing the current database file
    will_return(__wrap_wdb_close, 1);
    will_return(__wrap_wdb_close, OS_SUCCESS);
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);

    // Creating global.db
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);

    // Opening new global.db
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, new_db);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_ptr_equal(new_db, ret->db);
}

void test_wdb_upgrade_global_error_getting_database_version(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // Error getting database version
    char str_db_version[] = "1";
    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, str_db_version);
    will_return(__wrap_wdb_metadata_get_entry, OS_INVALID);
    expect_string(__wrap__mwarn, formatted_msg, "DB(global): Error trying to get DB version");

    // Error creating pre upgrade backup
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_INVALID);
    expect_string(__wrap__merror,
                  formatted_msg,
                  "Creating pre-upgrade Global DB snapshot failed: "
                  "global.db-pre_upgrade");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_false(ret->enabled);
}

void test_wdb_upgrade_global_error_creating_pre_upgrade_backup(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // Getting database version
    char str_db_version[] = "1";
    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, str_db_version);
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    // Error creating pre upgrade backup
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_INVALID);
    expect_string(__wrap__merror,
                  formatted_msg,
                  "Creating pre-upgrade Global DB snapshot failed: "
                  "global.db-pre_upgrade");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_false(ret->enabled);
}

void test_wdb_upgrade_global_error_restoring_database_and_getting_backup_name(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // Getting database version
    char str_db_version[] = "1";
    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, str_db_version);
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    // Creating pre upgrade backup
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Error restoring database and getting the backup file name
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, OS_INVALID);
    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, FALSE);
    will_return(__wrap_wdb_global_restore_backup, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 2.");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_false(ret->enabled);
}

void test_wdb_upgrade_global_database_restored(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // Getting database version
    char str_db_version[] = "1";
    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, str_db_version);
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    // Creating pre upgrade backup
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Error upgrading database from version 1 to 2
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, OS_INVALID);
    // Restoring database to the most recent backup
    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_SUCCESS);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 2. \
The global.db was restored to the original state.");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_true(ret->enabled);
}

void test_wdb_upgrade_global_intermediate_upgrade_error(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // Getting database version
    char str_db_version[] = "1";
    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, str_db_version);
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    // Creating pre upgrade backup
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Upgrading database from version 1 to 2
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Error upgrading database from version 2 to 3
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 3");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v3_sql);
    will_return(__wrap_wdb_sql_exec, OS_INVALID);
    // Restoring database to the most recent backup
    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_SUCCESS);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 3. \
The global.db was restored to the original state.");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_true(ret->enabled);
}

void test_wdb_upgrade_global_full_upgrade_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // Getting database version
    char str_db_version[] = "1";
    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, str_db_version);
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    // Creating pre upgrade backup
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Upgrading database from version 1 to 2
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 2 to 3
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 3");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v3_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 3 to 4
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 4");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v4_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    will_return(__wrap_wdb_global_adjust_v4, OS_SUCCESS);
    // Upgrading database from version 4 to 5
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 5");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v5_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 5 to 6
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 6");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v6_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 6 to 7
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_true(ret->enabled);
}

void test_wdb_upgrade_global_full_upgrade_success_from_unversioned_db(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 0);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    // wdb_upgrade_check_manager_keepalive (returns 1
    // to indicate that is a legacy database greater than 3.10)
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // Creating pre upgrade backup
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Upgrading unversioned database to version 1
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 1");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v1_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 1 to 2
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 2 to 3
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 3");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v3_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 3 to 4
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 4");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v4_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    will_return(__wrap_wdb_global_adjust_v4, OS_SUCCESS);
    // Upgrading database from version 4 to 5
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 5");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v5_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 5 to 6
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 6");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v6_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);
    // Upgrading database from version 6 to 7
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, OS_SUCCESS);

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_true(ret->enabled);
}

void test_wdb_upgrade_global_update_v1_to_latest_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Upgrade to version 2
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 3
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 3");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v3_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 4
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 4");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v4_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Adjust to version 4
    will_return(__wrap_wdb_global_adjust_v4, OS_SUCCESS);
    // Upgrade to version 5
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 5");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v5_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 6
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 6");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v6_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 7
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v1_to_latest_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);

    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_INVALID);

    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 2.");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v2_to_latest_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "2");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Upgrade to version 3
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 3");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v3_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 4
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 4");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v4_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Adjust to version 4
    will_return(__wrap_wdb_global_adjust_v4, OS_SUCCESS);
    // Upgrade to version 5
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 5");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v5_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 6
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 6");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v6_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 7
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v2_to_latest_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "2");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 3");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v3_sql);
    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 3. The global.db was "
                               "restored to the original state.");

    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_SUCCESS);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v3_to_latest_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "3");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Upgrade to version 4
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 4");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v4_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Adjust to version 4
    will_return(__wrap_wdb_global_adjust_v4, OS_SUCCESS);
    // Upgrade to version 5
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 5");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v5_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 6
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 6");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v6_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    // Upgrade to version 7
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v3_to_latest_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "3");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 4");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v4_sql);
    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 4.");

    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_INVALID);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v4_to_latest_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "4");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Upgrade to version 5
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 5");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v5_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    // Upgrade to version 6
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 6");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v6_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    // Upgrade to version 7
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v4_to_latest_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "4");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 5");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v5_sql);
    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 5.");

    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_INVALID);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v5_to_latest_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "5");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    // Upgrade to version 6
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 6");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v6_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    // Upgrade to version 7
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v5_to_latest_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "5");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 6");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v6_sql);
    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 6.");

    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_INVALID);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v6_to_latest_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "6");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v6_to_latest_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "6");
    will_return(__wrap_wdb_metadata_get_entry, OS_SUCCESS);

    will_return(__wrap_wdb_global_create_backup, "string");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 7");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v7_sql);
    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__merror, formatted_msg, "Failed to update global.db to version 7.");

    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_INVALID);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_fail_backup_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_count_tables_with_name, key, "metadata");
    will_return(__wrap_wdb_count_tables_with_name, 1);
    will_return(__wrap_wdb_count_tables_with_name, OS_SUCCESS);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, OS_INVALID);

    expect_string(__wrap__mwarn, formatted_msg, "DB(global): Error trying to get DB version");

    // Error creating pre upgrade backup
    will_return(__wrap_wdb_global_create_backup, "global.db");
    will_return(__wrap_wdb_global_create_backup, OS_INVALID);
    expect_string(__wrap__merror,
                  formatted_msg,
                  "Creating pre-upgrade Global DB snapshot failed: "
                  "global.db-pre_upgrade");

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
    assert_false(ret->enabled);
}

/* Tests wdb_is_older_than_v310 */

void test_wdb_is_older_than_v310_prepare_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_prepare_v2(): ERROR MESSAGE");

    assert_int_equal(wdb_is_older_than_v310(data->wdb), true);
}

void test_wdb_is_older_than_v310_step_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ERROR);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(wdb_is_older_than_v310(data->wdb), true);
}

void test_wdb_is_older_than_v310_step_nodata(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(wdb_is_older_than_v310(data->wdb), true);
}

void test_wdb_is_older_than_v310_step_ok(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    assert_int_equal(wdb_is_older_than_v310(data->wdb), false);
}


int main()
{

    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_wdb_recreate_global_error_closing_wdb_struct, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_recreate_global_error_creating_global_db, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_recreate_global_error_opening_global_db, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_recreate_global_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_error_checking_metadata_table, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_error_backingup_legacy_db, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_success_regenerating_legacy_db, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_error_getting_database_version, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_error_creating_pre_upgrade_backup, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_error_restoring_database_and_getting_backup_name, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_database_restored, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_intermediate_upgrade_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_full_upgrade_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_full_upgrade_success_from_unversioned_db, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_is_older_than_v310_prepare_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_is_older_than_v310_step_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_is_older_than_v310_step_nodata, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_is_older_than_v310_step_ok, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v1_to_latest_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v1_to_latest_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v2_to_latest_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v2_to_latest_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v3_to_latest_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v3_to_latest_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v4_to_latest_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v4_to_latest_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v5_to_latest_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v5_to_latest_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v6_to_latest_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v6_to_latest_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_fail_backup_fail, setup_wdb, teardown_wdb),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
