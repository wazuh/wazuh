/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "wazuh_db/wdb.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_metadata_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"

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

/* Tests wdb_upgrade_global */

void test_wdb_upgrade_global_table_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, OS_INVALID);
    expect_string(__wrap__mwarn, formatted_msg, "DB(global) Error trying to find metadata table");

    //Global backup success
    will_return(__wrap_wdb_close, 0);
    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);
    expect_string(__wrap__mwarn, formatted_msg, "Creating Global DB backup and creating empty DB");
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    expect_string(__wrap_wdb_init, id, "global");
    will_return(__wrap_wdb_init, (wdb_t*)1);
    expect_value(__wrap_wdb_pool_append, wdb, (wdb_t*)1);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, 1);
}

void test_wdb_upgrade_global_update_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 1");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v1_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    will_return(__wrap_wdb_global_check_manager_keepalive, 1);
    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_delete_old_version(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 0);
    will_return(__wrap_wdb_global_check_manager_keepalive, 0);

    //Global backup success
    will_return(__wrap_wdb_close, 0);
    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);
    expect_string(__wrap__mwarn, formatted_msg, "Creating Global DB backup and creating empty DB");
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    expect_string(__wrap_wdb_init, id, "global");
    will_return(__wrap_wdb_init, (wdb_t*)1);
    expect_value(__wrap_wdb_pool_append, wdb, (wdb_t*)1);


    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, 1);
}

void test_wdb_upgrade_global_update_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 1");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v1_sql);
    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__mwarn, formatted_msg, "Failed to update global.db to version 1");
    will_return(__wrap_wdb_global_check_manager_keepalive, 1);

    //Global backup success
    will_return(__wrap_wdb_close, 0);
    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);
    expect_string(__wrap__mwarn, formatted_msg, "Creating Global DB backup and creating empty DB");
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    expect_string(__wrap_wdb_init, id, "global");
    will_return(__wrap_wdb_init, (wdb_t*)1);
    expect_value(__wrap_wdb_pool_append, wdb, (wdb_t*)1);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, 1);
}

void test_wdb_upgrade_global_get_version_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 1);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, -1);
    expect_string(__wrap__mwarn, formatted_msg, "DB(global): Error trying to get DB version");

    //Global backup success
    will_return(__wrap_wdb_close, 0);
    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);
    expect_string(__wrap__mwarn, formatted_msg, "Creating Global DB backup and creating empty DB");
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    expect_string(__wrap_wdb_init, id, "global");
    will_return(__wrap_wdb_init, (wdb_t*)1);
    expect_value(__wrap_wdb_pool_append, wdb, (wdb_t*)1);


    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, 1);
}

void test_wdb_upgrade_global_all_versions_upgrade(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 1);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "0");
    will_return(__wrap_wdb_metadata_get_entry, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 1");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v1_sql);
    will_return(__wrap_wdb_sql_exec, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v1_to_v2_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 1);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, data->wdb);
}

void test_wdb_upgrade_global_update_v1_to_v2_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 1);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database 'global' to version 2");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v2_sql);
    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__mwarn, formatted_msg, "Failed to update global.db to version 2");

    //Global backup success
    will_return(__wrap_wdb_close, 0);
    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);
    expect_string(__wrap__mwarn, formatted_msg, "Creating Global DB backup and creating empty DB");
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    expect_string(__wrap_wdb_init, id, "global");
    will_return(__wrap_wdb_init, (wdb_t*)1);
    expect_value(__wrap_wdb_pool_append, wdb, (wdb_t*)1);

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, 1);
}

void test_wdb_upgrade_global_fail_backup_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 1);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, -1);
    expect_string(__wrap__mwarn, formatted_msg, "DB(global): Error trying to get DB version");
    will_return(__wrap_wdb_close, -1);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite Global backup database.");

    ret = wdb_upgrade_global(data->wdb);

    assert_int_equal(ret, NULL);
}

void test_wdb_create_backup_global_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);

    ret = wdb_create_backup_global(1);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_create_backup_global_dst_fopen_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 0);
    expect_string(__wrap__merror, formatted_msg, "Couldn't open source 'queue/db/global.db': Success (0)");

    ret = wdb_create_backup_global(1);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_create_backup_global_src_fopen_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 0);
    expect_string(__wrap__merror, formatted_msg, "Couldn't open dest 'queue/db/global.db-oldv1-1': Success (0)");
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    ret = wdb_create_backup_global(1);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_create_backup_global_fwrite_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 1);
    will_return(__wrap_fwrite, 0);
    expect_string(__wrap_unlink, file, "queue/db/global.db-oldv1-1");
    will_return(__wrap_unlink, 0);

    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);

    ret = wdb_create_backup_global(1);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_create_backup_global_fclose_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, -1);
    expect_string(__wrap_unlink, file, "queue/db/global.db-oldv1-1");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create file queue/db/global.db-oldv1-1 completely.");

    ret = wdb_create_backup_global(1);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_create_backup_global_chmod_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, -1);
    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object 'queue/db/global.db-oldv1-1' due to [(0)-(Success)].");
    expect_string(__wrap_unlink, file, "queue/db/global.db-oldv1-1");
    will_return(__wrap_unlink, 0);

    ret = wdb_create_backup_global(1);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_backup_global_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_close, 0);
    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);
    expect_string(__wrap__mwarn, formatted_msg, "Creating Global DB backup and creating empty DB");
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, 1);
    will_return(__wrap_sqlite3_open_v2, SQLITE_OK);
    expect_string(__wrap_wdb_init, id, "global");
    will_return(__wrap_wdb_init, (wdb_t*)1);
    expect_value(__wrap_wdb_pool_append, wdb, (wdb_t*)1);

    ret = wdb_backup_global(data->wdb, 1);

    assert_int_equal(ret, 1);
}

void test_wdb_backup_global_close_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_close, -1);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite Global backup database.");

    ret = wdb_backup_global(data->wdb,1);

    assert_int_equal(ret, NULL);
}

void test_wdb_backup_global_create_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_close, 0);
    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 0);
    expect_string(__wrap__merror, formatted_msg, "Couldn't open source 'queue/db/global.db': Success (0)");

    ret = wdb_backup_global(data->wdb, 1);

    assert_int_equal(ret, NULL);
}

void test_wdb_backup_global_qlite3_open_v2_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_close, 0);

    expect_any_always(__wrap_fopen, path);
    expect_any_always(__wrap_fopen, mode);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_any_always(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);
    will_return(__wrap_fclose, 0);
    expect_any_always(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);
    expect_string(__wrap__mwarn, formatted_msg, "Creating Global DB backup and creating empty DB");
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap_wdb_create_global, path, "queue/db/global.db");
    will_return(__wrap_wdb_create_global, OS_SUCCESS);
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, NULL);
    will_return(__wrap_sqlite3_open_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Can't open SQLite backup database 'queue/db/global.db': ERROR MESSAGE");
    will_return(__wrap_sqlite3_close_v2,0);

    ret = wdb_backup_global(data->wdb, 1);

    assert_int_equal(ret, NULL);
}

int main()
{

    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_table_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_delete_old_version, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_get_version_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_all_versions_upgrade, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v1_to_v2_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_v1_to_v2_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_fail_backup_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_create_backup_global_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_create_backup_global_dst_fopen_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_create_backup_global_src_fopen_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_create_backup_global_fwrite_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_create_backup_global_fclose_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_create_backup_global_chmod_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_backup_global_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_backup_global_close_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_backup_global_create_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_backup_global_qlite3_open_v2_fail, setup_wdb, teardown_wdb),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
