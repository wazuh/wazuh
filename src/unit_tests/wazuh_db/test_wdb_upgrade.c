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

typedef struct test_struct {
    wdb_t *socket;
    char *output;
} test_struct_t;

/* setup/teardown */

int setup_wdb(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->socket);
    os_strdup("000",init_data->socket->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->socket->db);
    *state = init_data;
    return 0;
}

int teardown_wdb(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->socket->id);
    os_free(data->socket->db);
    os_free(data->socket);
    os_free(data);
    return 0;
}

/* Tests wdb_upgrade_global */ 

void test_wdb_upgrade_global_table_fail(void **state) //Backup Fail
{   
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    
    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, OS_INVALID);
    expect_string(__wrap__mwarn, formatted_msg, "DB(000) Error trying to find metadata table");
    will_return(__wrap_wdb_close, -1);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite Global backup database.");

    ret = wdb_upgrade_global(data->socket);

    assert_int_equal(ret, NULL);
}

void test_wdb_upgrade_global_update_success(void **state)
{   
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    
    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database '000' to version 1");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v1_sql);
    will_return(__wrap_wdb_sql_exec, 0);

    ret = wdb_upgrade_global(data->socket);

    assert_int_equal(ret, data->socket);
}

void test_wdb_upgrade_global_update_fail(void **state) //backup fail
{   
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    
    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Updating database '000' to version 1");
    expect_string(__wrap_wdb_sql_exec, sql_exec, schema_global_upgrade_v1_sql);
    will_return(__wrap_wdb_sql_exec, -1);
    expect_string(__wrap__mwarn, formatted_msg, "Failed to update global.db to version 1");
    will_return(__wrap_wdb_close, -1);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite Global backup database.");


    ret = wdb_upgrade_global(data->socket);

    assert_int_equal(ret, 0);
}

void test_wdb_upgrade_global_get_version_fail(void **state) //backup fail
{   
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    
    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 1);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, -1);
    expect_string(__wrap__mwarn, formatted_msg, "DB(000): Error trying to get DB version");
    will_return(__wrap_wdb_close, -1);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite Global backup database.");


    ret = wdb_upgrade_global(data->socket);

    assert_int_equal(ret, 0);
}

void test_wdb_upgrade_global_get_version_success(void **state)
{   
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    
    expect_string(__wrap_wdb_metadata_table_check, key, "metadata");
    will_return(__wrap_wdb_metadata_table_check, 1);

    expect_string(__wrap_wdb_metadata_get_entry, key, "db_version");
    will_return(__wrap_wdb_metadata_get_entry, "1");
    will_return(__wrap_wdb_metadata_get_entry, 1);

    ret = wdb_upgrade_global(data->socket);

    assert_int_equal(ret, data->socket);
}

int main()
{
    const struct CMUnitTest tests[] = 
    {
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_table_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_update_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_get_version_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_get_version_success, setup_wdb, teardown_wdb)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
