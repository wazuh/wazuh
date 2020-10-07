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
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

void test_wdb_metadata_table_check_prepare_fail(void **state)
{
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_prepare_v2(): ERROR MESSAGE");
    
    ret = wdb_metadata_table_check(data->wdb, "metadata");
    
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_metadata_table_check_bind_fail(void **state)
{
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "metadata");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_text(): ERROR MESSAGE");
    
    ret = wdb_metadata_table_check(data->wdb, "metadata");
    
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_metadata_table_check_step_fail(void **state)
{
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "metadata");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): ERROR MESSAGE");
    
    ret = wdb_metadata_table_check(data->wdb, "metadata");
    
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_metadata_table_check_success(void **state)
{
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "metadata");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int,iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    
    ret = wdb_metadata_table_check(data->wdb, "metadata");
    
    assert_int_equal(ret, 1);
}

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wdb_metadata_table_check_prepare_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_metadata_table_check_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_metadata_table_check_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_metadata_table_check_success, test_setup, test_teardown)
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
