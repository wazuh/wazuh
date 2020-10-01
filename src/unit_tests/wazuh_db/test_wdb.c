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
#include "wazuhdb_op.h"
#include "hash_op.h"

#include "../wrappers/common.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

/* setup/teardown */

int setup_wdb(void **state) {
    test_mode = 1;
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
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

/* Tests wdb_open_global */

void test_wdb_open_global_pool_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_OSHash_Get, self, (OSHash*) 0);
    expect_string(__wrap_OSHash_Get, key, WDB_GLOB_NAME);
    will_return(__wrap_OSHash_Get, data->wdb);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_open_global();

    assert_int_equal(ret, data->wdb);
}

void test_wdb_open_global_create_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_OSHash_Get, self, (OSHash*) 0);
    expect_string(__wrap_OSHash_Get, key, WDB_GLOB_NAME);
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Global database not found, creating.");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    // wdb_create_global 
    //// wdb_create_file
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db': out of memory");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db'");
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_open_global();

    assert_null(ret);
}

int main()
{
    const struct CMUnitTest tests[] = 
    {
        cmocka_unit_test_setup_teardown(test_wdb_open_global_pool_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_open_global_create_fail, setup_wdb, teardown_wdb)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
