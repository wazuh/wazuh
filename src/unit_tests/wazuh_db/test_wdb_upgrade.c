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
//#include "wazuhdb_op.h"
//#include "hash_op.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
/*
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"*/

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

/* Tests wdb_open_global */

void test_wdb_upgrade_version_fail(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_OSHash_Get, self, (OSHash*) 0);
    expect_string(__wrap_OSHash_Get, key, WDB_GLOB_NAME);
    will_return(__wrap_OSHash_Get, data->socket);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_upgrade_global();

    assert_int_equal(ret, data->socket);
}


int main()
{
    const struct CMUnitTest tests[] = 
    {
        cmocka_unit_test_setup_teardown(test_wdb_open_global_pool_success, setup_wdb, teardown_wdb),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
