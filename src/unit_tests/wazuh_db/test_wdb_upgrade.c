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

#include "wdb.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_metadata_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_wrappers.h"

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

/* Tests wdb_upgrade_global */

/* Scenario: wdb_user_version_get fails (OS_INVALID).
 * Expected: merror, wdb->enabled = false, wdb returned. */
void test_wdb_upgrade_global_error_getting_database_version(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_user_version_get, 0 /* version output — ignored on OS_INVALID */);
    will_return(__wrap_wdb_user_version_get, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "DB(global) Error reading schema version.");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_false(ret->enabled);
}

/* Scenario: DB is at current version (no upgrades pending).
 * Expected: no upgrade steps run, wdb->enabled stays true, wdb returned. */
void test_wdb_upgrade_global_already_at_current_version(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_user_version_get, 1);
    will_return(__wrap_wdb_user_version_get, OS_SUCCESS);

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_true(ret->enabled);
}

/* Scenario: DB reports user_version = 0 (pre-PRAGMA schema, incompatible).
 * Expected: merror, wdb->enabled = false, wdb returned. */
void test_wdb_upgrade_global_version_zero(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_user_version_get, 0);
    will_return(__wrap_wdb_user_version_get, OS_SUCCESS);
    expect_string(__wrap__merror, formatted_msg,
                  "DB(global) Unsupported schema version 0 (expected: 1..1). Disabling database.");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_false(ret->enabled);
}

/* Scenario: DB reports user_version > latest (DB from a future manager version).
 * Expected: merror, wdb->enabled = false, wdb returned. */
void test_wdb_upgrade_global_future_version(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_user_version_get, 99);
    will_return(__wrap_wdb_user_version_get, OS_SUCCESS);
    expect_string(__wrap__merror, formatted_msg,
                  "DB(global) Unsupported schema version 99 (expected: 1..1). Disabling database.");

    ret = wdb_upgrade_global(data->wdb);

    assert_ptr_equal(data->wdb, ret);
    assert_false(ret->enabled);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_error_getting_database_version, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_already_at_current_version, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_version_zero, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_upgrade_global_future_version, setup_wdb, teardown_wdb),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
