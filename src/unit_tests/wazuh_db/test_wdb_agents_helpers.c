/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * February 23, 2021.
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

#include "../wazuh_db/helpers/wdb_agents_helpers.h"
#include "wazuhdb_op.h"

#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

extern int test_mode;

/* setup/teardown */

int setup_wdb_agents_helpers(void **state) {
    test_mode = 1;

    return 0;
}

int teardown_wdb_agents_helpers(void **state) {
    test_mode = 0;

    return 0;
}

/* Tests wdb_get_agent_sys_osinfo */

void test_wdb_get_sys_osinfo_error_sql_execution(void ** state)
{
    cJSON *ret = NULL;
    int id = 1;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    //Cleaning  memory
    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_get_agent_sys_osinfo(id, NULL);

    assert_null(ret);
}

void test_wdb_get_sys_osinfo_success(void ** state)
{
    cJSON *ret = NULL;
    int id = 1;

    cJSON *root = __real_cJSON_CreateArray();
    cJSON *row = __real_cJSON_CreateObject();
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    ret = wdb_get_agent_sys_osinfo(id, NULL);

    assert_ptr_equal(root, ret);

    __real_cJSON_Delete(root);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        /* Tests wdb_get_agent_sys_osinfo */
        cmocka_unit_test_setup_teardown(test_wdb_get_sys_osinfo_error_sql_execution, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_sys_osinfo_success, setup_wdb_agents_helpers, teardown_wdb_agents_helpers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
