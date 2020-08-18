/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 5, 2016.
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

/* redefinitons/wrapping */

int __wrap__mdebug1()
{
    return 0;
}

int __wrap__mdebug2()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

int __wrap__merror()
{
    return 0;
}

cJSON * __wrap_cJSON_CreateObject(void) {
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number) {
    check_expected(name);
    check_expected(number);
    return mock_type(cJSON *);
}

cJSON* __wrap_cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string) {
    check_expected(name);
    check_expected(string);
    return mock_type(cJSON *);
}

/* setup/teardown */

int setup_wdb_agent(void **state) {
    return 0;
}

int teardown_wdb_agent(void **state) {
    return 0;
}

/* Tests wdb_insert_agent*/

void test_wdb_insert_agent_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";
    const char *ip = "192.168.0.101";
    const char *register_ip = "any";
    const char *internal_key = "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301";
    const char *group = "default";
    int keep_date = 0;

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date);

    assert_string_equal(data->output, "err Invalid FIM query syntax, near \'badquery_nospace\'");
    assert_int_equal(ret, -1);
}

int main()
{
    const struct CMUnitTest tests[] = 
    {
        /* Tests wdb_insert_agent*/
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_json, setup_wdb_agent, teardown_wdb_agent)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}