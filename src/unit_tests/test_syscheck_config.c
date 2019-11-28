/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

/* redefinitons/wrapping */

int __wrap__merror()
{
    return 0;
}


static int delete_json(void **state)
{
    cJSON *data = *state;
    cJSON_Delete(data);
    return 0;
}


/* tests */

void test_Read_Syscheck_Config_success(void **state)
{
    (void) state;
    int ret;

    ret = Read_Syscheck_Config("test_syscheck.conf");

    assert_int_equal(ret, 0);
}


void test_Read_Syscheck_Config_invalid(void **state)
{
    (void) state;
    int ret;

    ret = Read_Syscheck_Config("invalid.conf");

    assert_int_equal(ret, -1);
}


void test_getSyscheckConfig(void **state)
{
    (void) state;
    cJSON * ret;

    Read_Syscheck_Config("test_syscheck.conf");

    ret = getSyscheckConfig();
    *state = ret;

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);
    cJSON* sys_items = cJSON_GetObjectItem(ret, "syscheck");
    assert_int_equal(cJSON_GetArraySize(sys_items), 17);
    cJSON* sys_dir = cJSON_GetObjectItem(sys_items, "directories");
    assert_int_equal(cJSON_GetArraySize(sys_dir), 6);
}


void test_getSyscheckInternalOptions(void **state)
{
    (void) state;
    cJSON * ret;

    Read_Syscheck_Config("test_syscheck.conf");

    ret = getSyscheckInternalOptions();
    *state = ret;

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);
    cJSON* items = cJSON_GetObjectItem(ret, "internal");
    assert_int_equal(cJSON_GetArraySize(items), 2);
    cJSON* sys_items = cJSON_GetObjectItem(items, "syscheck");
    assert_int_equal(cJSON_GetArraySize(sys_items), 8);
    cJSON* root_items = cJSON_GetObjectItem(items, "rootcheck");
    assert_int_equal(cJSON_GetArraySize(root_items), 1);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_Read_Syscheck_Config_success),
        cmocka_unit_test(test_Read_Syscheck_Config_invalid),
        cmocka_unit_test_teardown(test_getSyscheckConfig, delete_json),
        cmocka_unit_test_teardown(test_getSyscheckInternalOptions, delete_json),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
