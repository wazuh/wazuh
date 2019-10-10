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

#include "../headers/integrity_op.h"

/* tests */

void test_dbsync_check_msg_left(void **state)
{
    (void) state; /* unused */
    char *ret;
    char json[256] = "{\"component\":\"wazuh-testing\",\"type\":\"integrity_check_left\",\"data\":{\"id\":1569926892,\"begin\":\"start\",\"end\":\"top\",\"tail\":\"tail\",\"checksum\":\"51ABB9636078DEFBF888D8457A7C76F85C8F114C\"}}";

    ret = dbsync_check_msg("wazuh-testing", INTEGRITY_CHECK_LEFT, 1569926892, "start", "top", "tail", "51ABB9636078DEFBF888D8457A7C76F85C8F114C");
    assert_string_equal(json, ret);
}

void test_dbsync_check_msg_right(void **state)
{
    (void) state; /* unused */
    char *ret;
    char json[256] = "{\"component\":\"wazuh-testing\",\"type\":\"integrity_check_right\",\"data\":{\"id\":1569926892,\"begin\":\"start\",\"end\":\"top\",\"checksum\":\"51ABB9636078DEFBF888D8457A7C76F85C8F114C\"}}";

    ret = dbsync_check_msg("wazuh-testing", INTEGRITY_CHECK_RIGHT, 1569926892, "start", "top", "tail", "51ABB9636078DEFBF888D8457A7C76F85C8F114C");
    assert_string_equal(json, ret);
}

void test_dbsync_check_msg_global(void **state)
{
    (void) state; /* unused */
    char *ret;
    char json[256] = "{\"component\":\"wazuh-testing\",\"type\":\"integrity_check_global\",\"data\":{\"id\":1569926892,\"begin\":\"start\",\"end\":\"top\",\"checksum\":\"51ABB9636078DEFBF888D8457A7C76F85C8F114C\"}}";

    ret = dbsync_check_msg("wazuh-testing", INTEGRITY_CHECK_GLOBAL, 1569926892, "start", "top", "tail", "51ABB9636078DEFBF888D8457A7C76F85C8F114C");
    assert_string_equal(json, ret);
}

void test_dbsync_check_msg_clear(void **state)
{
    (void) state; /* unused */
    char *ret;
    char json[64] = "{\"component\":\"wazuh-testing\",\"type\":\"integrity_clear\"}";

    ret = dbsync_check_msg("wazuh-testing", INTEGRITY_CLEAR, 1569926892, "start", "top", "tail", "51ABB9636078DEFBF888D8457A7C76F85C8F114C");
    assert_string_equal(json, ret);
}

void test_dbsync_state_msg(void **state)
{
    (void) state; /* unused */
    char *ret;
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "test", "test");
    char json[128] = "{\"component\":\"wazuh-testing\",\"type\":\"state\",\"data\":{\"test\":\"test\"}}";

    ret = dbsync_state_msg("wazuh-testing", data);
    assert_string_equal(json, ret);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dbsync_check_msg_left),
        cmocka_unit_test(test_dbsync_check_msg_right),
        cmocka_unit_test(test_dbsync_check_msg_global),
        cmocka_unit_test(test_dbsync_check_msg_clear),
        cmocka_unit_test(test_dbsync_state_msg),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
