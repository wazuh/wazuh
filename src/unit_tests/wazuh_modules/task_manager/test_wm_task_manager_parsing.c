/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/task_manager/wm_task_manager_parsing.h"
#include "../../headers/shared.h"

#ifdef TEST_SERVER

const char* wm_task_manager_decode_status(char *status);

#endif

void test_wm_task_manager_decode_status_done(void **state)
{
    char *status = "Done";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Updated");
}

void test_wm_task_manager_decode_status_in_progress(void **state)
{
    char *status = "In progress";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Updating");
}

void test_wm_task_manager_decode_status_failed(void **state)
{
    char *status = "Failed";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Error");
}

void test_wm_task_manager_decode_status_new(void **state)
{
    char *status = "New";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "The agent is outdated since the task could not start");
}

void test_wm_task_manager_decode_status_timeout(void **state)
{
    char *status = "Timeout";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Timeout reached while waiting for the response from the agent");
}

void test_wm_task_manager_decode_status_legacy(void **state)
{
    char *status = "Legacy";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Legacy upgrade: check the result manually since the agent cannot report the result of the task");
}

void test_wm_task_manager_decode_status_unknown(void **state)
{
    char *status = "No status";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Invalid status");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_decode_status
        cmocka_unit_test(test_wm_task_manager_decode_status_done),
        cmocka_unit_test(test_wm_task_manager_decode_status_in_progress),
        cmocka_unit_test(test_wm_task_manager_decode_status_failed),
        cmocka_unit_test(test_wm_task_manager_decode_status_new),
        cmocka_unit_test(test_wm_task_manager_decode_status_timeout),
        cmocka_unit_test(test_wm_task_manager_decode_status_legacy),
        cmocka_unit_test(test_wm_task_manager_decode_status_unknown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
