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
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

// Setup / teardown

static int setup_agent_task(void **state) {
    wm_agent_task *agent_task = NULL;
    agent_task = wm_agent_upgrade_init_agent_task();
    *state = (void *)agent_task;
    return 0;
}

static int teardown_agent_task(void **state) {
    wm_agent_task *agent_task = *state;
    wm_agent_upgrade_free_agent_task(agent_task);
    return 0;
}

// Wrappers

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtdebug1(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_OSHash_Add_ex(OSHash *self, const char *key, void *data) {
    check_expected(key);
    check_expected(data);

    return mock();
}

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_create_task_entry_ok(void **state)
{
    int agent_id = 6;
    wm_agent_task *agent_task = *state;

    expect_string(__wrap_OSHash_Add_ex, key, "6");
    expect_memory(__wrap_OSHash_Add_ex, data, agent_task, sizeof(agent_task));
    will_return(__wrap_OSHash_Add_ex, OSHASH_SUCCESS);

    int ret = wm_agent_upgrade_create_task_entry(agent_id, agent_task);

    assert_int_equal(ret, OSHASH_SUCCESS);
}

void test_wm_agent_upgrade_create_task_entry_duplicate(void **state)
{
    int agent_id = 6;
    wm_agent_task *agent_task = *state;

    expect_string(__wrap_OSHash_Add_ex, key, "6");
    expect_memory(__wrap_OSHash_Add_ex, data, agent_task, sizeof(agent_task));
    will_return(__wrap_OSHash_Add_ex, OSHASH_DUPLICATED);

    int ret = wm_agent_upgrade_create_task_entry(agent_id, agent_task);

    assert_int_equal(ret, OSHASH_DUPLICATED);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        // wm_agent_upgrade_upgrade_success_callback
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_create_task_entry_ok, setup_agent_task, teardown_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_create_task_entry_duplicate, setup_agent_task, teardown_agent_task),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
