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
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_validate.h"
#include "../../headers/shared.h"

// Setup / teardown

static int setup_group(void **state) {
    wm_manager_configs *config = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    *state = config;
    return 0;
}

static int teardown_group(void **state) {
    wm_manager_configs *config = *state;
    os_free(config);
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

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_validate_id_ok(void **state)
{
    (void) state;
    int agent_id = 5;

    int ret = wm_agent_upgrade_validate_id(agent_id);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_id_manager(void **state)
{
    (void) state;
    int agent_id = 0;

    int ret = wm_agent_upgrade_validate_id(agent_id);

    assert_int_equal(ret, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);
}

void test_wm_agent_upgrade_validate_status_ok(void **state)
{
    (void) state;
    int last_keep_alive = time(0);

    int ret = wm_agent_upgrade_validate_status(last_keep_alive);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_status_disconnected(void **state)
{
    (void) state;
    int last_keep_alive = time(0) - (DISCON_TIME * 2);

    int ret = wm_agent_upgrade_validate_status(last_keep_alive);

    assert_int_equal(ret, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        // wm_agent_upgrade_listen_messages
        cmocka_unit_test(test_wm_agent_upgrade_validate_id_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_id_manager),
        cmocka_unit_test(test_wm_agent_upgrade_validate_status_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_status_disconnected),
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
