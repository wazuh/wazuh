/*
 * Copyright (C) Wazuh Inc.
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

#include "agentd.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* w_agent_validate_manager_address() decides whether the agent has a manager to connect to, the
 * check both entry points (main.c, win_utils.c) run right after ClientConf(). The address check
 * itself is Validate_Address() in client-config.c, which runs for real here. */

static void test_no_manager_block_refuses_to_start(void **state)
{
    (void)state;
    agent cfg = {0};

    expect_string(__wrap__merror, formatted_msg, "(4105): No valid server IP found.");

    assert_false(w_agent_validate_manager_address(&cfg));
}

static void test_real_address_starts(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "192.168.1.10"}, {0}};
    agent cfg = {.server = servers};

    assert_true(w_agent_validate_manager_address(&cfg));
}

/* Validate_Address() asks for one usable address, not for all of them to be usable. */
static void test_one_real_address_among_placeholders_starts(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {.rip = "192.168.1.10"}, {0}};
    agent cfg = {.server = servers};

    assert_true(w_agent_validate_manager_address(&cfg));
}

static void test_linux_placeholder_refuses_to_start(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {0}};
    agent cfg = {.server = servers};

    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: 'MANAGER_IP'");

    assert_false(w_agent_validate_manager_address(&cfg));
}

static void test_windows_placeholder_refuses_to_start(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "0.0.0.0"}, {0}};
    agent cfg = {.server = servers};

    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: '0.0.0.0'");

    assert_false(w_agent_validate_manager_address(&cfg));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_no_manager_block_refuses_to_start),
        cmocka_unit_test(test_real_address_starts),
        cmocka_unit_test(test_one_real_address_among_placeholders_starts),
        cmocka_unit_test(test_linux_placeholder_refuses_to_start),
        cmocka_unit_test(test_windows_placeholder_refuses_to_start),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
