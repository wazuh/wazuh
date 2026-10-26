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
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

/* w_agent_validate_manager_address() decides whether the agent has a manager to connect to, the
 * check both entry points (main.c, win_utils.c) run right after ClientConf(). The address check
 * itself is Validate_Address() in client-config.c, which runs for real here.
 *
 * FileSize() is wrapped so each test says whether client.keys is consulted: only a placeholder
 * address is, since that is what a package installed without a token leaves behind. */

#define NOT_ENROLLED_HINT "(4128): This agent is not enrolled yet. Enroll it with " \
                          "'wazuh-agent-auth --token-file <file>', then start the agent."

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

/* The case the hint exists for: a package installed without a token and started as it is. */
static void test_placeholder_on_an_unenrolled_agent_names_wazuh_agent_auth(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {0}};
    agent cfg = {.server = servers};

    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: 'MANAGER_IP'");
    expect_FileSize(KEYS_FILE, 0);
    expect_string(__wrap__merror, formatted_msg, NOT_ENROLLED_HINT);

    assert_false(w_agent_validate_manager_address(&cfg));
}

/* FileSize() answers -1 when there is no client.keys at all, which is just as unenrolled. */
static void test_placeholder_without_client_keys_names_wazuh_agent_auth(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {0}};
    agent cfg = {.server = servers};

    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: 'MANAGER_IP'");
    expect_FileSize(KEYS_FILE, -1);
    expect_string(__wrap__merror, formatted_msg, NOT_ENROLLED_HINT);

    assert_false(w_agent_validate_manager_address(&cfg));
}

/* The Windows package ships 0.0.0.0 instead of MANAGER_IP; it is the same unenrolled agent. */
static void test_windows_placeholder_on_an_unenrolled_agent_names_wazuh_agent_auth(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "0.0.0.0"}, {0}};
    agent cfg = {.server = servers};

    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: '0.0.0.0'");
    expect_FileSize(KEYS_FILE, 0);
    expect_string(__wrap__merror, formatted_msg, NOT_ENROLLED_HINT);

    assert_false(w_agent_validate_manager_address(&cfg));
}

/* An enrolled agent whose address was put back to the placeholder by hand: telling it to enroll
 * would be wrong, since wazuh-agent-auth refuses an agent that already has a key. */
static void test_placeholder_on_an_enrolled_agent_names_only_the_address(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {0}};
    agent cfg = {.server = servers};

    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: 'MANAGER_IP'");
    expect_FileSize(KEYS_FILE, 64);

    assert_false(w_agent_validate_manager_address(&cfg));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_no_manager_block_refuses_to_start),
        cmocka_unit_test(test_real_address_starts),
        cmocka_unit_test(test_one_real_address_among_placeholders_starts),
        cmocka_unit_test(test_placeholder_on_an_unenrolled_agent_names_wazuh_agent_auth),
        cmocka_unit_test(test_placeholder_without_client_keys_names_wazuh_agent_auth),
        cmocka_unit_test(test_windows_placeholder_on_an_unenrolled_agent_names_wazuh_agent_auth),
        cmocka_unit_test(test_placeholder_on_an_enrolled_agent_names_only_the_address),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
