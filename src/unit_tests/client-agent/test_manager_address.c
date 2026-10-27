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
#include <stdio.h>

#include "agentd.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* w_agent_validate_manager_address() decides whether the agent has a manager to connect to, the
 * check both entry points (main.c, win_utils.c) run right after ClientConf(). The address check
 * itself is Validate_Address() in client-config.c, which runs for real here.
 *
 * client.keys is a real file in the working directory (KEYS_FILE: etc/client.keys, or
 * client.keys on Windows), so the same cases run on both targets. The cases where it must not
 * matter use an empty one: a hint logged there would be an unexpected merror(), which fails. */

/* main.c passes the installation directory so the hint names a command that runs as typed: bin/
 * is not on PATH. The Windows hint names the GUI first and has no use for it. */
#ifndef WIN32
#define HOME_PATH "/var/ossec"
#define NOT_ENROLLED_HINT "(4128): This agent is not enrolled yet. Enroll it as root with " \
                          "'/var/ossec/bin/wazuh-agent-auth --token-file <path>', then start the agent."
#else
#define HOME_PATH NULL
#define NOT_ENROLLED_HINT "(4128): This agent is not enrolled yet. Enroll it with Manage > " \
                          "Enroll in the agent GUI, or as an administrator with " \
                          "'wazuh-agent-auth.exe --token-file <path>' from the agent's " \
                          "installation folder, then start the agent."
#endif

/* Leaves client.keys holding @p content, or absent when it is NULL. */
static void set_client_keys(const char *content)
{
    remove(KEYS_FILE);

    if (content != NULL) {
        FILE *fp = fopen(KEYS_FILE, "w");
        assert_non_null(fp);
        fputs(content, fp);
        fclose(fp);
    }
}

static int setup_group(void **state)
{
    (void)state;
#ifndef WIN32
    mkdir("etc", 0750);
#endif
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    remove(KEYS_FILE);
    return 0;
}

static void test_no_manager_block_refuses_to_start(void **state)
{
    (void)state;
    agent cfg = {0};

    set_client_keys("");
    expect_string(__wrap__merror, formatted_msg, "(4105): No valid server IP found.");

    assert_false(w_agent_validate_manager_address(&cfg, HOME_PATH));
}

static void test_real_address_starts(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "192.168.1.10"}, {0}};
    agent cfg = {.server = servers};

    set_client_keys("");

    assert_true(w_agent_validate_manager_address(&cfg, HOME_PATH));
}

/* Validate_Address() asks for one usable address, not for all of them to be usable. */
static void test_one_real_address_among_placeholders_starts(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {.rip = "192.168.1.10"}, {0}};
    agent cfg = {.server = servers};

    set_client_keys("");

    assert_true(w_agent_validate_manager_address(&cfg, HOME_PATH));
}

/* The case the hint exists for: a package installed without a token and started as it is. */
static void test_placeholder_on_an_unenrolled_agent_names_wazuh_agent_auth(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {0}};
    agent cfg = {.server = servers};

    set_client_keys("");
    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: 'MANAGER_IP'");
    expect_string(__wrap__merror, formatted_msg, NOT_ENROLLED_HINT);

    assert_false(w_agent_validate_manager_address(&cfg, HOME_PATH));
}

/* No client.keys at all is just as unenrolled. */
static void test_placeholder_without_client_keys_names_wazuh_agent_auth(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {0}};
    agent cfg = {.server = servers};

    set_client_keys(NULL);
    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: 'MANAGER_IP'");
    expect_string(__wrap__merror, formatted_msg, NOT_ENROLLED_HINT);

    assert_false(w_agent_validate_manager_address(&cfg, HOME_PATH));
}

/* The Windows package ships 0.0.0.0 instead of MANAGER_IP; it is the same unenrolled agent. */
static void test_windows_placeholder_on_an_unenrolled_agent_names_wazuh_agent_auth(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "0.0.0.0"}, {0}};
    agent cfg = {.server = servers};

    set_client_keys("");
    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: '0.0.0.0'");
    expect_string(__wrap__merror, formatted_msg, NOT_ENROLLED_HINT);

    assert_false(w_agent_validate_manager_address(&cfg, HOME_PATH));
}

/* An enrolled agent whose address was put back to the placeholder by hand: telling it to enroll
 * would be wrong, since wazuh-agent-auth refuses an agent that already has a key. */
static void test_placeholder_on_an_enrolled_agent_names_only_the_address(void **state)
{
    (void)state;
    agent_server servers[] = {{.rip = "MANAGER_IP"}, {0}};
    agent cfg = {.server = servers};

    set_client_keys("001 enrolled-agent any 0123456789abcdef\n");
    expect_string(__wrap__merror, formatted_msg, "(4112): Invalid server address found: 'MANAGER_IP'");

    assert_false(w_agent_validate_manager_address(&cfg, HOME_PATH));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_no_manager_block_refuses_to_start, teardown),
        cmocka_unit_test_teardown(test_real_address_starts, teardown),
        cmocka_unit_test_teardown(test_one_real_address_among_placeholders_starts, teardown),
        cmocka_unit_test_teardown(test_placeholder_on_an_unenrolled_agent_names_wazuh_agent_auth, teardown),
        cmocka_unit_test_teardown(test_placeholder_without_client_keys_names_wazuh_agent_auth, teardown),
        cmocka_unit_test_teardown(test_windows_placeholder_on_an_unenrolled_agent_names_wazuh_agent_auth, teardown),
        cmocka_unit_test_teardown(test_placeholder_on_an_enrolled_agent_names_only_the_address, teardown),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
