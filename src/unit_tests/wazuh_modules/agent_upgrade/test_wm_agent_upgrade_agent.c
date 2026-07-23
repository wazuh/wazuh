/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>

#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/select_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "wmodules.h"
#include "wm_agent_upgrade_agent.h"
#include "shared.h"

#ifndef TEST_WINAGENT
void* wm_agent_upgrade_listen_messages(void *arg);
#endif
bool wm_agent_upgrade_is_shutting_down(void);

// Setup / teardown

static int setup_group(void **state) {
    wm_agent_configs *config = NULL;
    os_calloc(1, sizeof(wm_agent_configs), config);
    *state = config;
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    wm_agent_configs *config = *state;
    os_free(config);
    test_mode = 0;
    return 0;
}

static int setup_test_executions(void **state) {
    wm_max_eps = 1;
    return 0;
}

// Wrappers

int __wrap_accept() {
    return mock();
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    check_expected_ptr(function_pointer);
    return 1;
}

// Tests

#ifndef TEST_WINAGENT

void test_wm_agent_upgrade_listen_messages_ok(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{"
                  "   \"command\": \"upgrade\","
                  "   \"parameters\": {"
                  "        \"file\":\"test.wpk\","
                  "        \"installer\":\"test.sh\""
                  "    }"
                  "}";

    size_t input_size = strlen(input) + 1;
    char *response = NULL;
    os_calloc(OS_SIZE_256, sizeof(char), response);

    sprintf(response, "{"
                      "    \"error\":0,"
                      "    \"data\":[],"
                      "    \"message\":\"ok\""
                      "}");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: '{"
                                                                               "   \"command\": \"upgrade\","
                                                                               "   \"parameters\": {"
                                                                               "        \"file\":\"test.wpk\","
                                                                               "        \"installer\":\"test.sh\""
                                                                               "    }"
                                                                               "}'");

    expect_memory(__wrap_wm_agent_upgrade_process_command, buffer, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_process_command, response);
    will_return(__wrap_wm_agent_upgrade_process_command, strlen(response));

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{"
                                                                              "    \"error\":0,"
                                                                              "    \"data\":[],"
                                                                              "    \"message\":\"ok\""
                                                                              "}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_empty(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8159): Empty message from local client.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8111): Error in recv(): 'Success'");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_sock_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_accept_error_eintr(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_accept_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = 1;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8110): Error in accept(): 'Operation not permitted'");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_zero(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_error_eintr(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_error(void **state)
{
    int socket = 0;
    errno = 1;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8109): Error in select(): 'Operation not permitted'. Exiting...");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_bind_error(void **state)
{
    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8108): Unable to bind to socket 'queue/sockets/upgrade': 'Operation not permitted'");

    wm_agent_upgrade_listen_messages(NULL);
}

#endif

void test_wm_agent_upgrade_start_agent_module_enabled(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_any(__wrap__mtinfo, formatted_msg);

#ifndef TEST_WINAGENT
    expect_memory(__wrap_CreateThread, function_pointer, wm_agent_upgrade_listen_messages, sizeof(wm_agent_upgrade_listen_messages));
#endif

    wm_agent_upgrade_start_agent_module(config, 1);

    assert_int_equal(allow_upgrades, true);
}

void test_wm_agent_upgrade_start_agent_module_disabled(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;

#ifndef TEST_WINAGENT
    expect_memory(__wrap_CreateThread, function_pointer, wm_agent_upgrade_listen_messages, sizeof(wm_agent_upgrade_listen_messages));
#endif

    wm_agent_upgrade_start_agent_module(config, 0);

    assert_int_equal(allow_upgrades, false);
}

int main(void) {
    const struct CMUnitTest tests[] = {
#ifndef TEST_WINAGENT
        // wm_agent_upgrade_listen_messages
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_ok),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_empty),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_sock_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_zero),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_bind_error),
#endif
        // wm_agent_upgrade_start_agent_module
        cmocka_unit_test_setup(test_wm_agent_upgrade_start_agent_module_enabled, setup_test_executions),
        cmocka_unit_test(test_wm_agent_upgrade_start_agent_module_disabled)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
