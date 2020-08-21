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
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_manager.h"
#include "../../headers/shared.h"

#ifdef TEST_SERVER

// Setup / teardown

static int setup_config(void **state) {
    wm_manager_configs *config = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    *state = config;
    return 0;
}

static int teardown_config(void **state) {
    wm_manager_configs *config = *state;
    os_free(config);
    return 0;
}

static int teardown_string(void **state) {
    char *string = *state;
    os_free(string);
    return 0;
}

#endif

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

void __wrap__mtwarn(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
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

void __wrap__mtdebug2(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_isChroot() {
    return mock();
}

int __wrap_OS_ConnectUnixDomain(const char *path, int type, int max_msg_size) {
    check_expected(path);
    check_expected(type);
    check_expected(max_msg_size);

    return mock();
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    check_expected(sock);
    check_expected(size);
    if (msg) check_expected(msg);

    return mock();
}

int __wrap_OS_RecvSecureTCP(int sock, char *ret, uint32_t size) {
    check_expected(sock);
    check_expected(size);

    if (mock()) {
        strncpy(ret, mock_type(char*), size);
    }

    return mock();
}

int __wrap_close(int fd) {
    check_expected(fd);
    return 0;
}

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_send_command_to_agent_ok(void **state)
{
    int socket = 555;
    char *command = "Command to agent: restart agent now.";
    char *response = "Command received OK.";
    size_t response_size = strlen(response) + 1;

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: 'Command to agent: restart agent now.'");

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(command));
    expect_string(__wrap_OS_SendSecureTCP, msg, command);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, response);
    will_return(__wrap_OS_RecvSecureTCP, response_size);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'Command received OK.'");

    expect_value(__wrap_close, fd, socket);

    char *res = wm_agent_upgrade_send_command_to_agent(command, strlen(command));

    *state = res;

    assert_non_null(res);
    assert_string_equal(res, response);
}

void test_wm_agent_upgrade_send_command_to_agent_recv_error(void **state)
{
    int socket = 555;
    char *command = "Command to agent: restart agent now.";

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_OS_ConnectUnixDomain, path, REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: 'Command to agent: restart agent now.'");

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(command));
    expect_string(__wrap_OS_SendSecureTCP, msg, command);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 0);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8111): Error in recv(): 'Success'");

    expect_value(__wrap_close, fd, socket);

    char *res = wm_agent_upgrade_send_command_to_agent(command, 0);

    *state = res;

    assert_non_null(res);
}

void test_wm_agent_upgrade_send_command_to_agent_sockterr_error(void **state)
{
    int socket = 555;
    char *command = "Command to agent: restart agent now.";
    char *response = "Command received OK.";

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_OS_ConnectUnixDomain, path, REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '(null)'");

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, 0);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, response);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    expect_value(__wrap_close, fd, socket);

    char *res = wm_agent_upgrade_send_command_to_agent(NULL, 0);

    *state = res;

    assert_non_null(res);
    assert_string_equal(res, response);
}

void test_wm_agent_upgrade_send_command_to_agent_connect_error(void **state)
{
    char *command = "Command to agent: restart agent now.";
    char *response = "Command received OK.";

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_OS_ConnectUnixDomain, path, REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8114): Cannot connect to '/queue/ossec/request'. Could not reach agent.");

    char *res = wm_agent_upgrade_send_command_to_agent(command, strlen(command));

    *state = res;

    assert_null(res);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        // wm_agent_upgrade_send_command_to_agent
        cmocka_unit_test_teardown(test_wm_agent_upgrade_send_command_to_agent_ok, teardown_string),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_send_command_to_agent_recv_error, teardown_string),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_send_command_to_agent_sockterr_error, teardown_string),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_send_command_to_agent_connect_error, teardown_string),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
