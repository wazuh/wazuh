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

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size) {
    return mock();
}

int __wrap_select() {
    return mock();
}

int __wrap_close(int fd) {
    check_expected(fd);
    return 0;
}

int __wrap_accept() {
    return mock();
}

int __wrap_OS_RecvSecureTCP(int sock, char *ret, uint32_t size) {
    check_expected(sock);
    check_expected(size);

    strncpy(ret, mock_type(char*), size);

    return mock();
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    check_expected(sock);
    check_expected(size);
    check_expected(msg);

    return mock();
}

int __wrap_wm_agent_upgrade_parse_message(const char* buffer, void** task, int** agent_ids, char** error) {
    check_expected(buffer);

    *task = mock_type(void*);
    *agent_ids = mock_type(int*);
    *error = mock_type(char*);

    return mock();
}

char* __wrap_wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task) {
    check_expected_ptr(agent_ids);
    check_expected_ptr(task);

    return mock_type(char *);
}

char* __wrap_wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task) {
    check_expected_ptr(agent_ids);
    check_expected_ptr(task);

    return mock_type(char *);
}

char* __wrap_wm_agent_upgrade_process_agent_result_command(const int* agent_ids, wm_upgrade_agent_status_task* task) {
    check_expected_ptr(agent_ids);
    check_expected_ptr(task);

    return mock_type(char *);
}

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_listen_messages_upgrade_command(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "{\"command\":\"upgrade\","
                   "\"agents\":[1],"
                   "\"params\":{\"wpk_repo\":\"packages.wazuh.com/wpk\"}}";
    size_t input_size = strlen(input) + 1;
    wm_upgrade_task *upgrade_task = NULL;
    int *agents = NULL;
    char *response = NULL;

    os_calloc(1, sizeof(wm_upgrade_task), upgrade_task);
    os_calloc(2, sizeof(int), agents);
    os_calloc(OS_SIZE_128, sizeof(char), response);

    agents[0] = 1;
    agents[1] = -1;

    sprintf(response, "[{\"error\":\"0\","
                        "\"data\":\"Success.\","
                        "\"agent\":1,"
                        "\"task_id\":1}]");

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: '{\"command\":\"upgrade\","
                                                                                "\"agents\":[1],"
                                                                                "\"params\":{\"wpk_repo\":\"packages.wazuh.com/wpk\"}}'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, (void*)upgrade_task);
    will_return(__wrap_wm_agent_upgrade_parse_message, agents);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, WM_UPGRADE_UPGRADE);

    expect_value(__wrap_wm_agent_upgrade_process_upgrade_command, agent_ids, agents);
    expect_value(__wrap_wm_agent_upgrade_process_upgrade_command, task, upgrade_task);
    will_return(__wrap_wm_agent_upgrade_process_upgrade_command, response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '[{\"error\":\"0\","
                                                                                "\"data\":\"Success.\","
                                                                                "\"agent\":1,"
                                                                                "\"task_id\":1}]'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_upgrade_custom_command(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "{\"command\":\"upgrade_custom\","
                   "\"agents\":[2],"
                   "\"params\":{\"file_path\":\"/test/wazuh.wpk\"}}";
    size_t input_size = strlen(input) + 1;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;
    int *agents = NULL;
    char *response = NULL;

    os_calloc(1, sizeof(wm_upgrade_custom_task), upgrade_custom_task);
    os_calloc(2, sizeof(int), agents);
    os_calloc(OS_SIZE_128, sizeof(char), response);

    agents[0] = 2;
    agents[1] = -1;

    sprintf(response, "[{\"error\":\"0\","
                        "\"data\":\"Success.\","
                        "\"agent\":2,"
                        "\"task_id\":2}]");

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: '{\"command\":\"upgrade_custom\","
                                                                                "\"agents\":[2],"
                                                                                "\"params\":{\"file_path\":\"/test/wazuh.wpk\"}}'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, (void*)upgrade_custom_task);
    will_return(__wrap_wm_agent_upgrade_parse_message, agents);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, WM_UPGRADE_UPGRADE_CUSTOM);

    expect_value(__wrap_wm_agent_upgrade_process_upgrade_custom_command, agent_ids, agents);
    expect_value(__wrap_wm_agent_upgrade_process_upgrade_custom_command, task, upgrade_custom_task);
    will_return(__wrap_wm_agent_upgrade_process_upgrade_custom_command, response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '[{\"error\":\"0\","
                                                                                "\"data\":\"Success.\","
                                                                                "\"agent\":2,"
                                                                                "\"task_id\":2}]'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_agent_update_status_command(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "{\"command\":\"upgrade_update_status\","
                   "\"agents\":[3],"
                   "\"params\":{\"error\":0," 
                               "\"message\":\"Upgrade was successful\","
                               "\"status\":\"Done\"}}";
    size_t input_size = strlen(input) + 1;
    wm_upgrade_agent_status_task *upgrade_agent_status_task = NULL;
    int *agents = NULL;
    char *response = NULL;

    os_calloc(1, sizeof(wm_upgrade_agent_status_task), upgrade_agent_status_task);
    os_calloc(2, sizeof(int), agents);
    os_calloc(OS_SIZE_128, sizeof(char), response);

    agents[0] = 3;
    agents[1] = -1;

    sprintf(response, "[{\"error\":\"0\","
                        "\"data\":\"Success.\","
                        "\"agent\":3}]");

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: '{\"command\":\"upgrade_update_status\","
                                                                                "\"agents\":[3],"
                                                                                "\"params\":{\"error\":0," 
                                                                                            "\"message\":\"Upgrade was successful\","
                                                                                            "\"status\":\"Done\"}}'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, (void*)upgrade_agent_status_task);
    will_return(__wrap_wm_agent_upgrade_parse_message, agents);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, WM_UPGRADE_AGENT_UPDATE_STATUS);

    expect_value(__wrap_wm_agent_upgrade_process_agent_result_command, agent_ids, agents);
    expect_value(__wrap_wm_agent_upgrade_process_agent_result_command, task, upgrade_agent_status_task);
    will_return(__wrap_wm_agent_upgrade_process_agent_result_command, response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '[{\"error\":\"0\","
                                                                                "\"data\":\"Success.\","
                                                                                "\"agent\":3}]'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_parse_error(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    size_t input_size = strlen(input) + 1;
    char *response = "{\"error\":18,"
                      "\"data\":\"Upgrade procedure could not start.\"}";

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: 'Bad JSON'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, OS_INVALID);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{\"error\":18,"
                                                                               "\"data\":\"Upgrade procedure could not start.\"}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_parse_error_with_message(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    size_t input_size = strlen(input) + 1;
    char *response = NULL;

    os_calloc(OS_SIZE_128, sizeof(char), response);

    sprintf(response, "{\"error\":1,"
                       "\"data\":\"Could not parse message JSON.\"}");

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: 'Bad JSON'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, response);
    will_return(__wrap_wm_agent_upgrade_parse_message, OS_INVALID);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{\"error\":1,"
                                                                               "\"data\":\"Could not parse message JSON.\"}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_receive_empty(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8159): Empty message from local client.");

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_receive_error(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8111): Error in recv(): 'Success'");

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_receive_sock_error(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_accept_error_eintr(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    will_return(__wrap_OS_BindUnixDomain, 0);

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

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_accept_error(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = 1;

    will_return(__wrap_OS_BindUnixDomain, 0);

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

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_select_zero(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_select_error_eintr(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    expect_value(__wrap_close, fd, peer);

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_select_error(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;
    int socket = 0;
    errno = 1;

    will_return(__wrap_OS_BindUnixDomain, 0);

    will_return(__wrap_select, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8109): Error in select(): 'Operation not permitted'. Exiting...");

    expect_value(__wrap_close, fd, socket);

    wm_agent_upgrade_listen_messages(timeout, config);
}

void test_wm_agent_upgrade_listen_messages_bind_error(void **state)
{
    wm_manager_configs *config = *state;
    int timeout = 10;

    will_return(__wrap_OS_BindUnixDomain, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8108): Unable to bind to socket '/var/ossec/queue/tasks/upgrade': 'Operation not permitted'");

    wm_agent_upgrade_listen_messages(timeout, config);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        // wm_agent_upgrade_listen_messages
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_upgrade_command),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_upgrade_custom_command),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_agent_update_status_command),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_parse_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_parse_error_with_message),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_empty),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_sock_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_zero),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_bind_error)
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
