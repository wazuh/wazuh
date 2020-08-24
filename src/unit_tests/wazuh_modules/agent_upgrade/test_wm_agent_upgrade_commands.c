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

int wm_agent_upgrade_send_lock_restart(int agent_id);
int wm_agent_upgrade_send_open(int agent_id, const char *wpk_file);
cJSON* wm_agent_upgrade_send_single_task(wm_upgrade_command command, int agent_id, const char* status_task);

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

static int teardown_json(void **state) {
    cJSON *json = *state;
    cJSON_Delete(json);
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

cJSON* __wrap_wm_agent_upgrade_parse_task_module_request(wm_upgrade_command command, int agent_id, const char* status) {
    check_expected(command);
    check_expected(agent_id);
    check_expected(status);

    return mock_type(cJSON *);
}

int __wrap_wm_agent_upgrade_task_module_callback(cJSON *json_response, const cJSON* task_module_request) {
    cJSON* json = cJSON_GetArrayItem(task_module_request, 0);
    check_expected(json);

    cJSON_AddItemToArray(json_response, mock_type(cJSON *));

    return mock();
}

int __wrap_wm_agent_upgrade_parse_agent_response(const char* agent_response, char **data) {
    check_expected(agent_response);

    return mock();
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

void test_wm_agent_upgrade_send_single_task_ok(void **state)
{
    wm_upgrade_command cmd = WM_UPGRADE_AGENT_GET_STATUS;
    int agent = 18;
    char *ag_status = "In progress";
    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent);
    cJSON_AddStringToObject(task_request, "status", ag_status);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", ag_status);

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, cmd);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, ag_status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    cJSON *res = wm_agent_upgrade_send_single_task(cmd, agent, ag_status);

    *state = res;

    assert_non_null(res);
    assert_memory_equal(res, task_response, sizeof(task_response));
}

void test_wm_agent_upgrade_send_single_task_null_response(void **state)
{
    wm_upgrade_command cmd = WM_UPGRADE_AGENT_GET_STATUS;
    int agent = 18;
    char *ag_status = "In progress";
    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent);
    cJSON_AddStringToObject(task_request, "status", ag_status);

    cJSON_AddItemToArray(request, task_request);

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, cmd);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, ag_status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, NULL);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    cJSON *res = wm_agent_upgrade_send_single_task(cmd, agent, ag_status);

    *state = res;

    assert_null(res);
}

void test_wm_agent_upgrade_send_lock_restart_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 28;
    char *cmd = "028 com lock_restart -1";
    char *agent_res = "ok ";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '028 com lock_restart -1'");

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(cmd));
    expect_string(__wrap_OS_SendSecureTCP, msg, cmd);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, 0);

    int res = wm_agent_upgrade_send_lock_restart(agent);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_lock_restart_err(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 28;
    char *cmd = "028 com lock_restart -1";
    char *agent_res = "err Could not restart agent";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '028 com lock_restart -1'");

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(cmd));
    expect_string(__wrap_OS_SendSecureTCP, msg, cmd);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not restart agent'");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_lock_restart(agent);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_open_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 39;
    char *wpk_file = "test.wpk";
    char *cmd = "039 com open wb test.wpk";
    char *agent_res = "ok ";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(cmd));
    expect_string(__wrap_OS_SendSecureTCP, msg, cmd);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, 0);

    int res = wm_agent_upgrade_send_open(agent, wpk_file);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_open_retry_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 39;
    char *wpk_file = "test.wpk";
    char *cmd = "039 com open wb test.wpk";
    char *agent_res1 = "err Could not open file in agent";
    char *agent_res2 = "ok ";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(cmd));
    expect_string(__wrap_OS_SendSecureTCP, msg, cmd);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res1) + 1);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res1);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(cmd));
    expect_string(__wrap_OS_SendSecureTCP, msg, cmd);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res2);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res2) + 1);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res2);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, 0);

    int res = wm_agent_upgrade_send_open(agent, wpk_file);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_open_retry_err(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 39;
    char *wpk_file = "test.wpk";
    char *cmd = "039 com open wb test.wpk";
    char *agent_res = "err Could not open file in agent";

    will_return_count(__wrap_isChroot, 0, 10);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 10);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 10);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 10);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 10);

    expect_value_count(__wrap_OS_SendSecureTCP, sock, socket, 10);
    expect_value_count(__wrap_OS_SendSecureTCP, size, strlen(cmd), 10);
    expect_string_count(__wrap_OS_SendSecureTCP, msg, cmd, 10);
    will_return_count(__wrap_OS_SendSecureTCP, 0, 10);

    expect_value_count(__wrap_OS_RecvSecureTCP, sock, socket, 10);
    expect_value_count(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR, 10);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 20);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not open file in agent'");

    expect_value_count(__wrap_close, fd, socket, 10);

    expect_string_count(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res, 10);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID, 10);

    int res = wm_agent_upgrade_send_open(agent, wpk_file);

    assert_int_equal(res, OS_INVALID);
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
        // wm_agent_upgrade_send_single_task
        cmocka_unit_test_teardown(test_wm_agent_upgrade_send_single_task_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_send_single_task_null_response, teardown_json),
        // wm_agent_upgrade_send_lock_restart
        cmocka_unit_test(test_wm_agent_upgrade_send_lock_restart_ok),
        cmocka_unit_test(test_wm_agent_upgrade_send_lock_restart_err),
        // wm_agent_upgrade_send_open
        cmocka_unit_test(test_wm_agent_upgrade_send_open_ok),
        cmocka_unit_test(test_wm_agent_upgrade_send_open_retry_ok),
        cmocka_unit_test(test_wm_agent_upgrade_send_open_retry_err),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
