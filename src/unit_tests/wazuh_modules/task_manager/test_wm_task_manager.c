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
#include "../../wazuh_modules/task_manager/wm_task_manager.h"
#include "../../headers/shared.h"

int wm_task_manager_init(wm_task_manager *task_config);
void* wm_task_manager_main(wm_task_manager* task_config);
void wm_task_manager_destroy(wm_task_manager* task_config);
cJSON* wm_task_manager_dump(const wm_task_manager* task_config);

// Setup / teardown

static int setup_group(void **state) {
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);
    *state = config;
    return 0;
}

static int teardown_group(void **state) {
    wm_task_manager *config = *state;
    os_free(config);
    return 0;
}

static int teardown_json(void **state) {
    if (state[1]) {
        cJSON *json = state[1];
        cJSON_Delete(json);
    }
    return 0;
}

static int teardown_string(void **state) {
    if (state[1]) {
        char *string = state[1];
        os_free(string);
    }
    return 0;
}

// Wrappers

void __wrap__mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

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

int __wrap_pthread_exit() {
    return mock();
}

int __wrap_wm_task_manager_check_db() {
    return mock();
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    return mock();
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

int __wrap_w_is_worker(void) {
    return mock();
}

cJSON* __wrap_wm_task_manager_parse_message(const char *msg) {
    check_expected(msg);

    return mock_type(cJSON*);
}

cJSON* __wrap_wm_task_manager_analyze_task(const cJSON *task_object, int *error_code) {
    check_expected(task_object);

    *error_code = mock();

    return mock_type(cJSON*);
}

cJSON* __wrap_wm_task_manager_parse_response(int error_code, int agent_id, int task_id, char *status) {
    check_expected(error_code);
    check_expected(agent_id);
    check_expected(task_id);
    if (status) check_expected(status);

    return mock_type(cJSON*);
}

// Tests

void test_wm_task_manager_dump_enabled(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "yes");
}

void test_wm_task_manager_dump_disabled(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 0;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "no");
}

void test_wm_task_manager_destroy(void **state)
{
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8201): Module Task Manager finished.");

    wm_task_manager_destroy(config);
}

void test_wm_task_manager_init_ok(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 1;

    will_return(__wrap_wm_task_manager_check_db, 0);

    will_return(__wrap_CreateThread, 1);

    will_return(__wrap_OS_BindUnixDomain, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_init_bind_err(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    will_return(__wrap_wm_task_manager_check_db, 0);

    will_return(__wrap_CreateThread, 1);

    will_return(__wrap_OS_BindUnixDomain, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8251): Queue '/queue/tasks/task' not accesible: 'Success'. Exiting...");

    will_return(__wrap_pthread_exit, OS_INVALID);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_init_db_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 1;

    will_return(__wrap_wm_task_manager_check_db, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8250): DB integrity is invalid. Exiting...");

    will_return(__wrap_pthread_exit, OS_INVALID);

    will_return(__wrap_CreateThread, 1);

    will_return(__wrap_OS_BindUnixDomain, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_init_disabled(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8202): Module disabled. Exiting...");

    will_return(__wrap_pthread_exit, OS_INVALID);

    will_return(__wrap_wm_task_manager_check_db, 0);

    will_return(__wrap_CreateThread, 1);

    will_return(__wrap_OS_BindUnixDomain, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_dispatch_ok(void **state)
{
    char *response = NULL;
    char *message = "[{\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade\","
                      "\"agent\":1},{"
                      "\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade_custom\","
                      "\"agent\":2}]";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response1, "data", "Success");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response2, "data", "Success");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "[{\"error\":0,\"data\":\"Success\",\"agent\":1},{\"error\":0,\"data\":\"Success\",\"agent\":2}]";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '[{\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade\","
                                                                                 "\"agent\":1},{"
                                                                                 "\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade_custom\","
                                                                                 "\"agent\":2}]'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '[{\"error\":0,\"data\":\"Success\",\"agent\":1},{\"error\":0,\"data\":\"Success\",\"agent\":2}]'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_module_err(void **state)
{
    char *response = NULL;
    char *message = "[{\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade\","
                      "\"agent\":1},{"
                      "\"module\":\"unknown\","
                      "\"command\":\"upgrade_custom\","
                      "\"agent\":2}]";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "unknown");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response1, "data", "Success");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_INVALID_MODULE);
    cJSON_AddStringToObject(response2, "data", "Invalid module");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "[{\"error\":0,\"data\":\"Success\",\"agent\":1},{\"error\":2,\"data\":\"Invalid module\",\"agent\":2}]";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '[{\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade\","
                                                                                 "\"agent\":1},{"
                                                                                 "\"module\":\"unknown\","
                                                                                 "\"command\":\"upgrade_custom\","
                                                                                 "\"agent\":2}]'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_MODULE);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Invalid 'module' at index '1'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '[{\"error\":0,\"data\":\"Success\",\"agent\":1},{\"error\":2,\"data\":\"Invalid module\",\"agent\":2}]'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_command_err(void **state)
{
    char *response = NULL;
    char *message = "[{\"module\":\"upgrade_module\","
                      "\"command\":\"unknown\","
                      "\"agent\":1},{"
                      "\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade_custom\","
                      "\"agent\":2}]";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "unknown");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_INVALID_COMMAND);
    cJSON_AddStringToObject(response1, "data", "Invalid command");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response2, "data", "Success");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "[{\"error\":3,\"data\":\"Invalid command\",\"agent\":1},{\"error\":0,\"data\":\"Success\",\"agent\":2}]";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '[{\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"unknown\","
                                                                                 "\"agent\":1},{"
                                                                                 "\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade_custom\","
                                                                                 "\"agent\":2}]'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_COMMAND);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Invalid 'command' at index '0'");

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '[{\"error\":3,\"data\":\"Invalid command\",\"agent\":1},{\"error\":0,\"data\":\"Success\",\"agent\":2}]'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_agent_id_err(void **state)
{
    char *response = NULL;
    char *message = "[{\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade\","
                      "\"agent\":\"1\"},{"
                      "\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade_custom\","
                      "\"agent\":2}]";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade");
    cJSON_AddStringToObject(task1, "agent", "1");

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_INVALID_AGENT_ID);
    cJSON_AddStringToObject(response1, "data", "Invalid agent");

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response2, "data", "Success");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "[{\"error\":4,\"data\":\"Invalid agent\"},{\"error\":0,\"data\":\"Success\",\"agent\":2}]";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '[{\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade\","
                                                                                 "\"agent\":\"1\"},{"
                                                                                 "\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade_custom\","
                                                                                 "\"agent\":2}]'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_AGENT_ID);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8259): Invalid message. 'agent' not found at index '0'");

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '[{\"error\":4,\"data\":\"Invalid agent\"},{\"error\":0,\"data\":\"Success\",\"agent\":2}]'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_task_id_err(void **state)
{
    char *response = NULL;
    char *message = "[{\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade\","
                      "\"agent\":1},{"
                      "\"module\":\"api\","
                      "\"command\":\"task_result\"}]";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task2, "module", "api");
    cJSON_AddStringToObject(task2, "command", "task_result");

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response1, "data", "Success");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_INVALID_TASK_ID);
    cJSON_AddStringToObject(response2, "data", "Invalid task");

    char *result = "[{\"error\":0,\"data\":\"Success\",\"agent\":1},{\"error\":5,\"data\":\"Invalid task\"}]";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '[{\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade\","
                                                                                 "\"agent\":1},{"
                                                                                 "\"module\":\"api\","
                                                                                 "\"command\":\"task_result\"}]'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_TASK_ID);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8259): Invalid message. 'task_id' not found at index '1'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '[{\"error\":0,\"data\":\"Success\",\"agent\":1},{\"error\":5,\"data\":\"Invalid task\"}]'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_status_err(void **state)
{
    char *response = NULL;
    char *message = "[{\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade\","
                      "\"agent\":1},{"
                      "\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade_update_status\","
                      "\"agent\":2}]";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response1, "data", "Success");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_INVALID_STATUS);
    cJSON_AddStringToObject(response2, "data", "Invalid status");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "[{\"error\":0,\"data\":\"Success\",\"agent\":1},{\"error\":6,\"data\":\"Invalid status\",\"agent\":2}]";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '[{\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade\","
                                                                                 "\"agent\":1},{"
                                                                                 "\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade_update_status\","
                                                                                 "\"agent\":2}]'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_STATUS);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8259): Invalid message. 'status' not found at index '1'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '[{\"error\":0,\"data\":\"Success\",\"agent\":1},{\"error\":6,\"data\":\"Invalid status\",\"agent\":2}]'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_no_task_err(void **state)
{
    char *response = NULL;
    char *message = "[{\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade_update_status\","
                      "\"agent\":1}]";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON_AddItemToArray(tasks, task1);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_DATABASE_NO_TASK);
    cJSON_AddStringToObject(response1, "data", "No task in DB");
    cJSON_AddNumberToObject(response1, "agent", 1);

    char *result = "[{\"error\":7,\"data\":\"No task in DB\",\"agent\":1}]";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '[{\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade_update_status\","
                                                                                 "\"agent\":1}]'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_DATABASE_NO_TASK);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8262): Couldn't find task in DB at index '0'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '[{\"error\":7,\"data\":\"No task in DB\",\"agent\":1}]'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_db_err(void **state)
{
    char *response = NULL;
    char *message = "[{\"module\":\"upgrade_module\","
                      "\"command\":\"upgrade_update_status\","
                      "\"agent\":1}]";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON_AddItemToArray(tasks, task1);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_DATABASE_ERROR);
    cJSON_AddStringToObject(response1, "data", "DB error");

    char *result = "{\"error\":8,\"data\":\"DB error\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '[{\"module\":\"upgrade_module\","
                                                                                 "\"command\":\"upgrade_update_status\","
                                                                                 "\"agent\":1}]'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_DATABASE_ERROR);
    will_return(__wrap_wm_task_manager_analyze_task, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8260): Database error at index '0'");

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_DATABASE_ERROR);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_response, response1);

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_parse_err(void **state)
{
    char *response = NULL;
    char *message = "unknown json";

    cJSON *response_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_json, "error", WM_TASK_INVALID_MESSAGE);
    cJSON_AddStringToObject(response_json, "data", "Invalid message");

    char *result = "{\"error\":1,\"data\":\"Invalid message\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: 'unknown json'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, NULL);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_MESSAGE);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_response, response_json);

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_dump
        cmocka_unit_test_teardown(test_wm_task_manager_dump_enabled, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_dump_disabled, teardown_json),
        // wm_task_manager_destroy
        cmocka_unit_test(test_wm_task_manager_destroy),
        // wm_task_manager_init
        cmocka_unit_test(test_wm_task_manager_init_ok),
        cmocka_unit_test(test_wm_task_manager_init_bind_err),
        cmocka_unit_test(test_wm_task_manager_init_db_err),
        cmocka_unit_test(test_wm_task_manager_init_disabled),
        // wm_task_manager_dispatch
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_ok, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_module_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_command_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_agent_id_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_task_id_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_status_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_no_task_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_db_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_parse_err, teardown_string),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
