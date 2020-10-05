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

#include "../../wrappers/posix/pthread_wrappers.h"
#include "../../wrappers/posix/select_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/shared/cluster_op_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/pthreads_op_wrappers.h"
#include "../../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_task_manager_wrappers.h"

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

int __wrap_accept() {
    return mock();
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

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_init_bind_err(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8251): Queue '/queue/tasks/task' not accessible: 'Success'. Exiting...");

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

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
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

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_dispatch_ok(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "upgrade");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response1, "message", "Success");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response2, "message", "Success");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "{\"error\":0,\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":1},{\"error\":0,\"message\":\"Success\",\"agent\":2}],\"message\":\"Success\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"upgrade_module\""
                                                                               "   },"
                                                                               "  \"command\": \"upgrade\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [1, 2]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":1},{\"error\":0,\"message\":\"Success\",\"agent\":2}],\"message\":\"Success\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_node_err(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade_custom\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "module", "unknown");
    cJSON_AddStringToObject(task1, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task2, "module", "unknown");
    cJSON_AddStringToObject(task2, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_INVALID_NODE);
    cJSON_AddStringToObject(response1, "message", "Invalid node");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_INVALID_NODE);
    cJSON_AddStringToObject(response2, "message", "Invalid node");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "{\"error\":0,\"data\":[{\"error\":2,\"message\":\"Invalid node\",\"agent\":1},{\"error\":2,\"message\":\"Invalid node\",\"agent\":2}],\"message\":\"Success\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"module\": \"upgrade_module\""
                                                                               "   },"
                                                                               "  \"command\": \"upgrade_custom\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [1, 2]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_NODE);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Invalid 'node' at index '0'");

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_NODE);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Invalid 'node' at index '1'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":2,\"message\":\"Invalid node\",\"agent\":1},{\"error\":2,\"message\":\"Invalid node\",\"agent\":2}],\"message\":\"Success\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_module_err(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"unknown\""
                    "   },"
                    "  \"command\": \"upgrade_custom\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "unknown");
    cJSON_AddStringToObject(task1, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task2, "module", "unknown");
    cJSON_AddStringToObject(task2, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_INVALID_MODULE);
    cJSON_AddStringToObject(response1, "message", "Invalid module");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_INVALID_MODULE);
    cJSON_AddStringToObject(response2, "message", "Invalid module");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "{\"error\":0,\"data\":[{\"error\":3,\"message\":\"Invalid module\",\"agent\":1},{\"error\":3,\"message\":\"Invalid module\",\"agent\":2}],\"message\":\"Success\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"unknown\""
                                                                               "   },"
                                                                               "  \"command\": \"upgrade_custom\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [1, 2]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_MODULE);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Invalid 'module' at index '0'");

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_MODULE);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Invalid 'module' at index '1'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":3,\"message\":\"Invalid module\",\"agent\":1},{\"error\":3,\"message\":\"Invalid module\",\"agent\":2}],\"message\":\"Success\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_command_err(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"unknown\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "unknown");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "unknown");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_INVALID_COMMAND);
    cJSON_AddStringToObject(response1, "message", "Invalid command");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_INVALID_COMMAND);
    cJSON_AddStringToObject(response2, "message", "Invalid command");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "{\"error\":0,\"data\":[{\"error\":4,\"message\":\"Invalid command\",\"agent\":1},{\"error\":4,\"message\":\"Invalid command\",\"agent\":2}],\"message\":\"Success\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"upgrade_module\""
                                                                               "   },"
                                                                               "  \"command\": \"unknown\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [1, 2]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_COMMAND);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Invalid 'command' at index '0'");

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_COMMAND);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Invalid 'command' at index '1'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":4,\"message\":\"Invalid command\",\"agent\":1},{\"error\":4,\"message\":\"Invalid command\",\"agent\":2}],\"message\":\"Success\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_agent_id_err(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [\"1\", 2]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade");
    cJSON_AddStringToObject(task1, "agent", "1");

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_INVALID_AGENT_ID);
    cJSON_AddStringToObject(response1, "message", "Invalid agent");

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response2, "message", "Success");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *result = "{\"error\":0,\"data\":[{\"error\":5,\"message\":\"Invalid agent\"},{\"error\":0,\"message\":\"Success\",\"agent\":2}],\"message\":\"Success\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"upgrade_module\""
                                                                               "   },"
                                                                               "  \"command\": \"upgrade\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [\"1\", 2]"
                                                                               "   }"
                                                                               "}'");

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
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":5,\"message\":\"Invalid agent\"},{\"error\":0,\"message\":\"Success\",\"agent\":2}],\"message\":\"Success\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_task_id_err(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"api\""
                    "   },"
                    "  \"command\": \"task_result\","
                    "  \"parameters\": {"
                    "      \"agents\": [1]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "api");
    cJSON_AddStringToObject(task1, "command", "task_result");

    cJSON_AddItemToArray(tasks, task1);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_INVALID_TASK_ID);
    cJSON_AddStringToObject(response1, "message", "Invalid task");

    char *result = "{\"error\":0,\"data\":[{\"error\":6,\"message\":\"Invalid task\"}],\"message\":\"Success\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"api\""
                                                                               "   },"
                                                                               "  \"command\": \"task_result\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [1]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_TASK_ID);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8259): Invalid message. 'task_id' not found at index '0'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":6,\"message\":\"Invalid task\"}],\"message\":\"Success\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_status_err(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade_update_status\","
                    "  \"parameters\": {"
                    "      \"agents\": [2]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task1, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_INVALID_STATUS);
    cJSON_AddStringToObject(response1, "message", "Invalid status");
    cJSON_AddNumberToObject(response1, "agent", 2);

    char *result = "{\"error\":0,\"data\":[{\"error\":7,\"message\":\"Invalid status\",\"agent\":2}],\"message\":\"Success\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"upgrade_module\""
                                                                               "   },"
                                                                               "  \"command\": \"upgrade_update_status\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [2]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_INVALID_STATUS);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8259): Invalid message. 'status' not found at index '0'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":7,\"message\":\"Invalid status\",\"agent\":2}],\"message\":\"Success\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_no_task_err(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade_update_status\","
                    "  \"parameters\": {"
                    "      \"agents\": [1]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON_AddItemToArray(tasks, task1);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_DATABASE_NO_TASK);
    cJSON_AddStringToObject(response1, "message", "No task in DB");
    cJSON_AddNumberToObject(response1, "agent", 1);

    char *result = "{\"error\":0,\"data\":[{\"error\":8,\"message\":\"No task in DB\",\"agent\":1}],\"message\":\"Success\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"upgrade_module\""
                                                                               "   },"
                                                                               "  \"command\": \"upgrade_update_status\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [1]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_DATABASE_NO_TASK);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8262): Couldn't find task in DB at index '0'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":8,\"message\":\"No task in DB\",\"agent\":1}],\"message\":\"Success\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_db_err(void **state)
{
    char *response = NULL;
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade_update_status\","
                    "  \"parameters\": {"
                    "      \"agents\": [1]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON_AddItemToArray(tasks, task1);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_DATABASE_ERROR);
    cJSON_AddStringToObject(response1, "message", "Database error");

    char *result = "{\"error\":9,\"data\":[{\"error\":9,\"message\":\"Database error\"}],\"message\":\"Database error\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"upgrade_module\""
                                                                               "   },"
                                                                               "  \"command\": \"upgrade_update_status\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [1]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_DATABASE_ERROR);
    will_return(__wrap_wm_task_manager_analyze_task, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8260): Database error at index '0'");

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_ERROR);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, response1);

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
    cJSON_AddStringToObject(response_json, "message", "Invalid message");

    char *result = "{\"error\":1,\"data\":[{\"error\":1,\"message\":\"Invalid message\"}],\"message\":\"Invalid message\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: 'unknown json'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, NULL);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_MESSAGE);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, response_json);

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_main_ok(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    cJSON *tasks = cJSON_CreateArray();

    cJSON *task1 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task1, "module", "upgrade_module");
    cJSON_AddStringToObject(task1, "command", "upgrade");
    cJSON_AddNumberToObject(task1, "agent", 1);

    cJSON *task2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task1, "node", "node05");
    cJSON_AddStringToObject(task2, "module", "upgrade_module");
    cJSON_AddStringToObject(task2, "command", "upgrade");
    cJSON_AddNumberToObject(task2, "agent", 2);

    cJSON_AddItemToArray(tasks, task1);
    cJSON_AddItemToArray(tasks, task2);

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response1, "message", "Success");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response2, "message", "Success");
    cJSON_AddNumberToObject(response2, "agent", 2);

    char *response = "{\"error\":0,\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":1},{\"error\":0,\"message\":\"Success\",\"agent\":2}],\"message\":\"Success\"}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, strlen(message) + 1);

    // wm_task_manager_dispatch

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8204): Incomming message: '{"
                                                                               "  \"origin\": {"
                                                                               "      \"name\": \"node05\","
                                                                               "      \"module\": \"upgrade_module\""
                                                                               "   },"
                                                                               "  \"command\": \"upgrade\","
                                                                               "  \"parameters\": {"
                                                                               "      \"agents\": [1, 2]"
                                                                               "   }"
                                                                               "}'");

    expect_string(__wrap_wm_task_manager_parse_message, msg, message);
    will_return(__wrap_wm_task_manager_parse_message, tasks);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task1, sizeof(task1));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response1);

    expect_memory(__wrap_wm_task_manager_analyze_task, task_object, task2, sizeof(task2));
    will_return(__wrap_wm_task_manager_analyze_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_analyze_task, response2);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":1},{\"error\":0,\"message\":\"Success\",\"agent\":2}],\"message\":\"Success\"}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_recv_max_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_MAXLEN);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8256): Received message > '4194304'");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_recv_empty_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8203): Empty message from local client.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_recv_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8254): Error in recv(): 'Success'");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_sockterr_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8255): Response size is bigger than expected.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_accept_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8253): Error in accept(): 'Success'");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8255): Response size is bigger than expected.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_select_empty_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8255): Response size is bigger than expected.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_select_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    will_return(__wrap_wm_task_manager_check_db, 0);

    expect_string(__wrap_OS_BindUnixDomain, path, DEFAULTDIR TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8252): Error in select(): 'Success'. Exiting...");

    will_return(__wrap_pthread_exit, OS_INVALID);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8255): Response size is bigger than expected.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_worker_err(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    will_return(__wrap_w_is_worker, 1);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8207): Module Task Manager only runs on Master nodes in cluster configuration.");

    wm_task_manager_main(config);
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
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_node_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_module_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_command_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_agent_id_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_task_id_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_status_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_no_task_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_db_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_parse_err, teardown_string),
        // wm_task_manager_main
        cmocka_unit_test(test_wm_task_manager_main_ok),
        cmocka_unit_test(test_wm_task_manager_main_recv_max_err),
        cmocka_unit_test(test_wm_task_manager_main_recv_empty_err),
        cmocka_unit_test(test_wm_task_manager_main_recv_err),
        cmocka_unit_test(test_wm_task_manager_main_sockterr_err),
        cmocka_unit_test(test_wm_task_manager_main_accept_err),
        cmocka_unit_test(test_wm_task_manager_main_select_empty_err),
        cmocka_unit_test(test_wm_task_manager_main_select_err),
        cmocka_unit_test(test_wm_task_manager_main_worker_err)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
