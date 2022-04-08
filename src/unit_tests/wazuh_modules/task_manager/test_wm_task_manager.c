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
#include "../../wazuh_modules/task_manager/wm_task_manager_tasks.h"
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

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_init_bind_err(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8251): Queue 'queue/tasks/task' not accessible: 'Success'. Exiting...");

    expect_assert_failure(wm_task_manager_init(config));
}

void test_wm_task_manager_init_disabled(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8202): Module disabled. Exiting...");

    expect_assert_failure(wm_task_manager_init(config));
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

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();
    int *agents = NULL;

    os_calloc(3, sizeof(int), agents);
    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_strdup("upgrade_module", task_parameters->module);
    os_strdup("node05", task_parameters->node);
    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE;
    task->parameters = task_parameters;

    cJSON *data_array = cJSON_CreateArray();

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response1, "message", "Success");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response2, "message", "Success");
    cJSON_AddNumberToObject(response2, "agent", 2);

    cJSON_AddItemToArray(data_array, response1);
    cJSON_AddItemToArray(data_array, response2);

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
    will_return(__wrap_wm_task_manager_parse_message, task);

    expect_memory(__wrap_wm_task_manager_process_task, task, task, sizeof(task));
    will_return(__wrap_wm_task_manager_process_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_process_task, data_array);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":0,\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":1},{\"error\":0,\"message\":\"Success\",\"agent\":2}],\"message\":\"Success\"}'");

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

    wm_task_manager_task *task = wm_task_manager_init_task();

    task->command = WM_TASK_UNKNOWN;

    cJSON *response_error = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_error, "error", WM_TASK_INVALID_COMMAND);
    cJSON_AddStringToObject(response_error, "message", "Invalid command");

    char *result = "{\"error\":2,\"data\":[{\"error\":2,\"message\":\"Invalid command\"}],\"message\":\"Invalid command\"}";

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
    will_return(__wrap_wm_task_manager_parse_message, task);

    expect_memory(__wrap_wm_task_manager_process_task, task, task, sizeof(task));
    will_return(__wrap_wm_task_manager_process_task, WM_TASK_INVALID_COMMAND);
    will_return(__wrap_wm_task_manager_process_task, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8258): No action defined for command provided.");

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_COMMAND);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, response_error);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":2,\"data\":[{\"error\":2,\"message\":\"Invalid command\"}],\"message\":\"Invalid command\"}'");

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
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();
    int *agents = NULL;

    os_calloc(3, sizeof(int), agents);
    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_strdup("upgrade_module", task_parameters->module);
    os_strdup("node05", task_parameters->node);
    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE;
    task->parameters = task_parameters;

    cJSON *response_error = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_error, "error", WM_TASK_DATABASE_ERROR);
    cJSON_AddStringToObject(response_error, "message", "Database error");

    char *result = "{\"error\":4,\"data\":[{\"error\":4,\"message\":\"Database error\"}],\"message\":\"Database error\"}";

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
    will_return(__wrap_wm_task_manager_parse_message, task);

    expect_memory(__wrap_wm_task_manager_process_task, task, task, sizeof(task));
    will_return(__wrap_wm_task_manager_process_task, WM_TASK_DATABASE_ERROR);
    will_return(__wrap_wm_task_manager_process_task, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Database error.");

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_ERROR);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, response_error);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":4,\"data\":[{\"error\":4,\"message\":\"Database error\"}],\"message\":\"Database error\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_db_parse_err(void **state)
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

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();
    int *agents = NULL;

    os_calloc(3, sizeof(int), agents);
    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_strdup("upgrade_module", task_parameters->module);
    os_strdup("node05", task_parameters->node);
    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE;
    task->parameters = task_parameters;

    cJSON *response_error = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_error, "error", WM_TASK_DATABASE_PARSE_ERROR);
    cJSON_AddStringToObject(response_error, "message", "Parse DB response error");

    char *result = "{\"error\":5,\"data\":[{\"error\":5,\"message\":\"Parse DB response error\"}],\"message\":\"Parse DB response error\"}";

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
    will_return(__wrap_wm_task_manager_parse_message, task);

    expect_memory(__wrap_wm_task_manager_process_task, task, task, sizeof(task));
    will_return(__wrap_wm_task_manager_process_task, WM_TASK_DATABASE_PARSE_ERROR);
    will_return(__wrap_wm_task_manager_process_task, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Database error.");

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_PARSE_ERROR);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, response_error);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":5,\"data\":[{\"error\":5,\"message\":\"Parse DB response error\"}],\"message\":\"Parse DB response error\"}'");

    int ret = wm_task_manager_dispatch(message, &response);

    state[1] = response;

    assert_int_equal(ret, strlen(result));
    assert_string_equal(response, result);
}

void test_wm_task_manager_dispatch_db_request_err(void **state)
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

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();
    int *agents = NULL;

    os_calloc(3, sizeof(int), agents);
    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_strdup("upgrade_module", task_parameters->module);
    os_strdup("node05", task_parameters->node);
    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE;
    task->parameters = task_parameters;

    cJSON *response_error = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_error, "error", WM_TASK_DATABASE_REQUEST_ERROR);
    cJSON_AddStringToObject(response_error, "message", "Error in DB request");

    char *result = "{\"error\":6,\"data\":[{\"error\":6,\"message\":\"Error in DB request\"}],\"message\":\"Error in DB request\"}";

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
    will_return(__wrap_wm_task_manager_parse_message, task);

    expect_memory(__wrap_wm_task_manager_process_task, task, task, sizeof(task));
    will_return(__wrap_wm_task_manager_process_task, WM_TASK_DATABASE_REQUEST_ERROR);
    will_return(__wrap_wm_task_manager_process_task, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8261): Database error.");

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_REQUEST_ERROR);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, response_error);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8205): Response to message: '{\"error\":6,\"data\":[{\"error\":6,\"message\":\"Error in DB request\"}],\"message\":\"Error in DB request\"}'");

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

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();
    int *agents = NULL;

    os_calloc(3, sizeof(int), agents);
    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_strdup("upgrade_module", task_parameters->module);
    os_strdup("node05", task_parameters->node);
    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE;
    task->parameters = task_parameters;

    cJSON *data_array = cJSON_CreateArray();

    cJSON *response1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response1, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response1, "message", "Success");
    cJSON_AddNumberToObject(response1, "agent", 1);

    cJSON *response2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(response2, "error", WM_TASK_SUCCESS);
    cJSON_AddStringToObject(response2, "message", "Success");
    cJSON_AddNumberToObject(response2, "agent", 2);

    cJSON_AddItemToArray(data_array, response1);
    cJSON_AddItemToArray(data_array, response2);

    char *response = "{\"error\":0,\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":1},{\"error\":0,\"message\":\"Success\",\"agent\":2}],\"message\":\"Success\"}";

    will_return(__wrap_w_is_worker, 0);

    // wm_task_manager_init

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

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
    will_return(__wrap_wm_task_manager_parse_message, task);

    expect_memory(__wrap_wm_task_manager_process_task, task, task, sizeof(task));
    will_return(__wrap_wm_task_manager_process_task, WM_TASK_SUCCESS);
    will_return(__wrap_wm_task_manager_process_task, data_array);

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

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

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

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

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

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

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

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

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

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

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

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

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

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8200): Module Task Manager started.");

    will_return(__wrap_select, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8252): Error in select(): 'Success'. Exiting...");

    expect_assert_failure(wm_task_manager_main(config));
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
        cmocka_unit_test(test_wm_task_manager_init_disabled),
        // wm_task_manager_dispatch
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_ok, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_command_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_db_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_db_parse_err, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_db_request_err, teardown_string),
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
