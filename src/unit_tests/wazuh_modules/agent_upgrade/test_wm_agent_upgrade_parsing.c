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
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_parsing.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

#ifdef TEST_SERVER

int* wm_agent_upgrade_parse_agents(const cJSON* agents, char** error_message);
wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message);
wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char** error_message);
wm_upgrade_agent_status_task* wm_agent_upgrade_parse_upgrade_agent_status(const cJSON* params, char** error_message);

#endif

// Setup / teardown

static int teardown_json(void **state) {
    if (*state) {
        cJSON *json = *state;
        cJSON_Delete(json);
    }
    return 0;
}

static int teardown_parse_agents(void **state) {
    if (state[0]) {
        char *error = (char*)state[0];
        os_free(error);
    }
    if (state[1]) {
        int *ids = (int*)state[1];
        os_free(ids);
    }
    return 0;
}

static int teardown_parse_upgrade(void **state) {
    if (state[0]) {
        char *error = (char*)state[0];
        os_free(error);
    }
    if (state[1]) {
        wm_upgrade_task *task = (wm_upgrade_task*)state[1];
        wm_agent_upgrade_free_upgrade_task(task);
    }
    return 0;
}

static int teardown_parse_upgrade_custom(void **state) {
    if (state[0]) {
        char *error = (char*)state[0];
        os_free(error);
    }
    if (state[1]) {
        wm_upgrade_custom_task *task = (wm_upgrade_custom_task*)state[1];
        wm_agent_upgrade_free_upgrade_custom_task(task);
    }
    return 0;
}

static int teardown_parse_upgrade_agent_status(void **state) {
    if (state[0]) {
        char *error = (char*)state[0];
        os_free(error);
    }
    if (state[1]) {
        wm_upgrade_agent_status_task *task = (wm_upgrade_agent_status_task*)state[1];
        wm_agent_upgrade_free_agent_status_task(task);
    }
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

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_parse_response_message_complete(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int agent_id = 10;
    int task_id = 25;
    char *status = "Done";

    cJSON *response = wm_agent_upgrade_parse_response_message(error_code, message, &agent_id, &task_id, status);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, message);
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_agent_upgrade_parse_response_message_without_status(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int agent_id = 10;
    int task_id = 25;

    cJSON *response = wm_agent_upgrade_parse_response_message(error_code, message, &agent_id, &task_id, NULL);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, message);
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_null(cJSON_GetObjectItem(response, "status"));
}

void test_wm_agent_upgrade_parse_response_message_without_task_id(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int agent_id = 10;
    char *status = "Done";

    cJSON *response = wm_agent_upgrade_parse_response_message(error_code, message, &agent_id, NULL, status);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, message);
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_null(cJSON_GetObjectItem(response, "task_id"));
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_agent_upgrade_parse_response_message_without_agent_id(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int task_id = 25;
    char *status = "Done";

    cJSON *response = wm_agent_upgrade_parse_response_message(error_code, message, NULL, &task_id, status);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, message);
    assert_null(cJSON_GetObjectItem(response, "agent"));
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_agent_upgrade_parse_task_module_request_complete(void **state)
{
    int command = 1;
    int agent_id = 10;
    char *status = "Done";

    cJSON *response = wm_agent_upgrade_parse_task_module_request(command, agent_id, status);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, "upgrade_module");
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, "upgrade_custom");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_agent_upgrade_parse_task_module_request_without_status(void **state)
{
    int command = 1;
    int agent_id = 10;

    cJSON *response = wm_agent_upgrade_parse_task_module_request(command, agent_id, NULL);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, "upgrade_module");
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, "upgrade_custom");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_null(cJSON_GetObjectItem(response, "status"));
}

void test_wm_agent_upgrade_parse_agent_response_ok_with_data(void **state)
{
    (void) state;
    char *response = "ok 1234567890";
    char *data = NULL;

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, 0);
    assert_string_equal(data, "1234567890");
}

void test_wm_agent_upgrade_parse_agent_response_ok_without_data(void **state)
{
    (void) state;
    char *response = "ok ";
    char *data = NULL;

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, 0);
    assert_string_equal(data, "");
}

void test_wm_agent_upgrade_parse_agent_response_err_with_data(void **state)
{
    (void) state;
    char *response = "err invalid request";
    char *data = NULL;

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8116): Error response from agent: 'invalid request'");

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, -1);
    assert_null(data);
}

void test_wm_agent_upgrade_parse_agent_response_err_without_data(void **state)
{
    (void) state;
    char *response = "err ";
    char *data = NULL;

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8116): Error response from agent: ''");

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, -1);
    assert_null(data);
}

void test_wm_agent_upgrade_parse_agent_response_unknown_response(void **state)
{
    (void) state;
    char *response = "unknown";
    char *data = NULL;

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, -1);
    assert_null(data);
}

void test_wm_agent_upgrade_parse_agent_response_invalid_response(void **state)
{
    (void) state;
    char *data = NULL;

    int ret = wm_agent_upgrade_parse_agent_response(NULL, &data);

    assert_int_equal(ret, -1);
    assert_null(data);
}

void test_wm_agent_upgrade_parse_agents_success(void **state)
{
    char *error = NULL;

    cJSON *agents = cJSON_CreateArray();
    cJSON *agent1 = cJSON_CreateNumber(15);
    cJSON *agent2 = cJSON_CreateNumber(23);
    cJSON *agent3 = cJSON_CreateNumber(8);
    cJSON_AddItemToArray(agents, agent1);
    cJSON_AddItemToArray(agents, agent2);
    cJSON_AddItemToArray(agents, agent3);

    int* agent_ids = wm_agent_upgrade_parse_agents(agents, &error);

    cJSON_Delete(agents);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 15);
    assert_int_equal(agent_ids[1], 23);
    assert_int_equal(agent_ids[2], 8);
    assert_int_equal(agent_ids[3], -1);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_agents_type_error(void **state)
{
    char *error = NULL;

    cJSON *agents = cJSON_CreateArray();
    cJSON *agent1 = cJSON_CreateNumber(15);
    cJSON *agent2 = cJSON_CreateString("23");
    cJSON *agent3 = cJSON_CreateNumber(8);
    cJSON_AddItemToArray(agents, agent1);
    cJSON_AddItemToArray(agents, agent2);
    cJSON_AddItemToArray(agents, agent3);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Agent id not recognized'");

    int* agent_ids = wm_agent_upgrade_parse_agents(agents, &error);

    cJSON_Delete(agents);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_string_equal(error, "Agent id not recognized");
}

void test_wm_agent_upgrade_parse_agents_empty(void **state)
{
    char *error = NULL;

    cJSON *agents = cJSON_CreateArray();

    int* agent_ids = wm_agent_upgrade_parse_agents(agents, &error);

    cJSON_Delete(agents);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], -1);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_command_success(void **state)
{
    char *error = NULL;
    char *repo = "wazuh.com";
    char *ver = "v4.0.0";
    bool http = false;
    bool force = false;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "wpk_repo", repo);
    cJSON_AddStringToObject(params, "version", ver);
    cJSON_AddNumberToObject(params, "use_http", http);
    cJSON_AddNumberToObject(params, "force_upgrade", force);

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = (void*)upgrade_task;
    state[2] = NULL;

    assert_non_null(upgrade_task);
    assert_string_equal(upgrade_task->wpk_repository, repo);
    assert_string_equal(upgrade_task->custom_version, ver);
    assert_int_equal(upgrade_task->use_http, http);
    assert_int_equal(upgrade_task->force_upgrade, force);
    assert_null(upgrade_task->wpk_file);
    assert_null(upgrade_task->wpk_sha1);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_command_default(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = (void*)upgrade_task;
    state[2] = NULL;

    assert_non_null(upgrade_task);
    assert_null(upgrade_task->wpk_repository);
    assert_null(upgrade_task->custom_version);
    assert_int_equal(upgrade_task->use_http, 0);
    assert_int_equal(upgrade_task->force_upgrade, 0);
    assert_null(upgrade_task->wpk_file);
    assert_null(upgrade_task->wpk_sha1);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_repo_type(void **state)
{
    char *error = NULL;
    bool http = true;
    bool force = false;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "use_http", http);
    cJSON_AddNumberToObject(params, "force_upgrade", force);
    cJSON_AddNumberToObject(params, "wpk_repo", 555);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"wpk_repo\" should be a string'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"wpk_repo\" should be a string");
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_version_type(void **state)
{
    char *error = NULL;
    bool http = false;
    bool force = true;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "use_http", http);
    cJSON_AddNumberToObject(params, "force_upgrade", force);
    cJSON_AddNumberToObject(params, "version", 111);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"version\" should be a string'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"version\" should be a string");
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_http(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "use_http", 5);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"use_http\" can take only values [0, 1]'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"use_http\" can take only values [0, 1]");
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_force(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "force_upgrade", 5);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"force_upgrade\" can take only values [0, 1]'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"force_upgrade\" can take only values [0, 1]");
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_json(void **state)
{
    char *error = NULL;
    char *repo = "wazuh.com";
    char *ver = "v4.0.0";
    bool http = false;
    bool force = false;

    cJSON *params = cJSON_CreateArray();
    cJSON *wpk_repo = cJSON_CreateObject();
    cJSON *version = cJSON_CreateObject();
    cJSON *use_http = cJSON_CreateObject();
    cJSON *force_upgrade = cJSON_CreateObject();
    cJSON_AddStringToObject(wpk_repo, "wpk_repo", repo);
    cJSON_AddStringToObject(version, "version", ver);
    cJSON_AddNumberToObject(use_http, "use_http", http);
    cJSON_AddNumberToObject(force_upgrade, "force_upgrade", force);
    cJSON_AddItemToArray(params, wpk_repo);
    cJSON_AddItemToArray(params, version);
    cJSON_AddItemToArray(params, use_http);
    cJSON_AddItemToArray(params, force_upgrade);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Invalid JSON type'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Invalid JSON type");
}

void test_wm_agent_upgrade_parse_upgrade_custom_command_success(void **state)
{
    char *error = NULL;
    char *file = "wazuh.wpk";
    char *exe = "install.sh";

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "file_path", file);
    cJSON_AddStringToObject(params, "installer", exe);

    wm_upgrade_custom_task* upgrade_custom_task = wm_agent_upgrade_parse_upgrade_custom_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = (void*)upgrade_custom_task;
    state[2] = NULL;

    assert_non_null(upgrade_custom_task);
    assert_string_equal(upgrade_custom_task->custom_file_path, file);
    assert_string_equal(upgrade_custom_task->custom_installer, exe);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_custom_command_default(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();

    wm_upgrade_custom_task* upgrade_custom_task = wm_agent_upgrade_parse_upgrade_custom_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = (void*)upgrade_custom_task;
    state[2] = NULL;

    assert_non_null(upgrade_custom_task);
    assert_null(upgrade_custom_task->custom_file_path);
    assert_null(upgrade_custom_task->custom_installer);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_file_type(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "file_path", 789);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"file_path\" should be a string'");

    wm_upgrade_custom_task* upgrade_custom_task = wm_agent_upgrade_parse_upgrade_custom_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"file_path\" should be a string");
}

void test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_installer_type(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "installer", 456);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"installer\" should be a string'");

    wm_upgrade_custom_task* upgrade_custom_task = wm_agent_upgrade_parse_upgrade_custom_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"installer\" should be a string");
}

void test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_json(void **state)
{
    char *error = NULL;
    char *file = "wazuh.wpk";
    char *exe = "install.sh";

    cJSON *params = cJSON_CreateArray();
    cJSON *file_path = cJSON_CreateObject();
    cJSON *installer = cJSON_CreateObject();
    cJSON_AddStringToObject(file_path, "file_path", file);
    cJSON_AddStringToObject(installer, "installer", exe);
    cJSON_AddItemToArray(params, file_path);
    cJSON_AddItemToArray(params, installer);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Invalid JSON type'");

    wm_upgrade_custom_task* upgrade_custom_task = wm_agent_upgrade_parse_upgrade_custom_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Invalid JSON type");
}

void test_wm_agent_upgrade_parse_upgrade_agent_status_success(void **state)
{
    char *error = NULL;
    int error_code = 0;
    char *data = "Success";
    char *status = "Done";

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "error", error_code);
    cJSON_AddStringToObject(params, "data", data);
    cJSON_AddStringToObject(params, "status", status);

    wm_upgrade_agent_status_task* agent_status_task = wm_agent_upgrade_parse_upgrade_agent_status(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = (void*)agent_status_task;
    state[2] = NULL;

    assert_non_null(agent_status_task);
    assert_int_equal(agent_status_task->error_code, error_code);
    assert_string_equal(agent_status_task->message, data);
    assert_string_equal(agent_status_task->status, status);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_agent_status_default(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();

    wm_upgrade_agent_status_task* agent_status_task = wm_agent_upgrade_parse_upgrade_agent_status(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = (void*)agent_status_task;
    state[2] = NULL;

    assert_non_null(agent_status_task);
    assert_int_equal(agent_status_task->error_code, 0);
    assert_null(agent_status_task->message);
    assert_null(agent_status_task->status);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_agent_status_invalid_code_type(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "error", "0");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"error\" should be a number'");

    wm_upgrade_agent_status_task* agent_status_task = wm_agent_upgrade_parse_upgrade_agent_status(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"error\" should be a number");
}

void test_wm_agent_upgrade_parse_upgrade_agent_status_invalid_data_type(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "data", 123);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"data\" should be a string'");

    wm_upgrade_agent_status_task* agent_status_task = wm_agent_upgrade_parse_upgrade_agent_status(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"data\" should be a string");
}

void test_wm_agent_upgrade_parse_upgrade_agent_status_invalid_status_type(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "status", 555);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"status\" should be a string'");

    wm_upgrade_agent_status_task* agent_status_task = wm_agent_upgrade_parse_upgrade_agent_status(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"status\" should be a string");
}

void test_wm_agent_upgrade_parse_upgrade_agent_status_invalid_json(void **state)
{
    char *error = NULL;
    int error_code = 0;
    char *data = "Success";

    cJSON *params = cJSON_CreateObject();
    cJSON *code = cJSON_CreateObject();
    cJSON *path = cJSON_CreateObject();
    cJSON_AddNumberToObject(code, "error", error_code);
    cJSON_AddStringToObject(path, "data", data);
    cJSON_AddItemToArray(params, code);
    cJSON_AddItemToArray(params, path);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Invalid JSON type'");

    wm_upgrade_agent_status_task* agent_status_task = wm_agent_upgrade_parse_upgrade_agent_status(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Invalid JSON type");
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        // wm_agent_upgrade_parse_response_message
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_message_complete, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_message_without_status, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_message_without_task_id, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_message_without_agent_id, teardown_json),
        // wm_agent_upgrade_parse_task_module_request
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_task_module_request_complete, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_task_module_request_without_status, teardown_json),
        // wm_agent_upgrade_parse_agent_response
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_ok_with_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_ok_without_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_err_with_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_err_without_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_unknown_response),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_invalid_response),
        // wm_agent_upgrade_parse_agents
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_agents_success, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_agents_type_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_agents_empty, teardown_parse_agents),
        // wm_agent_upgrade_parse_upgrade_command
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_success, teardown_parse_upgrade),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_default, teardown_parse_upgrade),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_invalid_repo_type, teardown_parse_upgrade),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_invalid_version_type, teardown_parse_upgrade),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_invalid_http, teardown_parse_upgrade),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_invalid_force, teardown_parse_upgrade),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_invalid_json, teardown_parse_upgrade),
        // wm_agent_upgrade_parse_upgrade_custom_command
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_success, teardown_parse_upgrade_custom),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_default, teardown_parse_upgrade_custom),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_file_type, teardown_parse_upgrade_custom),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_installer_type, teardown_parse_upgrade_custom),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_json, teardown_parse_upgrade_custom),
        // wm_agent_upgrade_parse_upgrade_agent_status
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_agent_status_success, teardown_parse_upgrade_agent_status),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_agent_status_default, teardown_parse_upgrade_agent_status),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_agent_status_invalid_code_type, teardown_parse_upgrade_agent_status),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_agent_status_invalid_data_type, teardown_parse_upgrade_agent_status),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_agent_status_invalid_status_type, teardown_parse_upgrade_agent_status),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_agent_status_invalid_json, teardown_parse_upgrade_agent_status),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
