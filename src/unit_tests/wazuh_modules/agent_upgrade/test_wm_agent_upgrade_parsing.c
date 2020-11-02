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

#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_parsing.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

int* wm_agent_upgrade_parse_agents(const cJSON* agents, char** error_message);
wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message);
wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char** error_message);
wm_upgrade_agent_status_task* wm_agent_upgrade_parse_upgrade_agent_status(const cJSON* params, char** error_message);

// Wrappers

int __wrap_OS_ReadXML(const char *file, OS_XML *_lxml) {
    return mock();
}

char* __wrap_OS_GetOneContentforElement(OS_XML *_lxml, const char **element_name) {
    return mock_type(char *);
}

void __wrap_OS_ClearXML(OS_XML *_lxml) {
    return;
}

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

// Tests

void test_wm_agent_upgrade_parse_data_response_complete(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int agent_id = 10;

    cJSON *response = wm_agent_upgrade_parse_data_response(error_code, message, &agent_id);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, message);
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
}

void test_wm_agent_upgrade_parse_data_response_without_agent_id(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";

    cJSON *response = wm_agent_upgrade_parse_data_response(error_code, message, NULL);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, message);
    assert_null(cJSON_GetObjectItem(response, "agent"));
}

void test_wm_agent_upgrade_parse_response_data_array(void **state) {
    int error_code = 0;
    cJSON *data = cJSON_CreateArray();

    cJSON *response = wm_agent_upgrade_parse_response(error_code, data);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_memory_equal(cJSON_GetObjectItem(response, "data"), data, sizeof(data));
}

void test_wm_agent_upgrade_parse_response_data_object(void **state) {
    int error_code = 0;
    cJSON *data = cJSON_CreateObject();

    cJSON *response = wm_agent_upgrade_parse_response(error_code, data);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_memory_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(response, "data"), 0), data, sizeof(data));
}

void test_wm_agent_upgrade_parse_task_module_request_complete(void **state)
{
    int command = 1;
    char *node = NULL;
    char *status = "Failed";
    char *error = "Error string";

    os_strdup("node00", node);

    cJSON *agent_array = cJSON_CreateArray();
    cJSON_AddItemToArray(agent_array, cJSON_CreateNumber(10));
    cJSON_AddItemToArray(agent_array, cJSON_CreateNumber(11));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node);

    cJSON *response = wm_agent_upgrade_parse_task_module_request(command, agent_array, status, error);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "origin"));
    cJSON *origin = cJSON_GetObjectItem(response, "origin");
    assert_non_null(cJSON_GetObjectItem(origin, "name"));
    assert_string_equal(cJSON_GetObjectItem(origin, "name")->valuestring, "node00");
    assert_non_null(cJSON_GetObjectItem(origin, "module"));
    assert_string_equal(cJSON_GetObjectItem(origin, "module")->valuestring, "upgrade_module");
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, "upgrade_custom");
    assert_non_null(cJSON_GetObjectItem(response, "parameters"));
    cJSON *parameters = cJSON_GetObjectItem(response, "parameters");
    assert_non_null(cJSON_GetObjectItem(parameters, "agents"));
    assert_int_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 0)->valueint, 10);
    assert_int_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 1)->valueint, 11);
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 2));
    assert_non_null(cJSON_GetObjectItem(parameters, "status"));
    assert_string_equal(cJSON_GetObjectItem(parameters, "status")->valuestring, status);
    assert_non_null(cJSON_GetObjectItem(parameters, "error_msg"));
    assert_string_equal(cJSON_GetObjectItem(parameters, "error_msg")->valuestring, error);
}

void test_wm_agent_upgrade_parse_task_module_request_without_status_and_error(void **state)
{
    int command = 1;
    char *node = NULL;

    os_strdup("node00", node);

    cJSON *agent_array = cJSON_CreateArray();
    cJSON_AddItemToArray(agent_array, cJSON_CreateNumber(10));
    cJSON_AddItemToArray(agent_array, cJSON_CreateNumber(11));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node);

    cJSON *response = wm_agent_upgrade_parse_task_module_request(command, agent_array, NULL, NULL);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "origin"));
    cJSON *origin = cJSON_GetObjectItem(response, "origin");
    assert_non_null(cJSON_GetObjectItem(origin, "name"));
    assert_string_equal(cJSON_GetObjectItem(origin, "name")->valuestring, "node00");
    assert_non_null(cJSON_GetObjectItem(origin, "module"));
    assert_string_equal(cJSON_GetObjectItem(origin, "module")->valuestring, "upgrade_module");
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, "upgrade_custom");
    assert_non_null(cJSON_GetObjectItem(response, "parameters"));
    cJSON *parameters = cJSON_GetObjectItem(response, "parameters");
    assert_non_null(cJSON_GetObjectItem(parameters, "agents"));
    assert_int_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 0)->valueint, 10);
    assert_int_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 1)->valueint, 11);
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 2));
    assert_null(cJSON_GetObjectItem(parameters, "status"));
    assert_null(cJSON_GetObjectItem(parameters, "error_msg"));
}

void test_wm_agent_upgrade_parse_task_module_request_xml_error(void **state)
{
    int command = 1;

    cJSON *agent_array = cJSON_CreateArray();
    cJSON_AddItemToArray(agent_array, cJSON_CreateNumber(10));
    cJSON_AddItemToArray(agent_array, cJSON_CreateNumber(11));

    will_return(__wrap_OS_ReadXML, -1);

    cJSON *response = wm_agent_upgrade_parse_task_module_request(command, agent_array, NULL, NULL);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "origin"));
    cJSON *origin = cJSON_GetObjectItem(response, "origin");
    assert_non_null(cJSON_GetObjectItem(origin, "name"));
    assert_string_equal(cJSON_GetObjectItem(origin, "name")->valuestring, "");
    assert_non_null(cJSON_GetObjectItem(origin, "module"));
    assert_string_equal(cJSON_GetObjectItem(origin, "module")->valuestring, "upgrade_module");
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, "upgrade_custom");
    assert_non_null(cJSON_GetObjectItem(response, "parameters"));
    cJSON *parameters = cJSON_GetObjectItem(response, "parameters");
    assert_non_null(cJSON_GetObjectItem(parameters, "agents"));
    assert_int_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 0)->valueint, 10);
    assert_int_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 1)->valueint, 11);
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(parameters, "agents"), 2));
    assert_null(cJSON_GetObjectItem(parameters, "status"));
    assert_null(cJSON_GetObjectItem(parameters, "error_msg"));
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

void test_wm_agent_upgrade_parse_agent_response_ok_null_data(void **state)
{
    (void) state;
    char *response = "ok 1234567890";

    int ret = wm_agent_upgrade_parse_agent_response(response, NULL);

    assert_int_equal(ret, 0);
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

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "wpk_repo", repo);
    cJSON_AddStringToObject(params, "version", ver);
    cJSON_AddTrueToObject(params, "use_http");
    cJSON_AddTrueToObject(params, "force_upgrade");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = (void*)upgrade_task;
    state[2] = NULL;

    assert_non_null(upgrade_task);
    assert_string_equal(upgrade_task->wpk_repository, repo);
    assert_string_equal(upgrade_task->custom_version, ver);
    assert_int_equal(upgrade_task->use_http, true);
    assert_int_equal(upgrade_task->force_upgrade, true);
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
    assert_int_equal(upgrade_task->use_http, false);
    assert_int_equal(upgrade_task->force_upgrade, false);
    assert_null(upgrade_task->wpk_file);
    assert_null(upgrade_task->wpk_sha1);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_repo_type(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddTrueToObject(params, "use_http");
    cJSON_AddFalseToObject(params, "force_upgrade");
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

    cJSON *params = cJSON_CreateObject();
    cJSON_AddFalseToObject(params, "use_http");
    cJSON_AddTrueToObject(params, "force_upgrade");
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
    cJSON_AddNumberToObject(params, "use_http", 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"use_http\" should be true or false'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"use_http\" should be true or false");
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_force(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "force_upgrade", 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"force_upgrade\" should be true or false'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"force_upgrade\" should be true or false");
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
    cJSON_AddStringToObject(params, "message", data);
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
    cJSON_AddNumberToObject(params, "message", 123);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"message\" should be a string'");

    wm_upgrade_agent_status_task* agent_status_task = wm_agent_upgrade_parse_upgrade_agent_status(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"message\" should be a string");
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
    cJSON_AddStringToObject(path, "message", data);
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

void test_wm_agent_upgrade_parse_message_upgrade_success(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_task* upgrade_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade\","
                   "   \"parameters\": {"
                   "        \"agents\": [1,15,24],"
                   "        \"wpk_repo\":\"wazuh.com\","
                   "        \"version\":\"v4.0.0\","
                   "        \"use_http\":false,"
                   "        \"force_upgrade\":true"
                   "    }"
                   "}";

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, WM_UPGRADE_UPGRADE);
    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 1);
    assert_int_equal(agent_ids[1], 15);
    assert_int_equal(agent_ids[2], 24);
    assert_int_equal(agent_ids[3], -1);
    assert_non_null(upgrade_task);
    assert_string_equal(upgrade_task->wpk_repository, "wazuh.com");
    assert_string_equal(upgrade_task->custom_version, "v4.0.0");
    assert_int_equal(upgrade_task->use_http, 0);
    assert_int_equal(upgrade_task->force_upgrade, 1);
    assert_null(upgrade_task->wpk_file);
    assert_null(upgrade_task->wpk_sha1);
    assert_null(error);

    wm_agent_upgrade_free_upgrade_task(upgrade_task);
}

void test_wm_agent_upgrade_parse_message_upgrade_agent_error(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_task* upgrade_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade\","
                   "   \"parameters\": {"
                   "        \"agents\": [1,15,\"24\"],"
                   "        \"wpk_repo\":\"wazuh.com\","
                   "        \"version\":\"v4.0.0\","
                   "        \"use_http\":false,"
                   "        \"force_upgrade\":true"
                   "    }"
                   "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Agent id not recognized'");

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_null(agent_ids);
    assert_null(upgrade_task);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":3,\"data\":[{\"error\":3,\"message\":\"Agent id not recognized\"}],\"message\":\"JSON parameter not recognized\"}");
}

void test_wm_agent_upgrade_parse_message_upgrade_task_error(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_task* upgrade_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade\","
                   "   \"parameters\": {"
                   "        \"agents\": [1,15,24],"
                   "        \"wpk_repo\":\"wazuh.com\","
                   "        \"version\":\"v4.0.0\","
                   "        \"use_http\":\"yes\","
                   "        \"force_upgrade\":true"
                   "    }"
                   "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"use_http\" should be true or false'");

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 1);
    assert_int_equal(agent_ids[1], 15);
    assert_int_equal(agent_ids[2], 24);
    assert_int_equal(agent_ids[3], -1);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":3,\"data\":[{\"error\":3,\"message\":\"Parameter \\\"use_http\\\" should be true or false\"}],\"message\":\"JSON parameter not recognized\"}");
}

void test_wm_agent_upgrade_parse_message_upgrade_custom_success(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_custom_task* upgrade_custom_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade_custom\","
                   "   \"parameters\": {"
                   "        \"agents\":[1,15,24],"
                   "        \"file_path\":\"wazuh.wpk\","
                   "        \"installer\":\"install.sh\""
                   "    }"
                   "}";

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_custom_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, WM_UPGRADE_UPGRADE_CUSTOM);
    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 1);
    assert_int_equal(agent_ids[1], 15);
    assert_int_equal(agent_ids[2], 24);
    assert_int_equal(agent_ids[3], -1);
    assert_non_null(upgrade_custom_task);
    assert_string_equal(upgrade_custom_task->custom_file_path, "wazuh.wpk");
    assert_string_equal(upgrade_custom_task->custom_installer, "install.sh");
    assert_null(error);

    wm_agent_upgrade_free_upgrade_custom_task(upgrade_custom_task);
}

void test_wm_agent_upgrade_parse_message_upgrade_custom_agent_error(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_custom_task* upgrade_custom_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade_custom\","
                   "   \"parameters\": {"
                   "        \"agents\":[1,\"15\",24],"
                   "        \"file_path\":\"wazuh.wpk\","
                   "        \"installer\":\"install.sh\""
                   "    }"
                   "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Agent id not recognized'");

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_custom_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_null(agent_ids);
    assert_null(upgrade_custom_task);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":3,\"data\":[{\"error\":3,\"message\":\"Agent id not recognized\"}],\"message\":\"JSON parameter not recognized\"}");
}

void test_wm_agent_upgrade_parse_message_upgrade_custom_task_error(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_custom_task* upgrade_custom_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade_custom\","
                   "   \"parameters\": {"
                   "        \"agents\":[1,15,24],"
                   "        \"file_path\":\"wazuh.wpk\","
                   "        \"installer\":123"
                   "    }"
                   "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"installer\" should be a string'");

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_custom_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 1);
    assert_int_equal(agent_ids[1], 15);
    assert_int_equal(agent_ids[2], 24);
    assert_int_equal(agent_ids[3], -1);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":3,\"data\":[{\"error\":3,\"message\":\"Parameter \\\"installer\\\" should be a string\"}],\"message\":\"JSON parameter not recognized\"}");
}

void test_wm_agent_upgrade_parse_message_upgrade_agent_status_success(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_agent_status_task* upgrade_agent_status_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade_update_status\","
                   "   \"parameters\": {"
                   "        \"agents\":[10],"
                   "        \"error\":0,"
                   "        \"message\":\"Success\","
                   "        \"status\":\"Done\""
                   "    }"
                   "}";

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_agent_status_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 10);
    assert_int_equal(agent_ids[1], -1);
    assert_non_null(upgrade_agent_status_task);
    assert_int_equal(upgrade_agent_status_task->error_code, 0);
    assert_string_equal(upgrade_agent_status_task->message, "Success");
    assert_string_equal(upgrade_agent_status_task->status, "Done");
    assert_null(error);

    wm_agent_upgrade_free_agent_status_task(upgrade_agent_status_task);
}

void test_wm_agent_upgrade_parse_message_upgrade_agent_status_agent_error(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_agent_status_task* upgrade_agent_status_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade_update_status\","
                   "   \"parameters\": {"
                   "        \"agents\":[\"10\"],"
                   "        \"error\":0,"
                   "        \"message\":\"Success\","
                   "        \"status\":\"Done\""
                   "    }"
                   "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Agent id not recognized'");

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_agent_status_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_null(agent_ids);
    assert_null(upgrade_agent_status_task);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":3,\"data\":[{\"error\":3,\"message\":\"Agent id not recognized\"}],\"message\":\"JSON parameter not recognized\"}");
}

void test_wm_agent_upgrade_parse_message_upgrade_agent_status_task_error(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    wm_upgrade_agent_status_task* upgrade_agent_status_task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade_update_status\","
                   "   \"parameters\": {"
                   "        \"agents\":[10],"
                   "        \"error\":0,"
                   "        \"message\":666,"
                   "        \"status\":\"Done\""
                   "    }"
                   "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"message\" should be a string'");

    int command = wm_agent_upgrade_parse_message(buffer, (void*)&upgrade_agent_status_task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 10);
    assert_int_equal(agent_ids[1], -1);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":3,\"data\":[{\"error\":3,\"message\":\"Parameter \\\"message\\\" should be a string\"}],\"message\":\"JSON parameter not recognized\"}");
}

void test_wm_agent_upgrade_parse_message_invalid_command(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    void* task = NULL;
    char *buffer = "{"
                   "   \"command\": \"unknown\","
                   "   \"parameters\": {"
                   "        \"agents\":[10]"
                   "    }"
                   "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8102): No action defined for command: 'unknown'");

    int command = wm_agent_upgrade_parse_message(buffer, &task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_null(agent_ids);
    assert_null(task);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":3,\"data\":[{\"error\":3,\"message\":\"JSON parameter not recognized\"}],\"message\":\"JSON parameter not recognized\"}");
}

void test_wm_agent_upgrade_parse_message_invalid_agents(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    void* task = NULL;
    char *buffer = "{"
                   "   \"command\": \"upgrade\","
                   "   \"parameters\": {"
                   "        \"agents\":[]"
                   "    }"
                   "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8107): Required parameters in message are missing.");

    int command = wm_agent_upgrade_parse_message(buffer, &task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_null(agent_ids);
    assert_null(task);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":2,\"data\":[{\"error\":2,\"message\":\"Required parameters in json message where not found\"}],\"message\":\"Required parameters in json message where not found\"}");
}

void test_wm_agent_upgrade_parse_message_invalid_json(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    void* task = NULL;
    char *buffer = "unknown";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8101): Cannot parse JSON: 'unknown'");

    int command = wm_agent_upgrade_parse_message(buffer, &task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_null(agent_ids);
    assert_null(task);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":1,\"data\":[{\"error\":1,\"message\":\"Could not parse message JSON\"}],\"message\":\"Could not parse message JSON\"}");
}

void test_wm_agent_upgrade_parse_message_missing_required(void **state)
{
    char *error = NULL;
    int* agent_ids = NULL;
    void* task = NULL;
    char *buffer = "{}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8107): Required parameters in message are missing.");

    int command = wm_agent_upgrade_parse_message(buffer, &task, &agent_ids, &error);

    state[0] = (void*)error;
    state[1] = (void*)agent_ids;
    state[2] = NULL;

    assert_int_equal(command, OS_INVALID);
    assert_null(agent_ids);
    assert_null(task);
    assert_non_null(error);
    assert_string_equal(error, "{\"error\":2,\"data\":[{\"error\":2,\"message\":\"Required parameters in json message where not found\"}],\"message\":\"Required parameters in json message where not found\"}");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_agent_upgrade_parse_data_response
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_data_response_complete, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_data_response_without_agent_id, teardown_json),
        // wm_agent_upgrade_parse_response
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_data_array, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_data_object, teardown_json),
        // wm_agent_upgrade_parse_task_module_request
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_task_module_request_complete, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_task_module_request_without_status_and_error, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_task_module_request_xml_error, teardown_json),
        // wm_agent_upgrade_parse_agent_response
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_ok_with_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_ok_without_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_ok_null_data),
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
        // wm_agent_upgrade_parse_message
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_success, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_agent_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_task_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_custom_success, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_custom_agent_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_custom_task_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_agent_status_success, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_agent_status_agent_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_agent_status_task_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_invalid_command, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_invalid_agents, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_invalid_json, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_missing_required, teardown_parse_agents)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
