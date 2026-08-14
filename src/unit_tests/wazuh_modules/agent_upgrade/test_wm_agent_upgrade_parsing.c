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

#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "wmodules.h"
#include "wm_agent_upgrade_parsing.h"
#include "shared.h"

int* wm_agent_upgrade_parse_agents(const cJSON* agents, char** error_message);
wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message);
wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char** error_message);

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

static int teardown_string(void **state) {
    char *string = *state;
    os_free(string);
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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
    char *package_type = "rpm";

    /* Each key is added twice: cJSON keeps duplicates, so the parser must end up with the last one */
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "wpk_repo", "duplicate");
    cJSON_AddStringToObject(params, "wpk_repo", repo);
    cJSON_AddStringToObject(params, "version", "duplicate");
    cJSON_AddStringToObject(params, "version", ver);
    cJSON_AddTrueToObject(params, "use_http");
    cJSON_AddTrueToObject(params, "force_upgrade");
    cJSON_AddStringToObject(params, "package_type", "deb");
    cJSON_AddStringToObject(params, "package_type", package_type);
    cJSON_AddNumberToObject(params, "request_time", 1234567890);

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
    assert_string_equal(upgrade_task->package_type, package_type);
    assert_null(upgrade_task->wpk_file);
    assert_null(upgrade_task->wpk_sha1);
    assert_null(error);
}

void test_wm_agent_upgrade_parse_upgrade_command_default(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "request_time", 1234567890);

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
    assert_null(upgrade_task->package_type);
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"force_upgrade\" should be true or false'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"force_upgrade\" should be true or false");
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_package_type(void **state)
{
    char *error = NULL;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "package_type", 123);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Parameter \"package_type\" should be a string'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Parameter \"package_type\" should be a string");
}

void test_wm_agent_upgrade_parse_upgrade_command_invalid_package_type_value(void **state)
{
    char *error = NULL;
    char *package_type = "msi";

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "package_type", package_type);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Invalid parameter \"package_type\", value should be \"rpm\" or \"deb\"'");

    wm_upgrade_task* upgrade_task = wm_agent_upgrade_parse_upgrade_command(params, &error);

    cJSON_Delete(params);

    state[0] = (void*)error;
    state[1] = NULL;

    assert_non_null(error);
    assert_string_equal(error, "Invalid parameter \"package_type\", value should be \"rpm\" or \"deb\"");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    /* Each key is added twice: cJSON keeps duplicates, so the parser must end up with the last one */
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "file_path", "duplicate");
    cJSON_AddStringToObject(params, "file_path", file);
    cJSON_AddStringToObject(params, "installer", "duplicate");
    cJSON_AddStringToObject(params, "installer", exe);
    cJSON_AddNumberToObject(params, "request_time", 1234567890);

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
    cJSON_AddNumberToObject(params, "request_time", 1234567890);

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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8103): Error parsing command: 'Invalid JSON type'");

    wm_upgrade_custom_task* upgrade_custom_task = wm_agent_upgrade_parse_upgrade_custom_command(params, &error);

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
                   "        \"force_upgrade\":true,"
                   "        \"request_time\":1234567890"
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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
                   "        \"installer\":\"install.sh\","
                   "        \"request_time\":1234567890"
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
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
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_invalid_package_type, teardown_parse_upgrade),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_invalid_package_type_value, teardown_parse_upgrade),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_command_invalid_json, teardown_parse_upgrade),
        // wm_agent_upgrade_parse_upgrade_custom_command
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_success, teardown_parse_upgrade_custom),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_default, teardown_parse_upgrade_custom),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_file_type, teardown_parse_upgrade_custom),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_installer_type, teardown_parse_upgrade_custom),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_upgrade_custom_command_invalid_json, teardown_parse_upgrade_custom),
        // wm_agent_upgrade_parse_message
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_success, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_agent_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_task_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_custom_success, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_custom_agent_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_upgrade_custom_task_error, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_invalid_command, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_invalid_agents, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_invalid_json, teardown_parse_agents),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_message_missing_required, teardown_parse_agents)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
