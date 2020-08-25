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
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

static int unit_testing;

OSHash *hash_table;

#ifdef TEST_SERVER

cJSON* wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task, wm_upgrade_error_code *error_code, const wm_manager_configs* manager_configs);
int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task, const wm_manager_configs* manager_configs);
void wm_agent_upgrade_start_upgrades(cJSON *json_response, const cJSON* task_module_request, const wm_manager_configs* manager_configs);
int wm_agent_upgrade_send_wpk_to_agent(const wm_agent_task *agent_task, const wm_manager_configs* manager_configs);
int wm_agent_upgrade_send_lock_restart(int agent_id);
int wm_agent_upgrade_send_open(int agent_id, const char *wpk_file);
int wm_agent_upgrade_send_write(int agent_id, const char *wpk_file, const char *file_path, int chunk_size);
int wm_agent_upgrade_send_close(int agent_id, const char *wpk_file);
int wm_agent_upgrade_send_sha1(int agent_id, const char *wpk_file, const char *file_sha1);
int wm_agent_upgrade_send_upgrade(int agent_id, const char *wpk_file, const char *installer);
cJSON* wm_agent_upgrade_send_single_task(wm_upgrade_command command, int agent_id, const char* status_task);

// Setup / teardown

static int setup_hash_table(void **state) {
    hash_table = OSHash_Create();
    return 0;
}

static int teardown_hash_table(void **state) {
    OSHash_Free(hash_table);
    return 0;
}

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

static int setup_config_agent_task(void **state) {
    wm_manager_configs *config = NULL;
    wm_agent_task *agent_task = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->task_info = wm_agent_upgrade_init_task_info();
    state[0] = (void *)config;
    state[1] = (void *)agent_task;
    return 0;
}

static int teardown_config_agent_task(void **state) {
    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    os_free(config);
    wm_agent_upgrade_free_agent_task(agent_task);
    return 0;
}

static int setup_analyze_agent_task(void **state) {
    setup_hash_table(state);
    wm_manager_configs *config = NULL;
    wm_agent_task *agent_task = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->task_info = wm_agent_upgrade_init_task_info();
    state[0] = (void *)config;
    state[1] = (void *)agent_task;
    return 0;
}

static int teardown_analyze_agent_task(void **state) {
    teardown_hash_table(state);
    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    os_free(config);
    wm_agent_upgrade_free_agent_task(agent_task);
    return 0;
}

static int setup_config_nodes(void **state) {
    setup_hash_table(state);
    wm_manager_configs *config = NULL;
    OSHashNode *node = NULL;
    OSHashNode *node_next = NULL;
    wm_agent_task *agent_task = NULL;
    wm_agent_task *agent_task_next = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    os_calloc(1, sizeof(OSHashNode), node);
    os_calloc(1, sizeof(OSHashNode), node_next);
    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->task_info = wm_agent_upgrade_init_task_info();
    agent_task_next = wm_agent_upgrade_init_agent_task();
    agent_task_next->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task_next->task_info = wm_agent_upgrade_init_task_info();
    node->data = agent_task;
    node_next->data = agent_task_next;
    node->next = node_next;
    state[0] = (void *)config;
    state[1] = (void *)node;
    return 0;
}

static int teardown_config_nodes(void **state) {
    teardown_hash_table(state);
    wm_manager_configs *config = (wm_manager_configs *)state[0];
    OSHashNode *node = (OSHashNode *)state[1];
    OSHashNode *node_next = node->next;
    wm_agent_task *agent_task = node->data;
    wm_agent_task *agent_task_next = node_next->data;
    os_free(config);
    wm_agent_upgrade_free_agent_task(agent_task_next);
    wm_agent_upgrade_free_agent_task(agent_task);
    os_free(node_next->key);
    os_free(node_next);
    os_free(node->key);
    os_free(node);
    return 0;
}

static int teardown_agent_status_task_string(void **state) {
    wm_upgrade_agent_status_task *task = state[0];
    char *string = state[1];
    wm_agent_upgrade_free_agent_status_task(task);
    os_free(string);
    return 0;
}

static int teardown_upgrade_custom_task_string(void **state) {
    teardown_hash_table(state);
    wm_upgrade_custom_task *task = state[0];
    char *string = state[1];
    wm_agent_upgrade_free_upgrade_custom_task(task);
    os_free(string);
    return 0;
}

static int teardown_upgrade_task_string(void **state) {
    teardown_hash_table(state);
    wm_upgrade_task *task = state[0];
    char *string = state[1];
    wm_agent_upgrade_free_upgrade_task(task);
    os_free(string);
    return 0;
}

#endif

static int setup_group(void **state) {
    unit_testing = 1;
    return 0;
}

static int teardown_group(void **state) {
    unit_testing = 0;
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
    if (status) check_expected(status);

    return mock_type(cJSON *);
}

int __wrap_wm_agent_upgrade_task_module_callback(cJSON *json_response, const cJSON* task_module_request) {
    cJSON* json = cJSON_GetArrayItem(task_module_request, 0);
    cJSON* json_next = cJSON_GetArrayItem(task_module_request, 1);

    check_expected(json);
    if (json_next) check_expected(json_next);

    cJSON_AddItemToArray(json_response, mock_type(cJSON *));
    if (json_next) cJSON_AddItemToArray(json_response, mock_type(cJSON *));

    return mock();
}

int __wrap_wm_agent_upgrade_parse_agent_response(const char* agent_response, char **data) {
    check_expected(agent_response);

    if (data && strchr(agent_response, ' ')) {
        *data = strchr(agent_response, ' ') + 1;
    }

    return mock();
}

extern FILE* __real_fopen(const char* path, const char* mode);
FILE* __wrap_fopen(const char* path, const char* mode) {
    if(unit_testing) {
        check_expected(path);
        check_expected(mode);
        return mock_ptr_type(FILE*);
    }
    return __real_fopen(path, mode);
}

extern size_t __real_fread(void *ptr, size_t size, size_t n, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t n, FILE *stream) {
    if (unit_testing) {
        strncpy((char *) ptr, mock_type(char *), n);
        return mock();
    }
    return __real_fread(ptr, size, n, stream);
}

int __wrap_fclose() {
    return 0;
}

int __wrap_OS_SHA1_File(const char *fname, char *output, int mode) {
    check_expected(fname);
    check_expected(mode);

    snprintf(output, 41, "%s", mock_type(char *));

    return mock();
}

OSHashNode* __wrap_wm_agent_upgrade_get_first_node(unsigned int *index) {
    if (mock()) {
        return mock_type(OSHashNode *);
    } else {
        return OSHash_Begin(hash_table, index);
    }
}

OSHashNode* __wrap_wm_agent_upgrade_get_next_node(unsigned int *index, OSHashNode *current) {
    if (mock()) {
        return mock_type(OSHashNode *);
    } else {
        return OSHash_Next(hash_table, index, current);
    }
}

int __wrap_wm_agent_upgrade_compare_versions(const char *version1, const char *version2) {
    check_expected(version1);
    check_expected(version2);

    return mock();
}

bool __wrap_wm_agent_upgrade_validate_task_status_message(const cJSON *input_json, char **status, int *agent_id) {
    check_expected(input_json);
    if (status) os_strdup(mock_type(char *), *status);
    if (agent_id) *agent_id = mock();

    return mock();
}

int __wrap_wm_agent_upgrade_validate_id(int agent_id) {
    check_expected(agent_id);

    return mock();
}

int __wrap_wm_agent_upgrade_validate_status(int last_keep_alive) {
    check_expected(last_keep_alive);

    return mock();
}

int __wrap_wm_agent_upgrade_validate_version(const wm_agent_info *agent_info, void *task, wm_upgrade_command command, const wm_manager_configs* manager_configs) {
    check_expected(command);
    check_expected(manager_configs);

    if (command == WM_UPGRADE_UPGRADE) {
        wm_upgrade_task *upgrade_task = (wm_upgrade_task *)task;
        os_strdup(mock_type(char*), upgrade_task->wpk_file);
        os_strdup(mock_type(char*), upgrade_task->wpk_sha1);
    }

    return mock();
}

int __wrap_wm_agent_upgrade_validate_wpk(const wm_upgrade_task *task) {
    return mock();
}

int __wrap_wm_agent_upgrade_validate_wpk_custom(const wm_upgrade_custom_task *task) {
    return mock();
}

int __wrap_wdb_agent_info(int id, char **platform, char **os_major, char **os_minor, char **arch, char **version, int *last_keepalive) {
    check_expected(id);

    os_strdup(mock_type(char *), *platform);
    os_strdup(mock_type(char *), *os_major);
    os_strdup(mock_type(char *), *os_minor);
    os_strdup(mock_type(char *), *arch);
    os_strdup(mock_type(char *), *version);
    *last_keepalive = mock();

    return mock();
}

int __wrap_wm_agent_upgrade_create_task_entry(int agent_id, wm_agent_task* ag_task) {
    check_expected(agent_id);

#ifdef TEST_SERVER
    char key[128];
    sprintf(key, "%d", agent_id);
    OSHash_Add_ex(hash_table, key, ag_task);
#endif

    return mock();
}

void __wrap_wm_agent_upgrade_remove_entry(int agent_id) {
    check_expected(agent_id);

#ifdef TEST_SERVER
    char key[128];
    sprintf(key, "%d", agent_id);
    wm_agent_task *agent_task = (wm_agent_task *)OSHash_Delete_ex(hash_table, key);
    if (agent_task) {
        wm_agent_upgrade_free_agent_task(agent_task);
    }
#endif
}

cJSON* __wrap_wm_agent_upgrade_parse_response_message(int error_id, const char* message, const int *agent_id, const int* task_id, const char* status) {
    int agent_int;
    int task_int;

    check_expected(error_id);
    check_expected(message);
    if (agent_id) {
        agent_int = *agent_id;
        check_expected(agent_int);
    }
    if (task_id) {
        task_int = *task_id;
        check_expected(task_int);
    }
    if (status) {
        check_expected(status);
    }

    return mock_type(cJSON *);
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

void test_wm_agent_upgrade_send_write_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 39;
    char *wpk_file = "test.wpk";
    char *file_path = "/var/upgrade/wazuh_agent.wpk";
    int chunk_size = 5;
    char *chunk = "test\n";
    char *cmd = "039 com write 5 test.wpk test\n";
    char *agent_res = "ok ";

    expect_string(__wrap_fopen, path, file_path);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, chunk);
    will_return(__wrap_fread, chunk_size);

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com write 5 test.wpk test\n'");

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

    will_return(__wrap_fread, chunk);
    will_return(__wrap_fread, chunk_size);

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com write 5 test.wpk test\n'");

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

    will_return(__wrap_fread, chunk);
    will_return(__wrap_fread, 0);

    int res = wm_agent_upgrade_send_write(agent, wpk_file, file_path, chunk_size);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_write_err(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 39;
    char *wpk_file = "test.wpk";
    char *file_path = "/var/upgrade/wazuh_agent.wpk";
    int chunk_size = 5;
    char *chunk = "test\n";
    char *cmd = "039 com write 5 test.wpk test\n";
    char *agent_res1 = "ok ";
    char *agent_res2 = "err Could not write file in agent";

    expect_string(__wrap_fopen, path, file_path);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, chunk);
    will_return(__wrap_fread, chunk_size);

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com write 5 test.wpk test\n'");

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
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res1);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, 0);

    will_return(__wrap_fread, chunk);
    will_return(__wrap_fread, chunk_size);

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '039 com write 5 test.wpk test\n'");

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
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not write file in agent'");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res2);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_write(agent, wpk_file, file_path, chunk_size);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_write_open_err(void **state)
{
    (void) state;

    int agent = 39;
    char *wpk_file = "test.wpk";
    char *file_path = "/var/upgrade/wazuh_agent.wpk";
    int chunk_size = 5;

    expect_string(__wrap_fopen, path, file_path);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 0);

    int res = wm_agent_upgrade_send_write(agent, wpk_file, file_path, chunk_size);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_close_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 33;
    char *wpk_file = "test.wpk";
    char *cmd = "033 com close test.wpk";
    char *agent_res = "ok ";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '033 com close test.wpk'");

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

    int res = wm_agent_upgrade_send_close(agent, wpk_file);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_close_err(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 33;
    char *wpk_file = "test.wpk";
    char *cmd = "033 com close test.wpk";
    char *agent_res = "err Could not close file in agent";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '033 com close test.wpk'");

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
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not close file in agent'");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_close(agent, wpk_file);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_sha1_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 33;
    char *wpk_file = "test.wpk";
    char *file_sha1 = "d321af65983fa412e3a12c312ada12ab321a253a";
    char *cmd = "033 com sha1 test.wpk";
    char *agent_res = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '033 com sha1 test.wpk'");

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
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, 0);

    int res = wm_agent_upgrade_send_sha1(agent, wpk_file, file_sha1);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_sha1_err(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 33;
    char *wpk_file = "test.wpk";
    char *file_sha1 = "d321af65983fa412e3a12c312ada12ab321a253a";
    char *cmd = "033 com sha1 test.wpk";
    char *agent_res = "err Could not calculate sha1 in agent";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '033 com sha1 test.wpk'");

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
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err Could not calculate sha1 in agent'");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_sha1(agent, wpk_file, file_sha1);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_sha1_invalid_sha1(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 33;
    char *wpk_file = "test.wpk";
    char *file_sha1 = "d321af65983fa412e3a12c312ada12ab321a253a";
    char *cmd = "033 com sha1 test.wpk";
    char *agent_res = "ok d321af65983fa412e3a21c312ada12ab321a253a";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '033 com sha1 test.wpk'");

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
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a21c312ada12ab321a253a'");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8118): The SHA1 of the file doesn't match in the agent.");

    int res = wm_agent_upgrade_send_sha1(agent, wpk_file, file_sha1);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_upgrade_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 55;
    char *wpk_file = "test.wpk";
    char *installer = "install.sh";
    char *cmd = "055 com upgrade test.wpk install.sh";
    char *agent_res = "ok ";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '055 com upgrade test.wpk install.sh'");

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

    int res = wm_agent_upgrade_send_upgrade(agent, wpk_file, installer);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_upgrade_err(void **state)
{
    (void) state;

    int socket = 555;
    int agent = 55;
    char *wpk_file = "test.wpk";
    char *installer = "install.sh";
    char *cmd = "055 com upgrade test.wpk install.sh";
    char *agent_res = "ok ";

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '055 com upgrade test.wpk install.sh'");

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
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_upgrade(agent, wpk_file, installer);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_linux_ok(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *write_file = "111 com write 5 test.wpk test\n";
    char *close_file = "111 com close test.wpk";
    char *calculate_sha1 = "111 com sha1 test.wpk";
    char *run_upgrade = "111 com upgrade test.wpk upgrade.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_task *upgrade_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com upgrade test.wpk upgrade.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_windows_ok(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *write_file = "111 com write 5 test.wpk test\n";
    char *close_file = "111 com close test.wpk";
    char *calculate_sha1 = "111 com sha1 test.wpk";
    char *run_upgrade = "111 com upgrade test.wpk upgrade.bat";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_task *upgrade_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("windows", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com upgrade test.wpk upgrade.bat'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_custom_custom_installer_ok(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *write_file = "111 com write 5 test.wpk test\n";
    char *close_file = "111 com close test.wpk";
    char *calculate_sha1 = "111 com sha1 test.wpk";
    char *run_upgrade = "111 com upgrade test.wpk test.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok 2c312ada12ab321a253ad321af65983fa412e3a1";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    os_strdup("/tmp/test.wpk", upgrade_custom_task->custom_file_path);
    os_strdup("test.sh", upgrade_custom_task->custom_installer);
    agent_task->task_info->task = upgrade_custom_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    expect_string(__wrap_OS_SHA1_File, fname, "/tmp/test.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, "2c312ada12ab321a253ad321af65983fa412e3a1");
    will_return(__wrap_OS_SHA1_File, 0);

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "/tmp/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok 2c312ada12ab321a253ad321af65983fa412e3a1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com upgrade test.wpk test.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_custom_default_installer_ok(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *write_file = "111 com write 5 test.wpk test\n";
    char *close_file = "111 com close test.wpk";
    char *calculate_sha1 = "111 com sha1 test.wpk";
    char *run_upgrade = "111 com upgrade test.wpk upgrade.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok 2c312ada12ab321a253ad321af65983fa412e3a1";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    os_strdup("/tmp/test.wpk", upgrade_custom_task->custom_file_path);
    agent_task->task_info->task = upgrade_custom_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    expect_string(__wrap_OS_SHA1_File, fname, "/tmp/test.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, "2c312ada12ab321a253ad321af65983fa412e3a1");
    will_return(__wrap_OS_SHA1_File, 0);

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "/tmp/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok 2c312ada12ab321a253ad321af65983fa412e3a1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com upgrade test.wpk upgrade.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, 0);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_run_upgrade_err(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *write_file = "111 com write 5 test.wpk test\n";
    char *close_file = "111 com close test.wpk";
    char *calculate_sha1 = "111 com sha1 test.wpk";
    char *run_upgrade = "111 com upgrade test.wpk upgrade.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";
    char *agent_res_err = "err ";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_task *upgrade_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com upgrade test.wpk upgrade.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_err);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 5);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_send_sha1_err(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *write_file = "111 com write 5 test.wpk test\n";
    char *close_file = "111 com close test.wpk";
    char *calculate_sha1 = "111 com sha1 test.wpk";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a21c312ada12ab321a253a";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_task *upgrade_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    will_return_count(__wrap_isChroot, 0, 5);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 5);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 5);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 5);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 5);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8118): The SHA1 of the file doesn't match in the agent.");

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 10);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a21c312ada12ab321a253a'");

    expect_value_count(__wrap_close, fd, socket, 5);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 5);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_close_file_err(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *write_file = "111 com write 5 test.wpk test\n";
    char *close_file = "111 com close test.wpk";
    char *agent_res_ok = "ok ";
    char *agent_res_err = "err ";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_task *upgrade_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    will_return_count(__wrap_isChroot, 0, 4);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 4);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 4);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 4);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 4);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 8);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");

    expect_value_count(__wrap_close, fd, socket, 4);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_err);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 3);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_write_file_err(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *write_file = "111 com write 5 test.wpk test\n";
    char *agent_res_ok = "ok ";
    char *agent_res_err = "err ";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_task *upgrade_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    will_return_count(__wrap_isChroot, 0, 3);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 3);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 3);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 3);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 3);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 6);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");

    expect_value_count(__wrap_close, fd, socket, 3);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_err);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 2);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_open_file_err(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *open_file = "111 com open wb test.wpk";
    char *agent_res_ok = "ok ";
    char *agent_res_err = "err ";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_task *upgrade_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    will_return_count(__wrap_isChroot, 0, 11);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 11);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 11);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 11);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 11);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value_count(__wrap_OS_SendSecureTCP, sock, socket, 10);
    expect_value_count(__wrap_OS_SendSecureTCP, size, strlen(open_file), 10);
    expect_string_count(__wrap_OS_SendSecureTCP, msg, open_file, 10);
    will_return_count(__wrap_OS_SendSecureTCP, 0, 10);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 22);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");

    expect_value_count(__wrap_close, fd, socket, 11);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string_count(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_err, 10);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, 0);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID, 10);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_send_wpk_to_agent_upgrade_lock_restart_err(void **state)
{
    (void) state;

    int socket = 555;
    char *lock_restart = "111 com lock_restart -1";
    char *agent_res_err = "err ";

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    wm_upgrade_task *upgrade_task = NULL;

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = 111;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '111'");

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 2);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '111 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_err);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    int res = wm_agent_upgrade_send_wpk_to_agent(agent_task, config);

    assert_int_equal(res, OS_INVALID);
}

void test_wm_agent_upgrade_start_upgrades_upgrade_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent_id = 25;
    char *status = "In progress";

    char *lock_restart = "025 com lock_restart -1";
    char *open_file = "025 com open wb test.wpk";
    char *write_file = "025 com write 5 test.wpk test\n";
    char *close_file = "025 com close test.wpk";
    char *calculate_sha1 = "025 com sha1 test.wpk";
    char *run_upgrade = "025 com upgrade test.wpk upgrade.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    wm_manager_configs *config = state[0];
    OSHashNode *node = state[1];
    wm_agent_task *agent_task = node->data;
    wm_upgrade_task *upgrade_task = NULL;

    os_strdup("025", node->key);

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent_id;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();
    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent_id);

    cJSON_AddItemToArray(request, task_request);

    cJSON *response = cJSON_CreateArray();
    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent_id);
    cJSON_AddNumberToObject(task_response, "task_id", 155);

    cJSON *task_request_status = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request_status, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_status, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request_status, "agent", agent_id);
    cJSON_AddStringToObject(task_request_status, "status", status);

    cJSON *task_response_status = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response_status, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_status, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_status, "agent", agent_id);
    cJSON_AddStringToObject(task_response_status, "status", status);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_first_node

    will_return(__wrap_wm_agent_upgrade_get_first_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_first_node, node);

    // wm_agent_upgrade_get_next_node

    will_return(__wrap_wm_agent_upgrade_get_next_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_next_node, NULL);

    // wm_agent_upgrade_send_wpk_to_agent

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '025'");

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com upgrade test.wpk upgrade.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent_id);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request_status);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request_status, sizeof(task_request_status));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_status);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response_status, sizeof(task_response_status));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent_id);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_remove_entry

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agent_id);

    wm_agent_upgrade_start_upgrades(response, request, config);

    cJSON_Delete(request);
    cJSON_Delete(response);
}

void test_wm_agent_upgrade_start_upgrades_upgrade_legacy_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent_id = 25;
    char *status = "Legacy";

    char *lock_restart = "025 com lock_restart -1";
    char *open_file = "025 com open wb test.wpk";
    char *write_file = "025 com write 5 test.wpk test\n";
    char *close_file = "025 com close test.wpk";
    char *calculate_sha1 = "025 com sha1 test.wpk";
    char *run_upgrade = "025 com upgrade test.wpk upgrade.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    wm_manager_configs *config = state[0];
    OSHashNode *node = state[1];
    wm_agent_task *agent_task = node->data;
    wm_upgrade_task *upgrade_task = NULL;

    os_strdup("025", node->key);

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent_id;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    os_strdup("v3.13.1", upgrade_task->custom_version);
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();
    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent_id);

    cJSON_AddItemToArray(request, task_request);

    cJSON *response = cJSON_CreateArray();
    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent_id);
    cJSON_AddNumberToObject(task_response, "task_id", 155);

    cJSON *task_request_status = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request_status, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_status, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request_status, "agent", agent_id);
    cJSON_AddStringToObject(task_request_status, "status", status);

    cJSON *task_response_status = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response_status, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_status, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_status, "agent", agent_id);
    cJSON_AddStringToObject(task_response_status, "status", status);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_first_node

    will_return(__wrap_wm_agent_upgrade_get_first_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_first_node, node);

    // wm_agent_upgrade_get_next_node

    will_return(__wrap_wm_agent_upgrade_get_next_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_next_node, NULL);

    // wm_agent_upgrade_send_wpk_to_agent

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '025'");

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com upgrade test.wpk upgrade.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    // wm_agent_upgrade_compare_versions

    expect_string(__wrap_wm_agent_upgrade_compare_versions, version1, "v3.13.1");
    expect_string(__wrap_wm_agent_upgrade_compare_versions, version2, WM_UPGRADE_NEW_UPGRADE_MECHANISM);
    will_return(__wrap_wm_agent_upgrade_compare_versions, -1);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent_id);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request_status);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request_status, sizeof(task_request_status));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_status);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response_status, sizeof(task_response_status));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent_id);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_remove_entry

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agent_id);

    wm_agent_upgrade_start_upgrades(response, request, config);

    cJSON_Delete(request);
    cJSON_Delete(response);
}

void test_wm_agent_upgrade_start_upgrades_upgrade_custom_ok(void **state)
{
    (void) state;

    int socket = 555;
    int agent_id = 25;
    char *status = "In progress";

    char *lock_restart = "025 com lock_restart -1";
    char *open_file = "025 com open wb test.wpk";
    char *write_file = "025 com write 5 test.wpk test\n";
    char *close_file = "025 com close test.wpk";
    char *calculate_sha1 = "025 com sha1 test.wpk";
    char *run_upgrade = "025 com upgrade test.wpk upgrade.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    wm_manager_configs *config = state[0];
    OSHashNode *node = state[1];
    wm_agent_task *agent_task = node->data;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    os_strdup("025", node->key);

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent_id;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    os_strdup("/tmp/test.wpk", upgrade_custom_task->custom_file_path);
    agent_task->task_info->task = upgrade_custom_task;

    cJSON *request = cJSON_CreateArray();
    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent_id);

    cJSON_AddItemToArray(request, task_request);

    cJSON *response = cJSON_CreateArray();
    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent_id);
    cJSON_AddNumberToObject(task_response, "task_id", 155);

    cJSON *task_request_status = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request_status, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_status, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request_status, "agent", agent_id);
    cJSON_AddStringToObject(task_request_status, "status", status);

    cJSON *task_response_status = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response_status, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_status, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_status, "agent", agent_id);
    cJSON_AddStringToObject(task_response_status, "status", status);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_first_node

    will_return(__wrap_wm_agent_upgrade_get_first_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_first_node, node);

    // wm_agent_upgrade_get_next_node

    will_return(__wrap_wm_agent_upgrade_get_next_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_next_node, NULL);

    // wm_agent_upgrade_send_wpk_to_agent

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '025'");

    expect_string(__wrap_OS_SHA1_File, fname, "/tmp/test.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, "d321af65983fa412e3a12c312ada12ab321a253a");
    will_return(__wrap_OS_SHA1_File, 0);

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "/tmp/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com upgrade test.wpk upgrade.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent_id);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request_status);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request_status, sizeof(task_request_status));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_status);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response_status, sizeof(task_response_status));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent_id);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_remove_entry

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agent_id);

    wm_agent_upgrade_start_upgrades(response, request, config);

    cJSON_Delete(request);
    cJSON_Delete(response);
}

void test_wm_agent_upgrade_start_upgrades_upgrade_err(void **state)
{
    (void) state;

    int socket = 555;
    int agent_id = 25;
    char *status = "Failed";

    char *lock_restart = "025 com lock_restart -1";
    char *open_file = "025 com open wb test.wpk";
    char *write_file = "025 com write 5 test.wpk test\n";
    char *close_file = "025 com close test.wpk";
    char *calculate_sha1 = "025 com sha1 test.wpk";
    char *run_upgrade = "025 com upgrade test.wpk upgrade.sh";
    char *agent_res_err = "err ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    wm_manager_configs *config = state[0];
    OSHashNode *node = state[1];
    wm_agent_task *agent_task = node->data;
    wm_upgrade_task *upgrade_task = NULL;

    os_strdup("025", node->key);

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent_id;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();
    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent_id);

    cJSON_AddItemToArray(request, task_request);

    cJSON *response = cJSON_CreateArray();
    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent_id);
    cJSON_AddNumberToObject(task_response, "task_id", 155);

    cJSON *task_request_status = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request_status, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_status, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request_status, "agent", agent_id);
    cJSON_AddStringToObject(task_request_status, "status", status);

    cJSON *task_response_status = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response_status, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_status, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_status, "agent", agent_id);
    cJSON_AddStringToObject(task_response_status, "status", status);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_first_node

    will_return(__wrap_wm_agent_upgrade_get_first_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_first_node, node);

    // wm_agent_upgrade_get_next_node

    will_return(__wrap_wm_agent_upgrade_get_next_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_next_node, NULL);

    // wm_agent_upgrade_send_wpk_to_agent

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '025'");

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 2);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_err);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent_id);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request_status);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request_status, sizeof(task_request_status));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_status);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response_status, sizeof(task_response_status));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent_id);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_remove_entry

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agent_id);

    wm_agent_upgrade_start_upgrades(response, request, config);

    cJSON_Delete(request);
    cJSON_Delete(response);
}

void test_wm_agent_upgrade_start_upgrades_no_agents(void **state)
{
    (void) state;

    int socket = 555;
    int agent_id = 25;
    char *status = "In progress";

    wm_manager_configs *config = state[0];

    config->chunk_size = 5;

    cJSON *request = cJSON_CreateArray();
    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent_id);

    cJSON_AddItemToArray(request, task_request);

    cJSON *response = cJSON_CreateArray();
    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent_id);
    cJSON_AddNumberToObject(task_response, "task_id", 155);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, OS_INVALID);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8160): There are no valid agents to upgrade.");

    wm_agent_upgrade_start_upgrades(response, request, config);

    cJSON_Delete(request);
    cJSON_Delete(response);
}

void test_wm_agent_upgrade_start_upgrades_upgrade_multiple(void **state)
{
    (void) state;

    int socket = 555;
    int agent_id = 25;
    int agent_id_next = 35;
    char *status = "Failed";
    char *status_next = "In progress";

    char *lock_restart = "025 com lock_restart -1";
    char *lock_restart_next = "035 com lock_restart -1";
    char *open_file_next = "035 com open wb test.wpk";
    char *write_file_next = "035 com write 5 test.wpk test\n";
    char *close_file_next = "035 com close test.wpk";
    char *calculate_sha1_next = "035 com sha1 test.wpk";
    char *run_upgrade_next = "035 com upgrade test.wpk upgrade.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_err = "err ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    wm_manager_configs *config = state[0];
    OSHashNode *node = state[1];
    wm_agent_task *agent_task = node->data;
    wm_upgrade_task *upgrade_task = NULL;

    OSHashNode *node_next = node->next;
    wm_agent_task *agent_task_next = node_next->data;
    wm_upgrade_task *upgrade_task_next = NULL;

    os_strdup("025", node->key);

    os_strdup("035", node_next->key);

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent_id;
    os_strdup("ubuntu", agent_task->agent_info->platform);
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task->wpk_sha1);
    agent_task->task_info->task = upgrade_task;

    agent_task_next->agent_info->agent_id = agent_id_next;
    os_strdup("ubuntu", agent_task_next->agent_info->platform);
    agent_task_next->task_info->command = WM_UPGRADE_UPGRADE;
    upgrade_task_next = wm_agent_upgrade_init_upgrade_task();
    os_strdup("test.wpk", upgrade_task_next->wpk_file);
    os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", upgrade_task_next->wpk_sha1);
    agent_task_next->task_info->task = upgrade_task_next;

    cJSON *request = cJSON_CreateArray();
    cJSON *task_request = cJSON_CreateObject();
    cJSON *task_request_next = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent_id);

    cJSON_AddItemToArray(request, task_request);

    cJSON_AddStringToObject(task_request_next, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_next, "command", "upgrade");
    cJSON_AddNumberToObject(task_request_next, "agent", agent_id_next);

    cJSON_AddItemToArray(request, task_request_next);

    cJSON *response = cJSON_CreateArray();
    cJSON *task_response = cJSON_CreateObject();
    cJSON *task_response_next = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent_id);
    cJSON_AddNumberToObject(task_response, "task_id", 155);

    cJSON_AddStringToObject(task_response_next, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_next, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_next, "agent", agent_id_next);
    cJSON_AddNumberToObject(task_response_next, "task_id", 156);

    cJSON *task_request_status = cJSON_CreateObject();
    cJSON *task_request_status_next = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request_status, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_status, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request_status, "agent", agent_id);
    cJSON_AddStringToObject(task_request_status, "status", status);

    cJSON_AddStringToObject(task_request_status_next, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_status_next, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request_status_next, "agent", agent_id);
    cJSON_AddStringToObject(task_request_status_next, "status", status);

    cJSON *task_response_status = cJSON_CreateObject();
    cJSON *task_response_status_next = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response_status, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_status, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_status, "agent", agent_id);
    cJSON_AddStringToObject(task_response_status, "status", status);

    cJSON_AddStringToObject(task_response_status_next, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_status_next, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_status_next, "agent", agent_id_next);
    cJSON_AddStringToObject(task_response_status_next, "status", status_next);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json_next, task_request_next, sizeof(task_request_next));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_next);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_first_node

    will_return(__wrap_wm_agent_upgrade_get_first_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_first_node, node);

    // wm_agent_upgrade_get_next_node

    will_return(__wrap_wm_agent_upgrade_get_next_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_next_node, node_next);

    // wm_agent_upgrade_send_wpk_to_agent

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '025'");

    will_return(__wrap_isChroot, 0);

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, socket);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_err);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_err) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 2);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '025 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'err '");

    expect_value(__wrap_close, fd, socket);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_err);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent_id);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request_status);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request_status, sizeof(task_request_status));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_status);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response_status, sizeof(task_response_status));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent_id);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_remove_entry

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agent_id);

    // wm_agent_upgrade_get_next_node

    will_return(__wrap_wm_agent_upgrade_get_next_node, 1);
    will_return(__wrap_wm_agent_upgrade_get_next_node, NULL);

    // wm_agent_upgrade_send_wpk_to_agent

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '035'");

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart_next));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart_next);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file_next));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file_next);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file_next));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file_next);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file_next));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file_next);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1_next));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1_next);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade_next));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade_next);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '035 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '035 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '035 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '035 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '035 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '035 com upgrade test.wpk upgrade.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent_id_next);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, status_next);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request_status_next);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request_status_next, sizeof(task_request_status_next));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_status_next);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response_status_next, sizeof(task_response_status_next));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent_id_next);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_remove_entry

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agent_id_next);

    wm_agent_upgrade_start_upgrades(response, request, config);

    cJSON_Delete(request);
    cJSON_Delete(response);
}

void test_wm_agent_upgrade_validate_agent_task_upgrade_ok(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk
    will_return(__wrap_wm_agent_upgrade_validate_wpk, WM_UPGRADE_SUCCESS);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_agent_task_upgrade_custom_ok(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
    agent_task->task_info->task = upgrade_custom_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk_custom
    will_return(__wrap_wm_agent_upgrade_validate_wpk_custom, WM_UPGRADE_SUCCESS);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_agent_task_upgrade_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk
    will_return(__wrap_wm_agent_upgrade_validate_wpk, WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH);
}

void test_wm_agent_upgrade_validate_agent_task_upgrade_custom_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
    agent_task->task_info->task = upgrade_custom_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk_custom
    will_return(__wrap_wm_agent_upgrade_validate_wpk_custom, WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST);
}

void test_wm_agent_upgrade_validate_agent_task_version_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_GLOBAL_DB_FAILURE);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_GLOBAL_DB_FAILURE);
}

void test_wm_agent_upgrade_validate_agent_task_in_progress_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "In progress");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS);
}

void test_wm_agent_upgrade_validate_agent_task_task_manager_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 0);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
}

void test_wm_agent_upgrade_validate_agent_task_status_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);
}

void test_wm_agent_upgrade_validate_agent_task_agent_id_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);
}

void test_wm_agent_upgrade_analyze_agent_ok(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request_status = cJSON_CreateArray();

    cJSON *status_request = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request, "agent", agent);

    cJSON_AddItemToArray(request_status, status_request);

    cJSON *status_response = cJSON_CreateObject();

    cJSON_AddStringToObject(status_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response, "agent", agent);

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response, sizeof(status_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk
    will_return(__wrap_wm_agent_upgrade_validate_wpk, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, agent_task->task_info->command);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_non_null(json);
    assert_memory_equal(json, task_request, sizeof(json));
    assert_int_equal(error_code, WM_UPGRADE_SUCCESS);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);

    cJSON_Delete(json);
}

void test_wm_agent_upgrade_analyze_agent_duplicated_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 120;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request_status = cJSON_CreateArray();

    cJSON *status_request = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request, "agent", agent);

    cJSON_AddItemToArray(request_status, status_request);

    cJSON *status_response = cJSON_CreateObject();

    cJSON_AddStringToObject(status_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response, "agent", agent);

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response, sizeof(status_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk
    will_return(__wrap_wm_agent_upgrade_validate_wpk, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_DUPLICATED);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_null(json);
    assert_int_equal(error_code, WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);
}

void test_wm_agent_upgrade_analyze_agent_unknown_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 121;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request_status = cJSON_CreateArray();

    cJSON *status_request = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request, "agent", agent);

    cJSON_AddItemToArray(request_status, status_request);

    cJSON *status_response = cJSON_CreateObject();

    cJSON_AddStringToObject(status_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response, "agent", agent);

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response, sizeof(status_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk
    will_return(__wrap_wm_agent_upgrade_validate_wpk, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OS_INVALID);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_null(json);
    assert_int_equal(error_code, WM_UPGRADE_UNKNOWN_ERROR);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);
}

void test_wm_agent_upgrade_analyze_agent_validate_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_null(json);
    assert_int_equal(error_code, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);
}

void test_wm_agent_upgrade_analyze_agent_global_db_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_null(json);
    assert_int_equal(error_code, WM_UPGRADE_GLOBAL_DB_FAILURE);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);
}

void test_wm_agent_upgrade_process_agent_result_command(void **state)
{
    (void) state;

    int agents[2];
    wm_upgrade_agent_status_task *upgrade_agent_status_task = NULL;
    char *agent_status = "Done";

    agents[0] = 25;
    agents[1] = OS_INVALID;

    upgrade_agent_status_task = wm_agent_upgrade_init_agent_status_task();
    upgrade_agent_status_task->error_code = 0;
    os_strdup("Success", upgrade_agent_status_task->message);
    os_strdup(agent_status, upgrade_agent_status_task->status);

    state[0] = (void *)upgrade_agent_status_task;

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request, "agent", agents[0]);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agents[0]);
    cJSON_AddStringToObject(task_response, "status", agent_status);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8164): Received upgrade notification from agent '25'. Error code: '0', message: 'Success'");

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, agent_status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    char *result = wm_agent_upgrade_process_agent_result_command(agents, upgrade_agent_status_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"data\":\"Success.\",\"agent\":25,\"status\":\"Done\"}]");
}

void test_wm_agent_upgrade_process_upgrade_custom_command(void **state)
{
    (void) state;

    int agents[3];
    wm_manager_configs *config = NULL;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    char *custom_file_path = "/tmp/test.wpk";
    char *custom_installer = "test.sh";

    int socket = 555;
    char *lock_restart = "001 com lock_restart -1";
    char *open_file = "001 com open wb test.wpk";
    char *write_file = "001 com write 5 test.wpk test\n";
    char *close_file = "001 com close test.wpk";
    char *calculate_sha1 = "001 com sha1 test.wpk";
    char *run_upgrade = "001 com upgrade test.wpk test.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_calloc(1, sizeof(wm_manager_configs), config);
    config->chunk_size = 5;

    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    os_strdup(custom_file_path, upgrade_custom_task->custom_file_path);
    os_strdup(custom_installer, upgrade_custom_task->custom_installer);

    state[0] = (void *)upgrade_custom_task;

    cJSON *task_request1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request1, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request1, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task_request1, "agent", agents[0]);

    cJSON *request_status1 = cJSON_CreateArray();

    cJSON *status_request1 = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request1, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request1, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request1, "agent", agents[0]);

    cJSON_AddItemToArray(request_status1, status_request1);

    cJSON *status_response1 = cJSON_CreateObject();

    cJSON_AddNumberToObject(status_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response1, "agent", agents[0]);
    cJSON_AddStringToObject(status_response1, "status", "Done");

    cJSON *task_request_status1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request_status1, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_status1, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request_status1, "agent", agents[0]);
    cJSON_AddStringToObject(task_request_status1, "status", "In progress");

    cJSON *task_response_status1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response_status1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_status1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_status1, "agent", agents[0]);
    cJSON_AddStringToObject(task_response_status1, "status", "In progress");

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);
    cJSON_AddNumberToObject(task_response1, "task_id", 100);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "data", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[0]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "18");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86_64");
    will_return(__wrap_wdb_agent_info, "v3.13.1");
    will_return(__wrap_wdb_agent_info, 123456789);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, 123456789);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status1);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request1, sizeof(status_request1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response1, sizeof(status_response1));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, WM_UPGRADE_UPGRADE_CUSTOM);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk_custom
    will_return(__wrap_wm_agent_upgrade_validate_wpk_custom, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_UPGRADE_CUSTOM);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request1);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[1]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "16");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86");
    will_return(__wrap_wdb_agent_info, "v3.5.0");
    will_return(__wrap_wdb_agent_info, 234567890);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, task_response2);

    // Start upgrades

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request1, sizeof(task_request1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_first_node

    will_return(__wrap_wm_agent_upgrade_get_first_node, 0);

    // wm_agent_upgrade_get_next_node

    will_return(__wrap_wm_agent_upgrade_get_next_node, 0);

    // wm_agent_upgrade_send_wpk_to_agent

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '001'");

    expect_string(__wrap_OS_SHA1_File, fname, "/tmp/test.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, "d321af65983fa412e3a12c312ada12ab321a253a");
    will_return(__wrap_OS_SHA1_File, 0);

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "/tmp/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com upgrade test.wpk test.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, "In progress");
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request_status1);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request_status1, sizeof(task_request_status1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_status1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response_status1, sizeof(task_response_status1));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agents[0]);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_remove_entry

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agents[0]);

    char *result = wm_agent_upgrade_process_upgrade_custom_command(agents, upgrade_custom_task, config);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"error\":6,\"data\":\"Agent information not found in database.\",\"agent\":2},{\"data\":\"Success.\",\"agent\":1,\"task_id\":100}]");

    os_free(config);
}

void test_wm_agent_upgrade_process_upgrade_command(void **state)
{
    (void) state;

    int agents[3];
    wm_manager_configs *config = NULL;
    wm_upgrade_task *upgrade_task = NULL;

    int socket = 555;
    char *lock_restart = "001 com lock_restart -1";
    char *open_file = "001 com open wb test.wpk";
    char *write_file = "001 com write 5 test.wpk test\n";
    char *close_file = "001 com close test.wpk";
    char *calculate_sha1 = "001 com sha1 test.wpk";
    char *run_upgrade = "001 com upgrade test.wpk upgrade.sh";
    char *agent_res_ok = "ok ";
    char *agent_res_ok_sha1 = "ok d321af65983fa412e3a12c312ada12ab321a253a";

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_calloc(1, sizeof(wm_manager_configs), config);
    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();

    state[0] = (void *)upgrade_task;

    cJSON *task_request1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request1, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request1, "command", "upgrade");
    cJSON_AddNumberToObject(task_request1, "agent", agents[0]);

    cJSON *request_status1 = cJSON_CreateArray();

    cJSON *status_request1 = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request1, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request1, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request1, "agent", agents[0]);

    cJSON_AddItemToArray(request_status1, status_request1);

    cJSON *status_response1 = cJSON_CreateObject();

    cJSON_AddNumberToObject(status_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response1, "agent", agents[0]);
    cJSON_AddStringToObject(status_response1, "status", "Done");

    cJSON *task_request_status1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request_status1, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request_status1, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request_status1, "agent", agents[0]);
    cJSON_AddStringToObject(task_request_status1, "status", "In progress");

    cJSON *task_response_status1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response_status1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response_status1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response_status1, "agent", agents[0]);
    cJSON_AddStringToObject(task_response_status1, "status", "In progress");

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);
    cJSON_AddNumberToObject(task_response1, "task_id", 110);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "data", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[0]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "18");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86_64");
    will_return(__wrap_wdb_agent_info, "v3.13.1");
    will_return(__wrap_wdb_agent_info, 123456789);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, 123456789);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status1);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request1, sizeof(status_request1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response1, sizeof(status_response1));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, WM_UPGRADE_UPGRADE);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "test.wpk");
    will_return(__wrap_wm_agent_upgrade_validate_version, "d321af65983fa412e3a12c312ada12ab321a253a");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_wpk
    will_return(__wrap_wm_agent_upgrade_validate_wpk, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_UPGRADE);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request1);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[1]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "16");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86");
    will_return(__wrap_wdb_agent_info, "v3.5.0");
    will_return(__wrap_wdb_agent_info, 234567890);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, task_response2);

    // Start upgrades

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request1, sizeof(task_request1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_first_node

    will_return(__wrap_wm_agent_upgrade_get_first_node, 0);

    // wm_agent_upgrade_get_next_node

    will_return(__wrap_wm_agent_upgrade_get_next_node, 0);

    // wm_agent_upgrade_send_wpk_to_agent

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8162): Sending WPK to agent: '001'");

    will_return_count(__wrap_isChroot, 0, 6);

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR REMOTE_REQ_SOCK, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, 6);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, 6);
    will_return_count(__wrap_OS_ConnectUnixDomain, socket, 6);

    // Lock restart

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(lock_restart));
    expect_string(__wrap_OS_SendSecureTCP, msg, lock_restart);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Open file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(open_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, open_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Write file

    expect_string(__wrap_fopen, path, "var/upgrade/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, config->chunk_size);

    will_return(__wrap_fread, "test\n");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(write_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, write_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Close file

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(close_file));
    expect_string(__wrap_OS_SendSecureTCP, msg, close_file);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    // Calculate file sha1

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(calculate_sha1));
    expect_string(__wrap_OS_SendSecureTCP, msg, calculate_sha1);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok_sha1);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok_sha1) + 1);

    // Run upgrade script

    expect_value(__wrap_OS_SendSecureTCP, sock, socket);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(run_upgrade));
    expect_string(__wrap_OS_SendSecureTCP, msg, run_upgrade);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, socket);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, 1);
    will_return(__wrap_OS_RecvSecureTCP, agent_res_ok);
    will_return(__wrap_OS_RecvSecureTCP, strlen(agent_res_ok) + 1);

    expect_string_count(__wrap__mtdebug2, tag, "wazuh-modulesd:agent-upgrade", 12);
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com lock_restart -1'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com open wb test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com write 5 test.wpk test\n'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com close test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com sha1 test.wpk'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok d321af65983fa412e3a12c312ada12ab321a253a'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8165): Sending message to agent: '001 com upgrade test.wpk upgrade.sh'");
    expect_string(__wrap__mtdebug2, formatted_msg, "(8166): Receiving message from agent: 'ok '");

    expect_value_count(__wrap_close, fd, socket, 6);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok_sha1);
    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res_ok);
    will_return_count(__wrap_wm_agent_upgrade_parse_agent_response, 0, 6);

    // wm_agent_upgrade_send_single_task

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, "In progress");
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request_status1);

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request_status1, sizeof(task_request_status1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response_status1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response_status1, sizeof(task_response_status1));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agents[0]);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_remove_entry

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agents[0]);

    char *result = wm_agent_upgrade_process_upgrade_command(agents, upgrade_task, config);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"error\":6,\"data\":\"Agent information not found in database.\",\"agent\":2},{\"data\":\"Success.\",\"agent\":1,\"task_id\":110}]");

    os_free(config);
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
        // wm_agent_upgrade_send_write
        cmocka_unit_test(test_wm_agent_upgrade_send_write_ok),
        cmocka_unit_test(test_wm_agent_upgrade_send_write_err),
        cmocka_unit_test(test_wm_agent_upgrade_send_write_open_err),
        // wm_agent_upgrade_send_close
        cmocka_unit_test(test_wm_agent_upgrade_send_close_ok),
        cmocka_unit_test(test_wm_agent_upgrade_send_close_err),
        // wm_agent_upgrade_send_sha1
        cmocka_unit_test(test_wm_agent_upgrade_send_sha1_ok),
        cmocka_unit_test(test_wm_agent_upgrade_send_sha1_err),
        cmocka_unit_test(test_wm_agent_upgrade_send_sha1_invalid_sha1),
        // wm_agent_upgrade_send_upgrade
        cmocka_unit_test(test_wm_agent_upgrade_send_upgrade_ok),
        cmocka_unit_test(test_wm_agent_upgrade_send_upgrade_err),
        // wm_agent_upgrade_send_wpk_to_agent
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_linux_ok, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_windows_ok, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_custom_custom_installer_ok, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_custom_default_installer_ok, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_run_upgrade_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_send_sha1_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_close_file_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_write_file_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_open_file_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_send_wpk_to_agent_upgrade_lock_restart_err, setup_config_agent_task, teardown_config_agent_task),
        // wm_agent_upgrade_start_upgrades
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_start_upgrades_upgrade_ok, setup_config_nodes, teardown_config_nodes),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_start_upgrades_upgrade_legacy_ok, setup_config_nodes, teardown_config_nodes),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_start_upgrades_upgrade_custom_ok, setup_config_nodes, teardown_config_nodes),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_start_upgrades_upgrade_err, setup_config_nodes, teardown_config_nodes),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_start_upgrades_no_agents, setup_config_nodes, teardown_config_nodes),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_start_upgrades_upgrade_multiple, setup_config_nodes, teardown_config_nodes),
        // wm_agent_upgrade_validate_agent_task
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_upgrade_ok, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_upgrade_custom_ok, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_upgrade_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_upgrade_custom_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_version_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_in_progress_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_task_manager_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_status_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_agent_id_err, setup_config_agent_task, teardown_config_agent_task),
        // wm_agent_upgrade_analyze_agent
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_ok, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_duplicated_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_unknown_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_validate_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_global_db_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        // wm_agent_upgrade_process_agent_result_command
        cmocka_unit_test_teardown(test_wm_agent_upgrade_process_agent_result_command, teardown_agent_status_task_string),
        // wm_agent_upgrade_process_upgrade_custom_command
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_custom_command, setup_hash_table, teardown_upgrade_custom_task_string),
        // wm_agent_upgrade_process_upgrade_command
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_command, setup_hash_table, teardown_upgrade_task_string)
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
