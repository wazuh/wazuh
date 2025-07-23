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
#include <string.h>

#include "shared.h"
#include "../../os_auth/auth.h"
#include "../../os_auth/key_request.h"
#include "../../addagent/validate.h"
#include "../../headers/sec.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/os_auth/os_auth_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

#define BUFFERSIZE 1024
#define QUEUE_SIZE 5

volatile int running = 1;

// Additional authd_sigblock definition to avoid including main-server.o

void authd_sigblock() {
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);
}

// setup/teardowns

static int test_setup(void **state) {
    authd_key_request_t *init_data = NULL;
    os_calloc(1, sizeof(authd_key_request_t), init_data);

    init_data->timeout = 1;
    init_data->threads = 1;
    init_data->queue_size = BUFFERSIZE;

    config.key_request.timeout = 1;
    config.key_request.socket = "/tmp/tmp_file_XXXXX";

    os_strdup("/tmp/tmp_file-XXXXXX", init_data->socket);

    test_mode = 1;
    *state = init_data;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    authd_key_request_t *data  = (authd_key_request_t *)*state;
    unlink(data->socket);
    os_free(data->socket);
    os_free(data);

    config.key_request.timeout = 0;
    config.key_request.socket = "";

    test_mode = 0;

    return OS_SUCCESS;
}

// Test get_agent_info_from_json()

void test_get_agent_info_from_json_error_malformed(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    char    *error_msg      = NULL;

    will_return(__wrap_cJSON_GetObjectItem, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Malformed JSON output received. No 'error' field found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);
    __real_cJSON_Delete(input_raw_json);
}

void test_get_agent_info_from_json_message_malformed(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    field->valueint = 1;

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Malformed JSON output received. No 'message' field found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(input_raw_json);
}

void test_get_agent_info_from_json_error_valuestring(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *message        = cJSON_CreateNumber(2);
    char    *error_msg      = NULL;

    field->valueint = 1;
    message->valuestring = strdup("test");

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, message);

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_string_equal(message->valuestring, error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(message);
    __real_cJSON_Delete(input_raw_json);
}

void test_get_agent_info_from_json_agent_data_not_found(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    field->valueint = 0;

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent data not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(input_raw_json);
}

void test_get_agent_info_from_json_agent_id_not_found(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(2);
    char    *error_msg      = NULL;

    field->valueint = 0;

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent ID not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(input_raw_json);
}

void test_get_agent_info_from_json_agent_name_not_found(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(2);
    cJSON   *id             = cJSON_CreateNumber(3);
    char    *error_msg      = NULL;

    field->valueint = 0;
    id->valuestring = strdup("001");

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent name not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(input_raw_json);
}

void test_get_agent_info_from_json_agent_ip_not_found(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(2);
    cJSON   *id             = cJSON_CreateNumber(3);
    cJSON   *name           = cJSON_CreateNumber(4);
    char    *error_msg      = NULL;

    field->valueint = 0;
    id->valuestring = strdup("001");
    name->valuestring = strdup("test");

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent address not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(input_raw_json);
}

void test_get_agent_info_from_json_agent_key_not_found(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(1);
    cJSON   *id             = cJSON_CreateNumber(1);
    cJSON   *name           = cJSON_CreateNumber(1);
    cJSON   *ip             = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    field->valueint = 0;
    id->valuestring = strdup("001");
    name->valuestring = strdup("test");
    ip->valuestring = strdup("127.0.0.1");

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent key not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(input_raw_json);
}

void test_get_agent_info_from_json_agent_success(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(1);
    cJSON   *id             = cJSON_CreateNumber(1);
    cJSON   *name           = cJSON_CreateNumber(1);
    cJSON   *ip             = cJSON_CreateNumber(1);
    cJSON   *key            = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    field->valueint = 0;
    id->valuestring = strdup("001");
    name->valuestring = strdup("test");
    ip->valuestring = strdup("127.0.0.1");
    key->valuestring = strdup("key");

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, key);

    key_request_agent_info *ret = get_agent_info_from_json(input_raw_json, &error_msg);

    assert_string_equal(ret->id, id->valuestring);
    assert_string_equal(ret->name, name->valuestring);
    assert_string_equal(ret->ip, ip->valuestring);
    assert_string_equal(ret->key, key->valuestring);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(key);
    __real_cJSON_Delete(input_raw_json);

    key_request_agent_info_destroy(ret);
}

// Test key_request_socket_output()

void test_key_request_socket_output_not_connect(void **state) {
    char debug_msg[128];
    char warn_msg[128];

    will_return(__wrap_external_socket_connect, -1);
    snprintf(debug_msg, OS_SIZE_128, "Could not connect to external socket: %s (%d)", strerror(errno), errno);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);
    expect_value(__wrap_sleep, seconds, 1);

    will_return(__wrap_external_socket_connect, -1);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);
    expect_value(__wrap_sleep, seconds, 2);

    will_return(__wrap_external_socket_connect, -1);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);
    expect_value(__wrap_sleep, seconds, 3);

    snprintf(warn_msg, OS_SIZE_128, "Could not connect to external integration: %s (%d). Discarding request.", strerror(errno), errno);
    expect_string(__wrap__mwarn, formatted_msg, warn_msg);

    char *ret = key_request_socket_output(K_TYPE_ID, "001");
    assert_null(ret);
}

void test_key_request_socket_output_long_request(void **state) {
    char buffer_request[127];

    memset(buffer_request, 'a', 126);
    buffer_request[126] = '\0';

    will_return(__wrap_external_socket_connect, 4);
    expect_string(__wrap__mdebug1, formatted_msg, "Request is too long for socket.");

    char *ret = key_request_socket_output(K_TYPE_ID, buffer_request);
    assert_null(ret);
}

void test_key_request_socket_output_send_fail(void **state) {
    will_return(__wrap_external_socket_connect, 4);
    will_return(__wrap_send, -1);

    char *ret = key_request_socket_output(K_TYPE_ID, NULL);
    assert_null(ret);
}

void test_key_request_socket_output_no_data_received(void **state) {
    will_return(__wrap_external_socket_connect, 4);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "No data received from external socket.");

    char *ret = key_request_socket_output(K_TYPE_ID, NULL);
    assert_null(ret);
}

void test_key_request_socket_output_empty_string_received(void **state) {
    will_return(__wrap_external_socket_connect, 4);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 0);

    char *ret = key_request_socket_output(K_TYPE_ID, NULL);
    assert_null(ret);
}

void test_key_request_socket_output_success(void **state) {
    will_return(__wrap_external_socket_connect, 4);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 12);

    char *ret = key_request_socket_output(K_TYPE_ID, NULL);
    assert_string_equal(ret, "Hello World!");
    os_free(ret);
}

// Test key_request_dispatch()

void test_key_request_dispatch_long_id(void **state) {
    char    *buffer = "id:000000001";

    expect_string(__wrap__mdebug1, formatted_msg, "Agent ID is too long.");
    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, -1);
}


void test_key_request_dispatch_long_ip(void **state) {
    char    *buffer = "ip:00000000000000000000";

    expect_string(__wrap__mdebug1, formatted_msg, "Agent IP is too long.");
    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, -1);
}

void test_key_request_dispatch_invalid_request(void **state) {
    char    *buffer = "bad:000000001";

    expect_string(__wrap__merror, formatted_msg, "Invalid request 'bad:000000001' received in Agent key request.");
    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, -1);
}

void test_key_request_dispatch_bad_socket_output(void **state) {
    authd_key_request_t *data   = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *error  = cJSON_CreateNumber(1);

    data->exec_path = NULL;

    will_return(__wrap_external_socket_connect, 4);
    will_return(__wrap_send, -1);

    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, -1);

    __real_cJSON_Delete(error);
}

void test_key_request_dispatch_error_parsing_json(void **state) {
    char    *buffer = "id:001";

    will_return(__wrap_external_socket_connect, 4);
    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 12);
    expect_string(__wrap__mdebug2, formatted_msg, "Socket output: Hello World!");

    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error parsing JSON event ()");

    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, 0);
}

void test_key_request_dispatch_error_parsing_agent_json(void **state) {
    authd_key_request_t *data   = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *field  = cJSON_CreateNumber(1);
    cJSON               *msg    = cJSON_CreateNumber(2);

    field->valueint = 1;
    msg->valuestring = strdup("Test");

    will_return(__wrap_external_socket_connect, 4);
    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 12);
    expect_string(__wrap__mdebug2, formatted_msg, "Socket output: Hello World!");

    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *)1);
    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, msg);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not get a key from ID 001. Error: 'Test'");
    expect_function_call(__wrap_cJSON_Delete);
    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, -1);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(msg);
}

void test_key_request_dispatch_exec_output_error(void **state) {
    char    *buffer = "id:001";

    config.key_request.socket = 0;
    config.key_request.exec_path = "python3 /tmp/test.py";

    expect_string(__wrap_wm_exec, command, "python3 /tmp/test.py id 001");
    expect_value(__wrap_wm_exec, secs, 1);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Output command");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 1);

    expect_string(__wrap__mwarn, formatted_msg, "Timeout received while running key request integration (python3 /tmp/test.py)");

    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, -1);
}

void test_key_request_dispatch_success(void **state) {
    authd_key_request_t *data_state  = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *field  = cJSON_CreateNumber(1);
    cJSON               *data   = cJSON_CreateNumber(2);
    cJSON               *id     = cJSON_CreateNumber(3);
    cJSON               *name   = cJSON_CreateNumber(4);
    cJSON               *ip     = cJSON_CreateNumber(5);
    cJSON               *key    = cJSON_CreateNumber(6);

    config.worker_node = 1;

    will_return(__wrap_external_socket_connect, 4);
    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 12);
    expect_string(__wrap__mdebug2, formatted_msg, "Socket output: Hello World!");

    field->valueint = 0;
    id->valuestring = strdup("001");
    name->valuestring = strdup("test");
    ip->valuestring = strdup("127.0.0.1");
    key->valuestring = strdup("key");

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, key);

    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *)1);

    expect_string(__wrap__mdebug1, formatted_msg, "Forwarding agent key request response to the master node for agent '001'");
    will_return(__wrap_w_request_agent_add_clustered, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent key request response forwarded to the master node for agent '001'");
    expect_function_call(__wrap_cJSON_Delete);
    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, 0);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(key);
    config.worker_node = 0;
}

void test_key_request_dispatch_success_add_agent(void **state) {
    char            *buffer = "id:001";
    cJSON           *field  = cJSON_CreateNumber(1);
    cJSON           *data   = cJSON_CreateNumber(2);
    cJSON           *id     = cJSON_CreateNumber(3);
    cJSON           *name   = cJSON_CreateNumber(4);
    cJSON           *ip     = cJSON_CreateNumber(5);
    cJSON           *key    = cJSON_CreateNumber(6);

    config.worker_node  = 0;
    field->valueint     = 0;
    id->valuestring     = strdup("001");
    name->valuestring   = strdup("test");
    ip->valuestring     = strdup("127.0.0.1");
    key->valuestring    = strdup("key");

    will_return(__wrap_external_socket_connect, 4);
    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 12);
    expect_string(__wrap__mdebug2, formatted_msg, "Socket output: Hello World!");

    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *)1);

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, key);

    expect_string(__wrap__mdebug1, formatted_msg, "Requesting local addition for agent '001' from the agent key request.");

    cJSON * response = NULL;
    cJSON * data_json = NULL;
    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", data_json = cJSON_CreateObject());
    cJSON_AddStringToObject(data_json, "id", id->valuestring);
    cJSON_AddStringToObject(data_json, "name", name->valuestring);
    cJSON_AddStringToObject(data_json, "ip", ip->valuestring);
    cJSON_AddStringToObject(data_json, "key", key->valuestring);

    expect_string(__wrap_local_add, id, id->valuestring);
    expect_string(__wrap_local_add, name, name->valuestring);
    expect_string(__wrap_local_add, ip, ip->valuestring);
    expect_string(__wrap_local_add, key, key->valuestring);
    will_return(__wrap_local_add, response);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent key request addition response: '{\"error\":0,\"data\":{\"id\":\"001\",\"name\":\"test\",\"ip\":\"127.0.0.1\",\"key\":\"key\"}}'");

    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);
    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, 0);

    __real_cJSON_Delete(response);
    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(key);

}

void test_key_request_dispatch_success_exec_output(void **state) {
    char            *buffer = "id:001";
    cJSON           *field  = cJSON_CreateNumber(1);
    cJSON           *data   = cJSON_CreateNumber(2);
    cJSON           *id     = cJSON_CreateNumber(3);
    cJSON           *name   = cJSON_CreateNumber(4);
    cJSON           *ip     = cJSON_CreateNumber(5);
    cJSON           *key    = cJSON_CreateNumber(6);

    config.worker_node  = 0;
    field->valueint     = 0;
    id->valuestring     = strdup("001");
    name->valuestring   = strdup("test");
    ip->valuestring     = strdup("127.0.0.1");
    key->valuestring    = strdup("key");

    config.key_request.socket = 0;
    config.key_request.exec_path = "python3 /tmp/test.py";

    expect_string(__wrap_wm_exec, command, "python3 /tmp/test.py id 001");
    expect_value(__wrap_wm_exec, secs, 1);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Output command");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Exec output: Output command");

    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *)1);
    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, key);

    expect_string(__wrap__mdebug1, formatted_msg, "Requesting local addition for agent '001' from the agent key request.");

    cJSON * response = NULL;
    cJSON * data_json = NULL;
    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", data_json = cJSON_CreateObject());
    cJSON_AddStringToObject(data_json, "id", id->valuestring);
    cJSON_AddStringToObject(data_json, "name", name->valuestring);
    cJSON_AddStringToObject(data_json, "ip", ip->valuestring);
    cJSON_AddStringToObject(data_json, "key", key->valuestring);

    expect_string(__wrap_local_add, id, id->valuestring);
    expect_string(__wrap_local_add, name, name->valuestring);
    expect_string(__wrap_local_add, ip, ip->valuestring);
    expect_string(__wrap_local_add, key, key->valuestring);
    will_return(__wrap_local_add, response);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent key request addition response: '{\"error\":0,\"data\":{\"id\":\"001\",\"name\":\"test\",\"ip\":\"127.0.0.1\",\"key\":\"key\"}}'");

    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);
    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, 0);

    __real_cJSON_Delete(response);
    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(key);

}

void test_key_request_dispatch_error_socket_success_exec_output(void **state) {
    char            *buffer = "id:001";
    cJSON           *field  = cJSON_CreateNumber(1);
    cJSON           *data   = cJSON_CreateNumber(2);
    cJSON           *id     = cJSON_CreateNumber(3);
    cJSON           *name   = cJSON_CreateNumber(4);
    cJSON           *ip     = cJSON_CreateNumber(5);
    cJSON           *key    = cJSON_CreateNumber(6);

    config.worker_node  = 0;
    field->valueint     = 0;
    id->valuestring     = strdup("001");
    name->valuestring   = strdup("test");
    ip->valuestring     = strdup("127.0.0.1");
    key->valuestring    = strdup("key");

    config.key_request.exec_path = "python3 /tmp/test.py";

    will_return(__wrap_external_socket_connect, 4);
    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 0);
    expect_string(__wrap__minfo, formatted_msg, "Socket connect fail. Trying to run 'exec_path'");

    expect_string(__wrap_wm_exec, command, "python3 /tmp/test.py id 001");
    expect_value(__wrap_wm_exec, secs, 1);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Output command");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Exec output: Output command");

    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *)1);
    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, key);

    expect_string(__wrap__mdebug1, formatted_msg, "Requesting local addition for agent '001' from the agent key request.");

    cJSON * response = NULL;
    cJSON * data_json = NULL;
    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", data_json = cJSON_CreateObject());
    cJSON_AddStringToObject(data_json, "id", id->valuestring);
    cJSON_AddStringToObject(data_json, "name", name->valuestring);
    cJSON_AddStringToObject(data_json, "ip", ip->valuestring);
    cJSON_AddStringToObject(data_json, "key", key->valuestring);

    expect_string(__wrap_local_add, id, id->valuestring);
    expect_string(__wrap_local_add, name, name->valuestring);
    expect_string(__wrap_local_add, ip, ip->valuestring);
    expect_string(__wrap_local_add, key, key->valuestring);
    will_return(__wrap_local_add, response);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent key request addition response: '{\"error\":0,\"data\":{\"id\":\"001\",\"name\":\"test\",\"ip\":\"127.0.0.1\",\"key\":\"key\"}}'");

    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);
    expect_value(__wrap_OSHash_Delete_ex, self, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, buffer);
    will_return(__wrap_OSHash_Delete_ex, 0);

    int ret = key_request_dispatch(buffer);
    assert_int_equal(ret, 0);

    __real_cJSON_Delete(response);
    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(key);

}

// Test key_request_exec_output()

void test_key_request_exec_output_too_long_request(void **state) {
    request_type_t type = K_TYPE_ID;
    char *request = "000";
    char exec_path[OS_MAXSTR];

    memset(exec_path, 'a', OS_MAXSTR);
    exec_path[OS_MAXSTR - 1] = '\0';
    config.key_request.exec_path = exec_path;

    expect_string(__wrap__mdebug1, formatted_msg, "Request is too long.");

    char *ret = key_request_exec_output(type,request);
    assert_null(ret);
}

void test_key_request_exec_output_result_code_no_zero(void **state) {
    char *exec_path = "python3 /tmp/test.py";
    config.key_request.exec_path = exec_path;
    request_type_t type = K_TYPE_ID;
    char *request = "000";

    expect_string(__wrap_wm_exec, command, "python3 /tmp/test.py id 000");
    expect_value(__wrap_wm_exec, secs, 1);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Output command");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mwarn, formatted_msg, "Key request integration (python3 /tmp/test.py) returned code 1.");

    char *ret = key_request_exec_output(type,request);
    assert_null(ret);
}

void test_key_request_exec_output_timeout_error(void **state) {
    char *exec_path = "python3 /tmp/test.py";
    config.key_request.exec_path = exec_path;
    request_type_t type = K_TYPE_ID;
    char *request = "000";

    expect_string(__wrap_wm_exec, command, "python3 /tmp/test.py id 000");
    expect_value(__wrap_wm_exec, secs, 1);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Output command");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 1);

    expect_string(__wrap__mwarn, formatted_msg, "Timeout received while running key request integration (python3 /tmp/test.py)");

    char *ret = key_request_exec_output(type,request);
    assert_null(ret);
}

void test_key_request_exec_output_path_invalid(void **state) {
    char *exec_path = "python3 /tmp/test.py";
    config.key_request.exec_path = exec_path;
    request_type_t type = K_TYPE_ID;
    char *request = "000";

    expect_string(__wrap_wm_exec, command, "python3 /tmp/test.py id 000");
    expect_value(__wrap_wm_exec, secs, 1);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Output command");
    will_return(__wrap_wm_exec, EXECVE_ERROR);
    will_return(__wrap_wm_exec, -1);

    expect_string(__wrap__mwarn, formatted_msg, "Cannot run key request integration (python3 /tmp/test.py): path is invalid or file has insufficient permissions.");

    char *ret = key_request_exec_output(type,request);
    assert_null(ret);
}

void test_key_request_exec_output_error_executing(void **state) {
    char *exec_path = "python3 /tmp/test.py";
    config.key_request.exec_path = exec_path;
    request_type_t type = K_TYPE_ID;
    char *request = "000";

    expect_string(__wrap_wm_exec, command, "python3 /tmp/test.py id 000");
    expect_value(__wrap_wm_exec, secs, 1);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Output command");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, -1);

    expect_string(__wrap__mwarn, formatted_msg, "Error executing [python3 /tmp/test.py]");

    char *ret = key_request_exec_output(type,request);
    assert_null(ret);
}

void test_key_request_exec_output_success(void **state) {
    char *exec_path = "python3 /tmp/test.py";
    config.key_request.exec_path = exec_path;
    request_type_t type = K_TYPE_ID;
    char *request = "000";

    expect_string(__wrap_wm_exec, command, "python3 /tmp/test.py id 000");
    expect_value(__wrap_wm_exec, secs, 1);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Output command");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    char *ret = key_request_exec_output(type,request);
    assert_string_equal(ret, "Output command");
    os_free(ret);
}

// main

int main(void) {
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_error_malformed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_message_malformed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_error_valuestring, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_data_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_id_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_name_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_ip_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_key_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_socket_output_not_connect, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_socket_output_long_request, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_socket_output_send_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_socket_output_no_data_received, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_socket_output_empty_string_received, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_socket_output_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_long_id, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_long_ip, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_invalid_request, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_bad_socket_output, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_error_parsing_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_error_parsing_agent_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_exec_output_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_success_add_agent, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_success_exec_output, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_dispatch_error_socket_success_exec_output, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_exec_output_too_long_request, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_exec_output_result_code_no_zero, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_exec_output_timeout_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_exec_output_path_invalid, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_exec_output_error_executing, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_key_request_exec_output_success, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
