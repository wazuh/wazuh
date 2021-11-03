/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "../../addagent/manage_agents.h"
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

#define BUFFERSIZE 1024
#define RELAUNCH_TIME 300
#define QUEUE_SIZE 5

pthread_mutex_t mutex_keys = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  cond_pending = PTHREAD_COND_INITIALIZER;
volatile int    write_pending = 0;
volatile int    running = 1;

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

    return OS_SUCCESS;
}

// Test get_agent_info_from_json()


void test_get_agent_info_from_json_malformed(void **state) {
    cJSON *input_raw_json = cJSON_CreateObject();
    char *error_msg = NULL;

    will_return(__wrap_cJSON_GetObjectItem, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Malformed JSON output received. No 'error' field found");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    free(input_raw_json);
}

void test_get_agent_info_from_json_error_malformed(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    field->valueint = 1;

    will_return(__wrap_cJSON_GetObjectItem, field);
    expect_string(__wrap__mdebug1, formatted_msg, "Malformed JSON output received. No 'error' field found");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    free(input_raw_json);
}

void test_get_agent_info_from_json_error(void **state) {
    cJSON   *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *message        = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    field->valueint = 1;
    message->valuestring = "Test";

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, message);

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_string_equal(message->valuestring, *error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(message);
    free(input_raw_json);
}

void test_get_agent_info_from_json_agent_data_not_found(void **state) {
    cJSON    *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent data not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    free(input_raw_json);
}

void test_get_agent_info_from_json_agent_id_not_found(void **state) {
    cJSON    *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent ID not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    free(input_raw_json);
}

void test_get_agent_info_from_json_agent_name_not_found(void **state) {
    cJSON    *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(1);
    cJSON   *id             = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    id->valuestring = "001";

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent ID not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    free(input_raw_json);
}

void test_get_agent_info_from_json_agent_ip_not_found(void **state) {
    cJSON    *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(1);
    cJSON   *id             = cJSON_CreateNumber(1);
    cJSON   *name           = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    id->valuestring = "001";
    name->valuestring = "test";

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent ID not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    free(input_raw_json);
}

void test_get_agent_info_from_json_agent_key_not_found(void **state) {
    cJSON    *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(1);
    cJSON   *id             = cJSON_CreateNumber(1);
    cJSON   *name           = cJSON_CreateNumber(1);
    cJSON   *ip            = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    id->valuestring = "001";
    name->valuestring = "test";
    ip->valuestring = "127.0.0.1";

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent ID not found.");

    void *ret = get_agent_info_from_json(input_raw_json, &error_msg);
    assert_null(ret);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    free(input_raw_json);
}

void test_get_agent_info_from_json_agent_success(void **state) {
    cJSON    *input_raw_json = cJSON_CreateObject();
    cJSON   *field          = cJSON_CreateNumber(1);
    cJSON   *data           = cJSON_CreateNumber(1);
    cJSON   *id             = cJSON_CreateNumber(1);
    cJSON   *name           = cJSON_CreateNumber(1);
    cJSON   *ip             = cJSON_CreateNumber(1);
    cJSON   *key            = cJSON_CreateNumber(1);
    char    *error_msg      = NULL;

    id->valuestring = "001";
    name->valuestring = "test";
    ip->valuestring = "127.0.0.1";
    key->valuestring = "key";

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
    free(input_raw_json);
    free(ret);
}

// Test keyrequest_socket_output()

void test_keyrequest_socket_output_not_connect(void **state) {
    char error_msg[128];

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, -1);

    snprintf(error_msg, OS_SIZE_128, "Could not connect to external socket: %s (%d)", strerror(errno), errno);
    expect_string(__wrap__mdebug1, formatted_msg, error_msg);
   
    expect_value(__wrap_sleep, seconds, 1);

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, -1);

    snprintf(error_msg, OS_SIZE_128, "Could not connect to external socket: %s (%d)", strerror(errno), errno);
    expect_string(__wrap__mdebug1, formatted_msg, error_msg);
    
    expect_value(__wrap_sleep, seconds, 2);

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, -1);

    snprintf(error_msg, OS_SIZE_128, "Could not connect to external socket: %s (%d)", strerror(errno), errno);
    expect_string(__wrap__mdebug1, formatted_msg, error_msg);

    expect_value(__wrap_sleep, seconds, 3);

    snprintf(error_msg, OS_SIZE_128, "Could not connect to external integration: %s (%d). Discarding request.", strerror(errno), errno);
    expect_string(__wrap__mwarn, formatted_msg, error_msg);

    char *ret = keyrequest_socket_output(W_TYPE_ID, "001");
    assert_null(ret);
}

void test_keyrequest_socket_output_long_request(void **state) {
    char buffer_request[OS_SIZE_128 + 1];
    memset(buffer_request, 'a', OS_SIZE_128 + 1);
 
    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Request too long for socket.");
    expect_value(__wrap_close, fd, 0);

    char *ret = keyrequest_socket_output(W_TYPE_ID, NULL);
    assert_null(ret);
}

void test_keyrequest_socket_output_send_fail(void **state) { 
    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, -1);
    expect_value(__wrap_close, fd, 0);

    char *ret = keyrequest_socket_output(W_TYPE_ID, NULL);
    assert_null(ret);
}

void test_keyrequest_socket_output_no_data_received(void **state) { 
    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "No data received from external socket");
    expect_value(__wrap_close, fd, 0);

    char *ret = keyrequest_socket_output(W_TYPE_ID, NULL);
    assert_null(ret);
}

void test_keyrequest_socket_output_empty_string_received(void **state) { 
    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 0);
    expect_value(__wrap_close, fd, 0);

    char *ret = keyrequest_socket_output(W_TYPE_ID, NULL);
    assert_null(ret);
}

void test_keyrequest_socket_output_success(void **state) { 
    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 4);
    will_return(__wrap_recv, "test");
    expect_value(__wrap_close, fd, 0);

    char *ret = keyrequest_socket_output(W_TYPE_ID, NULL);
    assert_string_equal(ret, "test");
}

// Test w_key_request_dispatch()

void test_w_key_request_dispatch_long_id(void **state) {
    authd_key_request_t *data = (authd_key_request_t *)(*state);
    char                *buffer = "id:000000001";

    expect_string(__wrap__mdebug1, formatted_msg, "Agent ID is too long");
    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, -1);
}


void test_w_key_request_dispatch_long_ip(void **state) {
    authd_key_request_t *data = (authd_key_request_t *)(*state);
    char                *buffer = "id:0.0.0.0.0.0.0.0.0.0";

    expect_string(__wrap__mdebug1, formatted_msg, "Agent IP is too long");
    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, -1);
}

void test_w_key_request_dispatch_wrong_request(void **state) {
    authd_key_request_t *data = (authd_key_request_t *)(*state);
    char                *buffer = "test";

    expect_string(__wrap__mdebug1, formatted_msg, "Wrong type of request");
    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, -1);
}

void test_w_key_request_dispatch_bad_socket_output(void **state) {
    authd_key_request_t *data   = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *error  = cJSON_CreateNumber(1);

    error->valuestring = "";

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, -1);
    expect_value(__wrap_close, fd, 0);

    assert_string_equal(error->valuestring, "");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, -1);

    __real_cJSON_Delete(error);
}

void test_w_key_request_dispatch_error_parsing_json(void **state) {
    authd_key_request_t *data   = (authd_key_request_t *)*state;
    char                *buffer = "id:001";

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 4);
    will_return(__wrap_recv, "test");
    expect_value(__wrap_close, fd, 0);

    will_return(__wrap_cJSON_ParseWithOpts, (char *)1);
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, 0);
}

void test_w_key_request_dispatch_error_parsing_agent_json(void **state) {
    authd_key_request_t *data   = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *field  = cJSON_CreateNumber(1);
    cJSON               *msg    = cJSON_CreateNumber(1);

    field->valueint = 1;
    msg->valuestring = "Test";

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 4);
    will_return(__wrap_recv, "test");
    expect_value(__wrap_close, fd, 0);

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, msg);

    expect_function_call(__wrap_cJSON_Delete);
    will_return(__wrap_OSHash_Delete_ex, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Could not get a key from ID 001. Error: 'test'.");

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, -1);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(msg);
}

void test_w_key_request_dispatch_success(void **state) {
    authd_key_request_t *data_state  = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *field  = cJSON_CreateNumber(1);
    cJSON               *data   = cJSON_CreateNumber(1);
    cJSON               *id     = cJSON_CreateNumber(1);
    cJSON               *name   = cJSON_CreateNumber(1);
    cJSON               *ip     = cJSON_CreateNumber(1);
    cJSON               *key    = cJSON_CreateNumber(1);

    config.worker_node = 1;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 4);
    will_return(__wrap_recv, "test");
    expect_value(__wrap_close, fd, 0);

    id->valuestring = "001";
    name->valuestring = "test";
    ip->valuestring = "127.0.0.1";
    key->valuestring = "key";

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, key);

    will_return(__wrap_w_request_agent_add_clustered, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Agent Key Polling response forwarded to the master node for agent '001'");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, 0);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(key);

    config.worker_node = 0;
}

void test_w_key_request_dispatch_success_add_agent(void **state) {
    authd_key_request_t *data_state   = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *field  = cJSON_CreateNumber(1);
    cJSON               *data   = cJSON_CreateNumber(1);
    cJSON               *id     = cJSON_CreateNumber(1);
    cJSON               *name   = cJSON_CreateNumber(1);
    cJSON               *ip     = cJSON_CreateNumber(1);
    cJSON               *key    = cJSON_CreateNumber(1);

    config.worker_node = 0;

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 0);
    will_return(__wrap_recv, 4);
    will_return(__wrap_recv, "test");
    expect_value(__wrap_close, fd, 0);

    id->valuestring = "001";
    name->valuestring = "test";
    ip->valuestring = "127.0.0.1";
    key->valuestring = "key";

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, key);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, 0);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(key);
}

void test_w_key_request_dispatch_exec_output_error(void **state) {
    authd_key_request_t *data_state   = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *id     = cJSON_CreateNumber(1);
    cJSON               *name   = cJSON_CreateNumber(1);
    cJSON               *ip     = cJSON_CreateNumber(1);
    cJSON               *key    = cJSON_CreateNumber(1);


    config.key_request.socket = 0;

   /* Exec output */

    will_return(__wrap_send, -1);
    expect_value(__wrap_close, fd, 0);

    id->valuestring = "001";
    name->valuestring = "test";
    ip->valuestring = "127.0.0.1";
    key->valuestring = "key";

    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, 0);
}

void test_w_key_request_dispatch_success_exec_output(void **state) {
    authd_key_request_t *data_state   = (authd_key_request_t *)*state;
    char                *buffer = "id:001";
    cJSON               *field  = cJSON_CreateNumber(1);
    cJSON               *data   = cJSON_CreateNumber(1);
    cJSON               *id     = cJSON_CreateNumber(1);
    cJSON               *name   = cJSON_CreateNumber(1);
    cJSON               *ip     = cJSON_CreateNumber(1);
    cJSON               *key    = cJSON_CreateNumber(1);

    config.worker_node = 0;
    config.key_request.socket = 0;

   /* Exec output */

    expect_value(__wrap__mtdebug2, formatted_msg, "Socket output: ");

    id->valuestring = "001";
    name->valuestring = "test";
    ip->valuestring = "127.0.0.1";
    key->valuestring = "key";

    will_return(__wrap_cJSON_GetObjectItem, field);
    will_return(__wrap_cJSON_GetObjectItem, data);
    will_return(__wrap_cJSON_GetObjectItem, id);
    will_return(__wrap_cJSON_GetObjectItem, name);
    will_return(__wrap_cJSON_GetObjectItem, ip);
    will_return(__wrap_cJSON_GetObjectItem, key);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = w_key_request_dispatch(buffer);
    assert_int_equal(ret, 0);

    __real_cJSON_Delete(field);
    __real_cJSON_Delete(data);
    __real_cJSON_Delete(id);
    __real_cJSON_Delete(name);
    __real_cJSON_Delete(ip);
    __real_cJSON_Delete(key);
}

// Test w_request_thread()

void test_w_request_thread(void **state) {
    int i;
    w_queue_t *queue = queue_init(QUEUE_SIZE);
    int *ptr = NULL;
    for (i=0; i < QUEUE_SIZE - 1; i++){
        ptr = malloc(sizeof(int));
        *ptr = i;
        queue_push(queue, ptr);
    }
    // Pop items from full queue
    for(i=0; i < QUEUE_SIZE - 1; i++) {
        ptr = queue_pop(queue);
        assert_int_equal(*ptr, i);
        os_free(ptr);
    }
    // Should be empty now
    ptr = queue_pop(queue);
    assert_ptr_equal(ptr, NULL);
    os_free(ptr);
}

// Test keyrequest_exec_output()

void test_keyrequest_exec_output_too_long_request(void **state) {
    _request_type_t type = (_request_type_t*)*state;
    char *request = "";

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Request is too long.");
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    void *ret = keyrequest_exec_output(type,request);
    assert_null(ret);
}

void test_keyrequest_exec_output_error_flag_to_one(void **state) {
    _request_type_t type = (_request_type_t*)*state;
    char *request = "";
    int error_flag = 0;

    will_return(__wrap_error_flag,error_flag);

    void *ret = keyrequest_exec_output(type,request);
    assert_null(ret)
}

void test_keyrequest_exec_output_result_code_no_zero(void **state) {
    char *exec_path = config.key_request.exec_path;
    config.key_request.exec_path = "python3 /tmp/test.py";
    _request_type_t type = (_request_type_t*)*state;
    char *request = "";
    int error_flag = 0;
    int result_code = 0;

    will_return(__wrap_error_flag,error_flag);
    will_return(__wrap_result_code,result_code);
    will_return(__wrap_wm_exec, 0);

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Key request integration (%s) returned code %d.", config.key_request.exec_path, result_code);
    expect_string(__wrap__mwarn, formatted_msg, debug_msg);

    config.key_request.exec_path = exec_path;

    void *ret = keyrequest_exec_output(type,request);
    assert_null(ret)
}

void test_keyrequest_exec_output_timeout_error(void **state) {
    char *exec_path = config.key_request.exec_path;
    config.key_request.exec_path = "python3 /tmp/test.py";
    _request_type_t type = (_request_type_t*)*state;
    char *request = "";
    int error_flag = 0;
    int result_code = 0;

    will_return(__wrap_error_flag,error_flag);
    will_return(__wrap_result_code,result_code);
    will_return(__wrap_wm_exec, KR_ERROR_TIMEOUT);

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Timeout received while running key request integration (%s)", config.key_request.exec_path);
    expect_string(__wrap__mwarn, formatted_msg, debug_msg);

    config.key_request.exec_path = exec_path;

    void *ret = keyrequest_exec_output(type,request);
    assert_null(ret)
}

void test_keyrequest_exec_output_path_invalid(void **state) {
    char *exec_path = config.key_request.exec_path;
    config.key_request.exec_path = "python3 /tmp/test.py";
    _request_type_t type = (_request_type_t*)*state;
    char *request = "";
    int error_flag = 1;
    int result_code = EXECVE_ERROR;

    will_return(__wrap_error_flag,error_flag);
    will_return(__wrap_result_code,result_code);
    will_return(__wrap_wm_exec, 1);

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Cannot run key request integration (%s): path is invalid or file has insufficient permissions.", config.key_request.exec_path);
    expect_string(__wrap__mwarn, formatted_msg, debug_msg);

    config.key_request.exec_path = exec_path;

    void *ret = keyrequest_exec_output(type,request);
    assert_null(ret)
}

void test_keyrequest_exec_output_error_executing(void **state) {
    char *exec_path = config.key_request.exec_path;
    config.key_request.exec_path = "python3 /tmp/test.py";
    _request_type_t type = (_request_type_t*)*state;
    char *request = "";
    int error_flag = 1;

    will_return(__wrap_error_flag,error_flag);
    will_return(__wrap_wm_exec, 1);

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Error executing [%s]", config.key_request.exec_path);
    expect_string(__wrap__mwarn, formatted_msg, debug_msg);

    config.key_request.exec_path = exec_path;

    void *ret = keyrequest_exec_output(type,request);
    assert_null(ret)
}

void test_keyrequest_exec_output_chroot_error(void **state) {
    _request_type_t type = (_request_type_t*)*state;
    char *request = "";
    int error_flag = 1;

    will_return(__wrap_error_flag,error_flag);

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, CHROOT_ERROR, "/var/ossec", errno, strerror(errno));
    expect_string(__wrap__merror, formatted_msg, debug_msg);

    void *ret = keyrequest_exec_output(type,request);
    assert_null(ret)
}

// main

int main(void) {
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_malformed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_error_malformed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_data_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_id_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_name_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_ip_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_key_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_info_from_json_agent_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_socket_output_not_connect, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_socket_output_long_request, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_socket_output_send_fail, test_setup, test_teardown), 
        cmocka_unit_test_setup_teardown(test_keyrequest_socket_output_no_data_received, test_setup, test_teardown), 
        cmocka_unit_test_setup_teardown(test_keyrequest_socket_output_empty_string_received, test_setup, test_teardown), 
        cmocka_unit_test_setup_teardown(test_keyrequest_socket_output_success, test_setup, test_teardown), 
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_long_id, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_long_ip, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_wrong_request, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_bad_socket_output, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_error_parsing_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_error_parsing_agent_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_success_add_agent, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_exec_output_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_key_request_dispatch_success_exec_output, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_exec_output_too_long_request, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_exec_output_error_flag_to_one, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_exec_output_result_code_no_zero, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_exec_output_timeout_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_exec_output_path_invalid, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_exec_output_error_executing, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_keyrequest_exec_output_chroot_error, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
