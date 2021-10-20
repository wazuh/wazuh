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
#include "../../addagent/manage_agents.h"
#include "../../headers/sec.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define IPV4 "127.0.0.1"
#define IPV6 "::1"
#define PORT 4321
#define SENDSTRING "Hello World!\n"
#define BUFFERSIZE 1024
#define RELAUNCH_TIME 300

static const int QUEUE_SIZE = 5;
authd_config_t config;

// Structs

typedef struct test_key_request_struct {
    int             enabled;
    char            *exec_path;
    char            *socket;
    unsigned int    timeout;
    unsigned int    threads;
    unsigned int    queue_size;
    wfd_t           *wfd;
} test_krequest_t;


// setup/teardowns

static int test_setup(void **state) {
    test_krequest_t *init_data = NULL;
    os_calloc(1, sizeof(test_krequest_t), init_data);
    os_calloc(1, sizeof(wfd_t), init_data->wfd);

    init_data->timeout = 1;
    init_data->threads = 1;
    init_data->queue_size = BUFFERSIZE;

    os_strdup("/tmp/tmp_file-XXXXXX", init_data->socket);

    *state = init_data;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_krequest_t *data  = (test_krequest_t *)*state;
    unlink(data->socket);
    os_free(data->socket);
    os_free(data->wfd);
    os_free(data);

    return OS_SUCCESS;
}

// Test wm_key_request_dispatch()

void test_wm_key_request_dispatch_success_id(void **state) {
    authd_key_request_t *data   = (test_krequest_t *)*state;
    const char          *buffer = "id:001";
    cJSON               *id1    = cJSON_CreateNumber(1);
    cJSON               *id2    = cJSON_CreateNumber(1);
    config.key_request.socket   = "/tmp/test";

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 1);

    will_return(__wrap_recv, 1);

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);

    will_return(__wrap_w_is_worker, 0);
    will_return(__wrap_w_request_agent_add_clustered, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Agent Key Polling response forwarded to the master node for agent '001'");
    expect_function_call(__wrap_cJSON_Delete);
    will_return(__wrap_OSHash_Delete_ex, NULL);


    int ret = wm_key_request_dispatch(buffer, data);
    assert_int_equal(ret, -0);

    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(id2);
}

void test_wm_key_request_dispatch_success_ip(void **state) {
    authd_key_request_t *data   = (test_krequest_t *)*state;
    const char          *buffer = "ip:127.0.0.1";
    cJSON               *id1    = cJSON_CreateNumber(1);
    cJSON               *id2    = cJSON_CreateNumber(1);
    config.key_request.socket   = "/tmp/test";

    will_return(__wrap_socket, 4);
    will_return(__wrap_connect, 0);
    will_return(__wrap_getsockopt, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);

    will_return(__wrap_send, 1);

    will_return(__wrap_recv, 1);

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);

    will_return(__wrap_w_is_worker, 0);
    will_return(__wrap_w_request_agent_add_clustered, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Agent Key Polling response forwarded to the master node for agent '001'");
    expect_function_call(__wrap_cJSON_Delete);
    will_return(__wrap_OSHash_Delete_ex, NULL);


    int ret = wm_key_request_dispatch(buffer, data);
    assert_int_equal(ret, -0);

    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(id2);
}

void test_wm_key_request_dispatch_no_socket(void **state) {
    authd_key_request_t *data   = (test_krequest_t *)*state;
    const char          *buffer = "ip:127.0.0.1";
    cJSON               *id1    = cJSON_CreateNumber(1);
    cJSON               *id2    = cJSON_CreateNumber(1);
    config.key_request.socket   = NULL;

    will_return(__wrap_wm_exec, 0);

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id1);

    will_return(__wrap_w_is_worker, 0);
    will_return(__wrap_w_request_agent_add_clustered, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Agent Key Polling response forwarded to the master node for agent '001'");
    expect_function_call(__wrap_cJSON_Delete);
    will_return(__wrap_OSHash_Delete_ex, NULL);


    int ret = wm_key_request_dispatch(buffer, data);
    assert_int_equal(ret, -0);

    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(id2);
}


void test_wm_key_request_dispatch_long_id(void **state) {
    authd_key_request_t *data = (test_krequest_t *)*state;
    const char          *buffer = "id:000000001";

    expect_string(__wrap__mdebug1, formatted_msg, "Agent ID is too long");
    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = wm_key_request_dispatch(buffer, data);
    assert_int_equal(ret, -1);
}


void test_wm_key_request_dispatch_long_ip(void **state) {
    authd_key_request_t *data = (test_krequest_t *)*state;
    const char          *buffer = "id:0.0.0.0.0.0.0.0.0.0";

    expect_string(__wrap__mdebug1, formatted_msg, "Agent IP is too long");
    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = wm_key_request_dispatch(buffer, data);
    assert_int_equal(ret, -1);
}

void test_wm_key_request_dispatch_wrong_request(void **state) {
    authd_key_request_t *data = (test_krequest_t *)*state;
    const char          *buffer = "test";

    expect_string(__wrap__mdebug1, formatted_msg, "Wrong type of request");
    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    int ret = wm_key_request_dispatch(buffer, data);
    assert_int_equal(ret, -1);
}


// Test wm_key_request_destroy()


// Test wm_key_request_dump()



// Test w_request_thread()

void w_request_thread(void **state) {
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


// Test w_socket_launcher()

void test_w_socket_launcher_bad_execution_path(void **state) {
    test_krequest_t *data  = (test_krequest_t *)*state;
    data->exec_path = "python3";

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Running integration daemon: %s", data->exec_path);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    snprintf(debug_msg, BUFFERSIZE, "Could not split integration command: %s", data->exec_path);
    expect_string(__wrap__merror, formatted_msg, debug_msg);

    void *ret = w_socket_launcher(data->exec_path);
    assert_null(ret);
}

void test_w_socket_launcher_success(void **state) {
    test_krequest_t *data  = (test_krequest_t *)*state;
    data->exec_path = "python3 /tmp/test.py";
    data->wfd->file_out = (FILE*) 1234;

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Running integration daemon: %s", data->exec_path);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    will_return(__wrap_wpopenv, data->wfd);
    will_return(__wrap_fgets, "000 wrong line\n");

    void *ret = w_socket_launcher(data->exec_path);
    assert_null(ret);
}

void test_w_socket_launcher_relaunch_execution(void **state) {
    test_krequest_t *data  = (test_krequest_t *)*state;
    data->exec_path = "python3 /tmp/test.py";

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Running integration daemon: %s", data->exec_path);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    snprintf(debug_msg, BUFFERSIZE, "Couldn not execute '%s'. Trying again in %d seconds.", data->exec_path, RELAUNCH_TIME);
    expect_string(__wrap__merror, formatted_msg, debug_msg);

    void *ret = w_socket_launcher(data->exec_path);
    assert_null(ret);
}

void test_w_socket_launcher_invalid_path_or_permissions(void **state) {
    test_krequest_t *data  = (test_krequest_t *)*state;
    data->exec_path = "python3 /tmp/test.py";
    int wstatus = EXECVE_ERROR;

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Running integration daemon: %s", data->exec_path);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    will_return(__wrap_wpopenv, data->wfd);
    will_return(__wrap_fgets, "000 wrong line\n");

    snprintf(debug_msg, BUFFERSIZE, "Cannot run key pulling integration (%s): path is invalid or file has insufficient permissions. Retrying in %d seconds.", data->exec_path, RELAUNCH_TIME);
    expect_string(__wrap__merror, formatted_msg, debug_msg);

    void *ret = w_socket_launcher(data->exec_path);
    assert_null(ret);
}

void test_w_socket_launcher_warn_time_less_than_ten(void **state) {
    test_krequest_t *data  = (test_krequest_t *)*state;
    data->exec_path = "python3 /tmp/test.py";
    int wstatus = 0;

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Running integration daemon: %s", data->exec_path);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    will_return(__wrap_wpopenv, data->wfd);
    will_return(__wrap_fgets, "000 wrong line\n");

    snprintf(debug_msg, BUFFERSIZE, "Key pulling integration (%s) returned code %d. Retrying in %d seconds.", exec_path, wstatus, RELAUNCH_TIME);
    expect_string(__wrap__mwarn, formatted_msg, debug_msg);

    void *ret = w_socket_launcher(data->exec_path);
    assert_null(ret);
}

void test_w_socket_launcher_warn_wstatus(void **state) {
    test_krequest_t *data  = (test_krequest_t *)*state;
    data->exec_path = "python3 /tmp/test.py";
    int wstatus = 10;

    char debug_msg[BUFFERSIZE];
    snprintf(debug_msg, BUFFERSIZE, "Running integration daemon: %s", data->exec_path);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    will_return(__wrap_wpopenv, data->wfd);
    will_return(__wrap_fgets, "000 wrong line\n");

    snprintf(debug_msg, BUFFERSIZE, "Key pulling integration (%s) returned code %d. Restarting.", exec_path, wstatus);
    expect_string(__wrap__mwarn, formatted_msg, debug_msg);

    void *ret = w_socket_launcher(data->exec_path);
    assert_null(ret);    
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(),
        cmocka_unit_test_teardown(),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
