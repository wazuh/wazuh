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
#include <stdlib.h>

#include "remoted/remoted.h"
#include "remoted/state.h"
#include "headers/shared.h"

#include "../wrappers/common.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/wazuh/os_crypto/keys_wrappers.h"
#include "../wrappers/wazuh/os_crypto/msgs_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/time_op_wrappers.h"
#include "../wrappers/wazuh/remoted/netbuffer_wrappers.h"

extern remoted_state_t remoted_state;

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

static int test_setup_tcp(void ** state) {
    test_mode = 1;

    keyentry *node_key = NULL;
    os_calloc(1, sizeof(keyentry), node_key);
    node_key->net_protocol = REMOTED_NET_PROTOCOL_TCP;
    node_key->rcvd = 10;
    node_key->sock = 15;
    node_key->id = "001";
    os_calloc(2, sizeof(keyentry*), keys.keyentries);
    keys.keyentries[0] = node_key;
    keys.keyentries[1] = NULL;

    return 0;
}

static int test_teardown_tcp(void ** state) {
    test_mode = 0;

    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);

    return 0;
}

/* Tests */

void test_send_msg_tcp_ok(void ** state) {
    (void) state;

    char *agent_id = "001";
    char *msg = "abcdefghijk";
    ssize_t msg_length = 11;
    int key = 0;

    char *crypto_msg = "!@#123abc";
    ssize_t crypto_size = 9;

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    expect_function_call(__wrap_pthread_mutex_lock);

    will_return(__wrap_time, (time_t)0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_nb_queue, socket, 15);
    expect_string(__wrap_nb_queue, crypt_msg, crypto_msg);
    expect_value(__wrap_nb_queue, msg_size, crypto_size);
    expect_value(__wrap_nb_queue, agent_id, agent_id);
    will_return(__wrap_nb_queue, 0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_pthread_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, 0);
}

void test_send_msg_tcp_err(void ** state) {
    (void) state;

    char *agent_id = "001";
    char *msg = "abcdefghijk";
    ssize_t msg_length = 11;
    int key = 0;

    char *crypto_msg = "!@#123abc";
    ssize_t crypto_size = 9;

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    expect_function_call(__wrap_pthread_mutex_lock);

    will_return(__wrap_time, (time_t)0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_nb_queue, socket, 15);
    expect_string(__wrap_nb_queue, crypt_msg, crypto_msg);
    expect_value(__wrap_nb_queue, msg_size, crypto_size);
    expect_value(__wrap_nb_queue, agent_id, agent_id);
    will_return(__wrap_nb_queue, -1);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_pthread_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_send_msg_tcp_ok, test_setup_tcp, test_teardown_tcp),
        cmocka_unit_test_setup_teardown(test_send_msg_tcp_err, test_setup_tcp, test_teardown_tcp),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
