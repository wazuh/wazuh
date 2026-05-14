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

#include "../remoted/remoted.h"
#include "../remoted/state.h"
#include "../headers/shared.h"

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

static int test_setup_keys(void ** state) {
    test_mode = 1;

    keyentry *node_key = NULL;
    os_calloc(1, sizeof(keyentry), node_key);
    node_key->rcvd = 10;
    node_key->sock = 15;
    os_strdup("001",node_key->id);

    os_calloc(2, sizeof(keyentry*), keys.keyentries);
    keys.keyentries[0] = node_key;
    keys.keyentries[1] = NULL;

    return 0;
}

static int test_teardown_keys(void **state){
    test_mode = 0;

    os_free(keys.keyentries[0]->id);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);

    return 0;
}

static int test_setup_tcp(void ** state) {

    test_setup_keys(state);
    keys.keyentries[0]->net_protocol = REMOTED_NET_PROTOCOL_TCP;

    return 0;
}

static int test_teardown_tcp(void ** state) {
    return test_teardown_keys(state);
}

static int test_setup_udp(void ** state) {

    test_setup_keys(state);
    keys.keyentries[0]->net_protocol = REMOTED_NET_PROTOCOL_UDP;

    return 0;
}

static int test_teardown_udp(void ** state) {
    return test_teardown_keys(state);
}

/* Tests */

void test_send_msg_invalid_agent(void ** state) {
    (void) state;

    const char *const agent_id = "555";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);


    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);

    // Setup invalid agent error
    will_return(__wrap_OS_IsAllowedID, -1);

    expect_function_call(__wrap_rwlock_unlock);

    expect_string(__wrap__merror, formatted_msg, "(1320): Agent '555' not found.");

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

void test_send_msg_disconnected_agent(void ** state) {
    (void) state;

    const char *const agent_id = "001";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);

    const int key = 0;

    // Setup disconnected agent
    const time_t now = 1000;
    logr.global.agents_disconnection_time = 300;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, now);

    expect_function_call(__wrap_rwlock_unlock);

    expect_string(__wrap__mdebug1, formatted_msg, "(1245): Sending message to disconnected agent '001'.");

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

void test_send_msg_encryption_error(void ** state) {
    (void) state;

    const char *const agent_id = "001";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);
    const int key = 0;

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);

    // Setup message encryption error
    const char *const crypto_msg = "";
    const ssize_t crypto_size = 0;
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_rwlock_unlock);

    expect_string(__wrap__merror,formatted_msg,"(1217): Error creating encrypted message.");

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

void test_send_msg_tcp_ok(void ** state) {
    (void) state;

    char *agent_id = "001";
    char *msg = "abcdefghijk";
    ssize_t msg_length = strlen(msg);
    int key = 0;

    char *crypto_msg = "!@#123abc";
    ssize_t crypto_size = strlen(crypto_msg);

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_nb_queue, socket, 15);
    expect_string(__wrap_nb_queue, crypt_msg, crypto_msg);
    expect_value(__wrap_nb_queue, msg_size, crypto_size);
    expect_string(__wrap_nb_queue, agent_id, agent_id);
    will_return(__wrap_nb_queue, 0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, 0);
}

void test_send_msg_tcp_err(void ** state) {
    (void) state;

    char *agent_id = "001";
    char *msg = "abcdefghijk";
    ssize_t msg_length = strlen(msg);
    int key = 0;

    char *crypto_msg = "!@#123abc";
    ssize_t crypto_size = strlen(crypto_msg);

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_nb_queue, socket, 15);
    expect_string(__wrap_nb_queue, crypt_msg, crypto_msg);
    expect_value(__wrap_nb_queue, msg_size, crypto_size);
    expect_string(__wrap_nb_queue, agent_id, agent_id);
    will_return(__wrap_nb_queue, -1);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

void test_send_msg_tcp_err_closed_socket(void ** state) {
    (void) state;

    const char *const agent_id = "001";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);
    const int key = 0;

    const char *const crypto_msg = "!@#123abc";
    const ssize_t crypto_size = strlen(crypto_msg);

    logr.global.agents_disconnection_time = 0;

    // Setup closed socket
    keys.keyentries[0]->sock=-1;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_rwlock_unlock);

    expect_string(__wrap__mdebug1, formatted_msg, "Send operation cancelled due to closed socket.");

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

void test_send_msg_udp_ok(void ** state) {
    (void) state;

    const char *const agent_id = "001";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);
    const int key = 0;

    const char *const crypto_msg = "!@#123abc";
    const ssize_t crypto_size = strlen(crypto_msg);

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    will_return(__wrap_sendto, crypto_size);

    expect_value(__wrap_rem_add_send, bytes, crypto_size);

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, 0);
}

void test_send_msg_udp_error(void ** state) {
    (void) state;

    const char *const agent_id = "001";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);
    const int key = 0;

    const char *const crypto_msg = "!@#123abc";
    const ssize_t crypto_size = strlen(crypto_msg);

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    // Setup udp connection error
    will_return(__wrap_sendto, 0);
    errno = 0;

    expect_string(__wrap__mwarn,formatted_msg,"(1218): Unable to send message to '001': A message could not be delivered completely. [15]");

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

void test_send_msg_udp_error_connection_reset(void ** state) {
    (void) state;

    const char *const agent_id = "001";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);
    const int key = 0;

    const char *const crypto_msg = "!@#123abc";
    const ssize_t crypto_size = strlen(crypto_msg);

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    // Setup udp connection reset error
    will_return(__wrap_sendto, 0);
    errno = ECONNRESET;

    expect_string(__wrap__mdebug1,formatted_msg,"(1218): Unable to send message to '001': Agent may have disconnected. [15]");

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

void test_send_msg_udp_error_agent_not_responding(void ** state) {
    (void) state;

    const char *const agent_id = "001";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);
    const int key = 0;

    const char *const crypto_msg = "!@#123abc";
    const ssize_t crypto_size = strlen(crypto_msg);

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    // Setup udp connection reset error
    will_return(__wrap_sendto, 0);
    errno = EAGAIN;

    expect_string(__wrap__mwarn,formatted_msg,"(1218): Unable to send message to '001': Agent is not responding. [15]");

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

void test_send_msg_udp_error_generic(void ** state) {
    (void) state;

    const char *const agent_id = "001";
    const char *const msg = "abcdefghijk";
    const ssize_t msg_length = strlen(msg);
    const int key = 0;

    const char *const crypto_msg = "!@#123abc";
    const ssize_t crypto_size = strlen(crypto_msg);

    logr.global.agents_disconnection_time = 0;

    expect_function_call(__wrap_rwlock_lock_read);

    expect_string(__wrap_OS_IsAllowedID, id, agent_id);
    will_return(__wrap_OS_IsAllowedID, key);

    will_return(__wrap_time, (time_t)0);

    expect_string(__wrap_CreateSecMSG, msg, msg);
    expect_value(__wrap_CreateSecMSG, msg_length, msg_length);
    expect_value(__wrap_CreateSecMSG, id, key);
    will_return(__wrap_CreateSecMSG, crypto_size);
    will_return(__wrap_CreateSecMSG, crypto_msg);

    expect_function_call(__wrap_pthread_mutex_lock);

    // Setup udp error
    will_return(__wrap_sendto, 0);
    errno = EACCES;

    expect_string(__wrap__merror,formatted_msg,"(1218): Unable to send message to '001': Permission denied [15]");

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_rwlock_unlock);

    int ret = send_msg(agent_id, msg, msg_length);

    assert_int_equal(ret, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Guard clauses tests
        cmocka_unit_test_setup_teardown(test_send_msg_invalid_agent, test_setup_keys, test_teardown_keys),
        cmocka_unit_test_setup_teardown(test_send_msg_disconnected_agent, test_setup_keys, test_teardown_keys),
        cmocka_unit_test_setup_teardown(test_send_msg_encryption_error, test_setup_keys, test_teardown_keys),

        // TCP tests
        cmocka_unit_test_setup_teardown(test_send_msg_tcp_ok, test_setup_tcp, test_teardown_tcp),
        cmocka_unit_test_setup_teardown(test_send_msg_tcp_err, test_setup_tcp, test_teardown_tcp),
        cmocka_unit_test_setup_teardown(test_send_msg_tcp_err_closed_socket, test_setup_tcp, test_teardown_tcp),

        // UDP tests
        cmocka_unit_test_setup_teardown(test_send_msg_udp_ok, test_setup_udp, test_teardown_udp),
        cmocka_unit_test_setup_teardown(test_send_msg_udp_error, test_setup_udp, test_teardown_udp),
        cmocka_unit_test_setup_teardown(test_send_msg_udp_error_connection_reset, test_setup_udp, test_teardown_udp),
        cmocka_unit_test_setup_teardown(test_send_msg_udp_error_agent_not_responding, test_setup_udp, test_teardown_udp),
        cmocka_unit_test_setup_teardown(test_send_msg_udp_error_generic, test_setup_udp, test_teardown_udp),

    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
