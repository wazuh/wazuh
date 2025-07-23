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
#include <errno.h>
#include <string.h>

#include "../../headers/shared.h"
#include "../../headers/sec.h"
#include "../../addagent/validate.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/libc/string_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "cJSON.h"

/* redefinitons/wrapping */

extern cJSON* w_create_agent_add_payload(const char *name, const char *ip, const char *groups, const char *key_hash, const char *key, const char *id, authd_force_options_t *force_options);
extern cJSON* w_create_agent_remove_payload(const char *id, const int purge);
extern cJSON* w_create_sendsync_payload(const char *daemon_name, cJSON *message);
extern int w_parse_agent_add_response(const char* buffer, char *err_response, char* id, char* key, const int json_format, const int exit_on_error);
extern int w_parse_agent_remove_response(const char* buffer, char *err_response, const int json_format, const int exit_on_error);

static void test_create_agent_add_payload(void **state) {
    char* agent = "agent1";
    char* ip = "192.0.0.0";
    char* groups = "Group1,Group2";
    char* key = "1234";
    char* key_hash = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";
    authd_force_options_t force_options = {0};
    char* id = "001";
    cJSON* payload = NULL;
    char* expected_force_payload = "{\"disconnected_time\":{\"enabled\":false,\"value\":0},"
                                   "\"enabled\":true,\"key_mismatch\":false,\"after_registration_time\":0}";

    force_options.disconnected_time_enabled = false;
    force_options.disconnected_time = 0;
    force_options.enabled = true;
    force_options.key_mismatch = false;
    force_options.after_registration_time = 0;

    payload = w_create_agent_add_payload(agent, ip, groups, key_hash, key, id, &force_options);

    assert_non_null(payload);
    cJSON* function = cJSON_GetObjectItem(payload, "function");
    assert_non_null(function);
    assert_string_equal(function->valuestring, "add");

    cJSON* arguments = cJSON_GetObjectItem(payload, "arguments");
    assert_non_null(arguments);

    cJSON* item = NULL;
    item = cJSON_GetObjectItem(arguments, "groups");
    assert_non_null(item);
    assert_string_equal(item->valuestring, groups);

    item = cJSON_GetObjectItem(arguments, "key");
    assert_non_null(item);
    assert_string_equal(item->valuestring, key);

    item = cJSON_GetObjectItem(arguments, "key_hash");
    assert_non_null(item);
    assert_string_equal(item->valuestring, key_hash);

    item = cJSON_GetObjectItem(arguments, "id");
    assert_non_null(item);
    assert_string_equal(item->valuestring, id);

    cJSON* j_force = cJSON_GetObjectItem(arguments, "force");
    assert_non_null(j_force);

    char* str_force = cJSON_PrintUnformatted(j_force);
    assert_string_equal(str_force, expected_force_payload);

    cJSON_Delete(payload);
    os_free(str_force);
}

#ifndef WIN32
static void test_create_agent_remove_payload(void **state) {
    char* id = "001";
    int purge = 1;
    cJSON* payload = NULL;
    payload = w_create_agent_remove_payload(id, purge);

    assert_non_null(payload);
    cJSON* function = cJSON_GetObjectItem(payload, "function");
    assert_non_null(function);
    assert_string_equal(function->valuestring, "remove");

    cJSON* arguments = cJSON_GetObjectItem(payload, "arguments");
    assert_non_null(arguments);

    cJSON* item = NULL;
    item = cJSON_GetObjectItem(arguments, "id");
    assert_non_null(item);
    assert_string_equal(item->valuestring, id);


    item = cJSON_GetObjectItem(arguments, "purge");
    assert_non_null(item);
    assert_int_equal(item->valueint, purge);

    cJSON_Delete(payload);
}

static void test_create_sendsync_payload(void **state) {
    char* daemon = "daemon_test";
    char* id = "001";
    int purge = 1;
    cJSON* payload = NULL;
    cJSON* message = NULL;
    cJSON* item = NULL;
    /* NULL message */
    payload = w_create_sendsync_payload(daemon, message);

    assert_non_null(payload);

    item = cJSON_GetObjectItem(payload, "daemon_name");
    assert_non_null(item);
    assert_string_equal(item->valuestring, daemon);

    item = cJSON_GetObjectItem(payload, "message");
    assert_null(item);

    cJSON_Delete(payload);

    /* non NULL message */
    message = w_create_agent_remove_payload(id,purge);
    payload = w_create_sendsync_payload(daemon, message);

    assert_non_null(payload);

    item = cJSON_GetObjectItem(payload, "daemon_name");
    assert_non_null(item);
    assert_string_equal(item->valuestring, daemon);

    item = cJSON_GetObjectItem(payload, "message");
    assert_non_null(item);

    cJSON_Delete(payload);
}

static void test_parse_agent_remove_response(void **state) {
    char* success_response = "{\"error\":0}";
    char* error_response = "{\"error\":9009,\"message\":\"ERROR_MESSAGE\"}";
    char* unknown_response = "{\"message \":\"any_message\"}";
    int err = 0;
    char err_response[OS_MAXSTR + 1];

    // Remove _merror checks
    expect_any_always(__wrap__merror, formatted_msg);

    /* Success parse */
    err = w_parse_agent_remove_response(success_response, err_response, FALSE, FALSE);
    assert_int_equal(err, 0);

    /* Error parse */
    err = w_parse_agent_remove_response(error_response, err_response, FALSE, FALSE);
    assert_int_equal(err, -1);
    assert_string_equal(err_response, "ERROR: ERROR_MESSAGE");

    /* Unknown parse */
    err = w_parse_agent_remove_response(unknown_response, err_response, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");
}

/* Tests w_send_clustered_message */

void test_w_send_clustered_message_connection_error(void **state) {
    char response[OS_MAXSTR + 1];

    for (int i=0; i < CLUSTER_SEND_MESSAGE_ATTEMPTS; ++i) {
        will_return(__wrap_external_socket_connect, -1);

        will_return(__wrap_strerror, "ERROR");
        expect_string(__wrap__mwarn, formatted_msg, "Could not connect to socket 'queue/cluster/c-internal.sock': ERROR (0).");
    }
    expect_value_count(__wrap_sleep, seconds, 1, 9);

    expect_string(__wrap__merror, formatted_msg, "Could not send message through the cluster after '10' attempts.");

    assert_int_equal(w_send_clustered_message("command", "payload", response), -2);
}

void test_w_send_clustered_message_send_error(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    for (int i=0; i < CLUSTER_SEND_MESSAGE_ATTEMPTS; ++i) {
        will_return(__wrap_external_socket_connect, sock_num);

        expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
        expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
        expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
        expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
        will_return(__wrap_OS_SendSecureTCPCluster, -1);

        will_return(__wrap_strerror, "ERROR");
        expect_string(__wrap__mwarn, formatted_msg, "OS_SendSecureTCPCluster(): ERROR");
    }
    expect_value_count(__wrap_sleep, seconds, 1, 9);

    expect_string(__wrap__merror, formatted_msg, "Could not send message through the cluster after '10' attempts.");

    assert_int_equal(w_send_clustered_message(command, payload, response), -2);
}

void test_w_send_clustered_message_recv_cluster_error_detected(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    for (int i=0; i < CLUSTER_SEND_MESSAGE_ATTEMPTS; ++i) {
        will_return(__wrap_external_socket_connect, sock_num);

        expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
        expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
        expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
        expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
        will_return(__wrap_OS_SendSecureTCPCluster, 1);

        expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
        expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
        will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
        will_return(__wrap_OS_RecvSecureClusterTCP, -2);

        expect_string(__wrap__mwarn, formatted_msg, "Cluster error detected");
    }
    expect_value_count(__wrap_sleep, seconds, 1, 9);

    expect_string(__wrap__merror, formatted_msg, "Could not send message through the cluster after '10' attempts.");

    assert_int_equal(w_send_clustered_message(command, payload, response), -1);
}

void test_w_send_clustered_message_recv_error(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    for (int i=0; i < CLUSTER_SEND_MESSAGE_ATTEMPTS; ++i) {
        will_return(__wrap_external_socket_connect, sock_num);

        expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
        expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
        expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
        expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
        will_return(__wrap_OS_SendSecureTCPCluster, 1);

        expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
        expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
        will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
        will_return(__wrap_OS_RecvSecureClusterTCP, -1);

        will_return(__wrap_strerror, "ERROR");
        expect_string(__wrap__mwarn, formatted_msg, "OS_RecvSecureClusterTCP(): ERROR");
    }
    expect_value_count(__wrap_sleep, seconds, 1, 9);

    expect_string(__wrap__merror, formatted_msg, "Could not send message through the cluster after '10' attempts.");

    assert_int_equal(w_send_clustered_message(command, payload, response), -1);
}

void test_w_send_clustered_message_recv_empty_message(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Empty message from local client.");

    assert_int_equal(w_send_clustered_message(command, payload, response), -1);
}

void test_w_send_clustered_message_recv_max_len(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, OS_MAXLEN);

    expect_string(__wrap__merror, formatted_msg, "Received message > 65536");

    assert_int_equal(w_send_clustered_message(command, payload, response), -1);
}

void test_w_send_clustered_message_success(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, strlen(recv_response));

    assert_int_equal(w_send_clustered_message(command, payload, response), 0);
    assert_string_equal(recv_response, response);
}

void test_w_send_clustered_message_success_after_connection_error(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    will_return(__wrap_external_socket_connect, -1);

    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mwarn, formatted_msg, "Could not connect to socket 'queue/cluster/c-internal.sock': ERROR (0).");
    expect_value(__wrap_sleep, seconds, 1);

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, strlen(recv_response));

    assert_int_equal(w_send_clustered_message(command, payload, response), 0);
    assert_string_equal(recv_response, response);
}

void test_w_send_clustered_message_success_after_send_error(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, -1);

    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mwarn, formatted_msg, "OS_SendSecureTCPCluster(): ERROR");

    expect_value(__wrap_sleep, seconds, 1);

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, strlen(recv_response));

    assert_int_equal(w_send_clustered_message(command, payload, response), 0);
    assert_string_equal(recv_response, response);
}

void test_w_send_clustered_message_success_after_cluster_error(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, -2);

    expect_string(__wrap__mwarn, formatted_msg, "Cluster error detected");
    expect_value(__wrap_sleep, seconds, 1);

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, strlen(recv_response));

    assert_int_equal(w_send_clustered_message(command, payload, response), 0);
    assert_string_equal(recv_response, response);
}

void test_w_send_clustered_message_success_after_recv_error(void **state) {
    char response[OS_MAXSTR + 1];
    char *command = "command";
    char *payload = "payload";
    char *recv_response = "response";
    size_t payload_size = strlen(payload);
    int sock_num = 3;

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, -1);

    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mwarn, formatted_msg, "OS_RecvSecureClusterTCP(): ERROR");
    expect_value(__wrap_sleep, seconds, 1);

    will_return(__wrap_external_socket_connect, sock_num);

    expect_value(__wrap_OS_SendSecureTCPCluster, sock, sock_num);
    expect_value(__wrap_OS_SendSecureTCPCluster, command, command);
    expect_string(__wrap_OS_SendSecureTCPCluster, payload, payload);
    expect_value(__wrap_OS_SendSecureTCPCluster, length, payload_size);
    will_return(__wrap_OS_SendSecureTCPCluster, 1);

    expect_value(__wrap_OS_RecvSecureClusterTCP, sock, sock_num);
    expect_value(__wrap_OS_RecvSecureClusterTCP, length, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureClusterTCP, recv_response);
    will_return(__wrap_OS_RecvSecureClusterTCP, strlen(recv_response));

    assert_int_equal(w_send_clustered_message(command, payload, response), 0);
    assert_string_equal(recv_response, response);
}
#endif

static void test_parse_agent_add_response(void **state) {
    char* success_response = "{\"error\":0,\"data\":{\"id\":\"001\",\"name\":\"agent1\",\"ip\":\"any\",\"key\":\"347e2dc688148aec8544c9777ff291b8868b885\"}}";
    char* missingdata_response = "{\"error\":0}";
    char* missingkey_response = "{\"error\":0,\"data\":{\"id\":\"001\",\"name\":\"agent1\",\"ip\":\"any\"}}";
    char* missingid_response = "{\"error\":0,\"data\":{\"name\":\"agent1\",\"ip\":\"any\",\"key\":\"347e2dc688148aec8544c9777ff291b8868b885\"}}";
    char* error_response = "{\"error\":9009,\"message\":\"ERROR_MESSAGE\"}";
    char* unknown_response = "{\"message \":\"any_message\"}";
    char new_id[FILE_SIZE+1] = { '\0' };
    char new_key[KEYSIZE+1] = { '\0' };
    int err = 0;
    char err_response[OS_MAXSTR + 1];

    // Remove _mwarn checks
    expect_any_always(__wrap__mwarn, formatted_msg);

    /* Success parse */
    err = w_parse_agent_add_response(success_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, 0);
    assert_string_equal(new_id, "001");
    assert_string_equal(new_key, "347e2dc688148aec8544c9777ff291b8868b885");

    err = w_parse_agent_add_response(success_response, err_response, new_id, NULL, FALSE, FALSE);
    assert_int_equal(err, 0);
    assert_string_equal(new_id, "001");

    err = w_parse_agent_add_response(success_response, err_response, NULL, new_key, FALSE, FALSE);
    assert_int_equal(err, 0);
    assert_string_equal(new_key, "347e2dc688148aec8544c9777ff291b8868b885");

    /* Error parse */
    err = w_parse_agent_add_response(error_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -1);
    assert_string_equal(err_response, "ERROR: ERROR_MESSAGE");

    /* Unknown parse */
    err = w_parse_agent_add_response(unknown_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Missing Data parse */
    err = w_parse_agent_add_response(missingdata_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Missing ID parse */
    err = w_parse_agent_add_response(missingid_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Missing key parse */
    err = w_parse_agent_add_response(missingkey_response, err_response, new_id, new_key, FALSE, FALSE);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_agent_add_payload),
        cmocka_unit_test(test_parse_agent_add_response),
        #ifndef WIN32
        cmocka_unit_test(test_create_agent_remove_payload),
        cmocka_unit_test(test_create_sendsync_payload),
        cmocka_unit_test(test_parse_agent_remove_response),
        // Tests w_send_clustered_message
        cmocka_unit_test(test_w_send_clustered_message_connection_error),
        cmocka_unit_test(test_w_send_clustered_message_send_error),
        cmocka_unit_test(test_w_send_clustered_message_recv_cluster_error_detected),
        cmocka_unit_test(test_w_send_clustered_message_recv_error),
        cmocka_unit_test(test_w_send_clustered_message_recv_empty_message),
        cmocka_unit_test(test_w_send_clustered_message_recv_max_len),
        cmocka_unit_test(test_w_send_clustered_message_success),
        cmocka_unit_test(test_w_send_clustered_message_success_after_connection_error),
        cmocka_unit_test(test_w_send_clustered_message_success_after_send_error),
        cmocka_unit_test(test_w_send_clustered_message_success_after_cluster_error),
        cmocka_unit_test(test_w_send_clustered_message_success_after_recv_error),
        #endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
