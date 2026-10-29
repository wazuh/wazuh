/*
 * Copyright (C) Wazuh Inc.
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

#include "shared.h"
#include "sec.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/wazuhdb_queries_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/libc/string_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

#include "cJSON.h"

#ifndef WIN32
#include "../wrappers/wazuh/data_provider/sysInfo_wrappers.h"
#include "../../data_provider/include/sysInfo.h"
#endif

/* redefinitons/wrapping */

extern cJSON* w_create_agent_add_payload(const char *name, const char *ip, const char *groups, const char *key_hash, const char *key, const char *id, authd_force_options_t *force_options, const char *token_id, const char *reenroll_kid, const char *reenroll_bearer, const char *source);
extern cJSON* w_create_agent_remove_payload(const char *id, const int purge);
extern cJSON* w_create_sendsync_payload(const char *daemon_name, cJSON *message);
extern int w_parse_agent_add_response(const char* buffer, char *err_response, char* id, char* key, char* reenroll_secret, const int json_format, const int exit_on_error, int *error_code);
extern int w_parse_agent_remove_response(const char* buffer, char *err_response, const int json_format, const int exit_on_error);

#ifndef WIN32
extern sysinfo_networks_func sysinfo_network_ptr;
extern sysinfo_free_result_func sysinfo_free_result_ptr;
#endif

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

    payload = w_create_agent_add_payload(agent, ip, groups, key_hash, key, id, &force_options, NULL, NULL, NULL, NULL);

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

    // No enrollment token was presented: the member must be absent, not null. Nor a re-enrollment,
    // nor a network source.
    assert_null(cJSON_GetObjectItem(arguments, "token_id"));
    assert_null(cJSON_GetObjectItem(arguments, "reenroll"));
    assert_null(cJSON_GetObjectItem(arguments, "source"));

    cJSON_Delete(payload);
    os_free(str_force);
}

// An enrollment presented with a token (#38993): the worker forwards the token id so the master can
// count the use; the master's local_dispatch reads it back as `arguments.token_id`. Built on every
// target, like test_create_agent_add_payload: the payload builder is plain cJSON.
static void test_create_agent_add_payload_carries_token_id(void **state) {
    (void)state;
    cJSON* payload = w_create_agent_add_payload("agent1", "any", NULL, NULL, NULL, NULL, NULL, "AAECAwQFBgcICQoLDA0ODw", NULL, NULL, NULL);
    assert_non_null(payload);
    cJSON* arguments = cJSON_GetObjectItem(payload, "arguments");
    assert_non_null(arguments);
    cJSON* token_id = cJSON_GetObjectItem(arguments, "token_id");
    assert_non_null(token_id);
    assert_string_equal(token_id->valuestring, "AAECAwQFBgcICQoLDA0ODw");
    assert_null(cJSON_GetObjectItem(arguments, "groups"));
    assert_null(cJSON_GetObjectItem(arguments, "id"));
    cJSON_Delete(payload);
}

// A re-enrollment (#38993): the worker forwards the agent id the bearer names and the bearer itself,
// verbatim and unverified -- the master, which holds the agent's secret, reads them back as
// `arguments.reenroll.{kid,bearer}`. A kid without a bearer (or the reverse) travels as nothing.
static void test_create_agent_add_payload_carries_reenroll_credential(void **state) {
    (void)state;
    cJSON* payload = w_create_agent_add_payload("agent1", "any", NULL, NULL, NULL, NULL, NULL, NULL, "001", "eyJ.claims.sig", NULL);
    assert_non_null(payload);
    cJSON* arguments = cJSON_GetObjectItem(payload, "arguments");
    assert_non_null(arguments);
    cJSON* reenroll = cJSON_GetObjectItem(arguments, "reenroll");
    assert_true(cJSON_IsObject(reenroll));
    assert_string_equal(cJSON_GetObjectItem(reenroll, "kid")->valuestring, "001");
    assert_string_equal(cJSON_GetObjectItem(reenroll, "bearer")->valuestring, "eyJ.claims.sig");
    assert_null(cJSON_GetObjectItem(arguments, "token_id"));
    assert_null(cJSON_GetObjectItem(arguments, "id"));
    cJSON_Delete(payload);

    payload = w_create_agent_add_payload("agent1", "any", NULL, NULL, NULL, NULL, NULL, NULL, "001", NULL, NULL);
    assert_null(cJSON_GetObjectItem(cJSON_GetObjectItem(payload, "arguments"), "reenroll"));
    cJSON_Delete(payload);
}

// An enrollment that arrived over the network: the worker forwards the agent's peer address so the
// master's log names it, and the master reads it back as `arguments.source`. It never replaces `ip`.
static void test_create_agent_add_payload_carries_source(void **state) {
    (void)state;
    cJSON* payload = w_create_agent_add_payload("agent1", "any", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "192.168.60.71");
    assert_non_null(payload);
    cJSON* arguments = cJSON_GetObjectItem(payload, "arguments");
    assert_non_null(arguments);
    assert_string_equal(cJSON_GetObjectItem(arguments, "source")->valuestring, "192.168.60.71");
    assert_string_equal(cJSON_GetObjectItem(arguments, "ip")->valuestring, "any");
    cJSON_Delete(payload);
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
        expect_string(__wrap__mdebug1, formatted_msg, "Could not connect to socket 'queue/sockets/cluster-internal.sock': ERROR (0).");
    }
    expect_value_count(__wrap_sleep, seconds, 1, 9);

    expect_string(__wrap__mwarn, formatted_msg, "Could not send message through the cluster after '10' attempts.");

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
        expect_string(__wrap__mdebug1, formatted_msg, "OS_SendSecureTCPCluster(): ERROR");
    }
    expect_value_count(__wrap_sleep, seconds, 1, 9);

    expect_string(__wrap__mwarn, formatted_msg, "Could not send message through the cluster after '10' attempts.");

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

        expect_string(__wrap__mdebug1, formatted_msg, "Cluster error detected");
    }
    expect_value_count(__wrap_sleep, seconds, 1, 9);

    expect_string(__wrap__mwarn, formatted_msg, "Could not send message through the cluster after '10' attempts.");

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
        expect_string(__wrap__mdebug1, formatted_msg, "OS_RecvSecureClusterTCP(): ERROR");
    }
    expect_value_count(__wrap_sleep, seconds, 1, 9);

    expect_string(__wrap__mwarn, formatted_msg, "Could not send message through the cluster after '10' attempts.");

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
    expect_string(__wrap__mdebug1, formatted_msg, "Could not connect to socket 'queue/sockets/cluster-internal.sock': ERROR (0).");
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
    expect_string(__wrap__mdebug1, formatted_msg, "OS_SendSecureTCPCluster(): ERROR");

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

    expect_string(__wrap__mdebug1, formatted_msg, "Cluster error detected");
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
    expect_string(__wrap__mdebug1, formatted_msg, "OS_RecvSecureClusterTCP(): ERROR");
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
    int error_code = 0;

    // Remove _mwarn checks
    expect_any_always(__wrap__mwarn, formatted_msg);

    /* Success parse */
    err = w_parse_agent_add_response(success_response, err_response, new_id, new_key, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, 0);
    assert_string_equal(new_id, "001");
    assert_string_equal(new_key, "347e2dc688148aec8544c9777ff291b8868b885");

    err = w_parse_agent_add_response(success_response, err_response, new_id, NULL, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, 0);
    assert_string_equal(new_id, "001");

    err = w_parse_agent_add_response(success_response, err_response, NULL, new_key, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, 0);
    assert_string_equal(new_key, "347e2dc688148aec8544c9777ff291b8868b885");

    /* Error parse */
    err = w_parse_agent_add_response(error_response, err_response, new_id, new_key, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, -1);
    assert_string_equal(err_response, "ERROR: ERROR_MESSAGE");

    /* Error parse: the master's own numeric code is captured when the caller asks for it */
    error_code = 0;
    err = w_parse_agent_add_response(error_response, err_response, new_id, new_key, NULL, FALSE, FALSE, &error_code);
    assert_int_equal(err, -1);
    assert_int_equal(error_code, 9009);
    assert_string_equal(err_response, "ERROR: ERROR_MESSAGE");

    /* Unknown parse */
    err = w_parse_agent_add_response(unknown_response, err_response, new_id, new_key, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Unknown parse: error_code must stay untouched on a non-business failure */
    error_code = 0;
    err = w_parse_agent_add_response(unknown_response, err_response, new_id, new_key, NULL, FALSE, FALSE, &error_code);
    assert_int_equal(err, -2);
    assert_int_equal(error_code, 0);

    /* Missing Data parse */
    err = w_parse_agent_add_response(missingdata_response, err_response, new_id, new_key, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Missing ID parse */
    err = w_parse_agent_add_response(missingid_response, err_response, new_id, new_key, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Missing key parse */
    err = w_parse_agent_add_response(missingkey_response, err_response, new_id, new_key, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, -2);
    assert_string_equal(err_response, "ERROR: Invalid message format");

    /* Re-enrollment secret (#38993): copied when the master sends it, empty (not an error) when it does not */
    char* secret_response = "{\"error\":0,\"data\":{\"id\":\"001\",\"name\":\"agent1\",\"ip\":\"any\",\"key\":\"347e2dc688148aec8544c9777ff291b8868b885\",\
\"reenroll_secret\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}}";
    char new_secret[AGENT_REENROLL_SECRET_HEX_CHARS + 1] = "stale";
    err = w_parse_agent_add_response(secret_response, err_response, new_id, new_key, new_secret, FALSE, FALSE, NULL);
    assert_int_equal(err, 0);
    assert_string_equal(new_secret, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    assert_string_equal(new_key, "347e2dc688148aec8544c9777ff291b8868b885");

    strcpy(new_secret, "stale");
    err = w_parse_agent_add_response(success_response, err_response, new_id, new_key, new_secret, FALSE, FALSE, NULL);
    assert_int_equal(err, 0);
    assert_string_equal(new_secret, "");

    /* A caller that does not ask for it (NULL) is unaffected either way */
    err = w_parse_agent_add_response(secret_response, err_response, new_id, new_key, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, 0);
}

static void test_parse_agent_add_response_logs_only_without_error_code(void **state) {
    (void) state;
    char* error_response = "{\"error\":9026,\"message\":\"Unknown agent or no re-enrollment credential\"}";
    char err_response[OS_MAXSTR + 1];
    int error_code = 0;

    /* A caller that asks for the master's code reports the rejection itself: no warning here, or the
     * rejection is logged twice on a worker (issue #40482) */
    int err = w_parse_agent_add_response(error_response, err_response, NULL, NULL, NULL, FALSE, FALSE, &error_code);
    assert_int_equal(err, -1);
    assert_int_equal(error_code, 9026);
    assert_string_equal(err_response, "ERROR: Unknown agent or no re-enrollment credential");

    /* A caller that does not ask for it keeps the warning as its only log line (the 1515 path) */
    expect_string(__wrap__mwarn, formatted_msg, "9026: Unknown agent or no re-enrollment credential");
    err = w_parse_agent_add_response(error_response, err_response, NULL, NULL, NULL, FALSE, FALSE, NULL);
    assert_int_equal(err, -1);
    assert_string_equal(err_response, "ERROR: Unknown agent or no re-enrollment credential");
}

static void test_os_write_agent_info_success(void **state) {
    FILE *fp = (FILE*)0x1234;

    test_mode = 1;

    expect_string(__wrap_wfopen, path, AGENT_INFO_FILE);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, fp);

    expect_fprintf(fp, "agent\n-\n001\n-\n", 0);

    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, 0);

    int ret = os_write_agent_info("agent", "192.168.56.10", "001", NULL);

    test_mode = 0;
    assert_int_equal(ret, 1);
}

#ifndef WIN32
static void test_getPrimaryIP_no_sysinfo_network(void ** state) {
    sysinfo_network_ptr = NULL;

    char * ip = getPrimaryIP();

    assert_null(ip);
}

static void test_getPrimaryIP_no_sysinfo_free(void ** state) {
    sysinfo_network_ptr = (int (*)(cJSON **)) 1;
    sysinfo_free_result_ptr = NULL;

    char * ip = getPrimaryIP();

    assert_null(ip);
}

static void test_getPrimaryIP_sysinfo_network_return_error(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = NULL;

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 1234);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to get system network information. Error code: 1234.");

    char * ip = getPrimaryIP();

    assert_null(ip);
}

static void test_getPrimaryIP_sysinfo_network_no_object(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = NULL;

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);

    char * ip = getPrimaryIP();

    assert_null(ip);
}

static void test_getPrimaryIP_sysinfo_network_no_iface(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_no_iface_array(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":{}}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_empty_array(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_no_gateway(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\"}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_invalid_gateway_type(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":1234}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_empty_gateway(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\" \"}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_ipv6_gateway_ipv6_address(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"fe80::\",\"IPv6\":[{\"address\":"
                                   "\"fe80::a00:27ff:fee0:d046\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "FE80:0000:0000:0000:0A00:27FF:FEE0:D046");

    os_free(ip);
    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_ipv6_gateway_ipv4_address(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse(
        "{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"fe80::\",\"IPv4\":[{\"address\":\"192.168.1.10\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "192.168.1.10");

    os_free(ip);
    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_ipv4_gateway_ipv6_address(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\",\"IPv6\":[{\"address\":"
                                   "\"fe80::a00:27ff:fee0:d046\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "FE80:0000:0000:0000:0A00:27FF:FEE0:D046");

    os_free(ip);
    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_ipv4_gateway_ipv4_address(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse(
        "{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\",\"IPv4\":[{\"address\":\"192.168.1.10\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "192.168.1.10");

    os_free(ip);
    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_valid_gateway_no_address_array(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\"}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_valid_gateway_address_invalid_type(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks =
        cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\",\"IPv4\":[{\"address\":1234}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_getPrimaryIP_sysinfo_network_iface_valid_gateway_multiple_address_array(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\",\"IPv4\":[{\"address\":"
                                   "\"192.168.1.10\"},{\"address\":\"192.168.1.11\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "192.168.1.10");

    os_free(ip);
    cJSON_Delete(networks);
}
#endif /* !WIN32 */

/* w_validate_group_name */

#define GROUP_RESPONSE_SIZE OS_SIZE_2048
#define GROUP_SENTINEL      'X'
#define GROUP_ERR_PREFIX    "ERROR: Invalid group name: "
#define GROUP_PROHIBITED    "... characters '\\/:*?\"<>|,' are prohibited"
#define GROUP_TOO_LARGE     "... group is too large"
#define GROUP_DBG_EMPTY     "At w_validate_group_name(): Group length is 0"
#define GROUP_DBG_TOO_LARGE "At w_validate_group_name(): Group length is over 255 characters"
#define GROUP_DBG_MULTI     "At w_validate_group_name(): Multigroup length is over 65536 characters"

/* Returns prefix + n chars cycling over pattern + suffix. */
static char *build_group(const char *prefix, const char *pattern, size_t n, const char *suffix) {
    size_t plen = strlen(prefix);
    size_t pat_len = strlen(pattern);
    char *group = calloc(plen + n + strlen(suffix) + 1, 1);

    strcpy(group, prefix);
    for (size_t i = 0; i < n; i++) {
        group[plen + i] = pattern[i % pat_len];
    }
    strcpy(group + plen + n, suffix);
    return group;
}

static void fill_group_sentinel(char *response) {
    memset(response, GROUP_SENTINEL, GROUP_RESPONSE_SIZE - 1);
    response[GROUP_RESPONSE_SIZE - 1] = '\0';
}

static void assert_group_sentinel_from(const char *response, size_t from) {
    for (size_t i = from; i < GROUP_RESPONSE_SIZE - 1; i++) {
        assert_int_equal(response[i], GROUP_SENTINEL);
    }
}

/* Checks return and full response for quoted (first 255 chars of quoted, as the source formats it), then the
 * same call with a NULL response. dbg is the mdebug1 message the branch logs, or NULL. */
static void check_group_error(const char *group, int expected_ret, const char *quoted, const char *suffix,
                              const char *dbg) {
    char response[GROUP_RESPONSE_SIZE];
    char expected[GROUP_RESPONSE_SIZE];

    snprintf(expected, sizeof(expected), "%s%.255s%s", GROUP_ERR_PREFIX, quoted, suffix);

    if (dbg) {
        expect_string(__wrap__mdebug1, formatted_msg, dbg);
    }
    fill_group_sentinel(response);
    assert_int_equal(w_validate_group_name(group, response), expected_ret);
    assert_string_equal(response, expected);
    assert_group_sentinel_from(response, strlen(expected) + 1);

    if (dbg) {
        expect_string(__wrap__mdebug1, formatted_msg, dbg);
    }
    assert_int_equal(w_validate_group_name(group, NULL), expected_ret);
}

static void check_group_valid(const char *group) {
    char response[GROUP_RESPONSE_SIZE];

    fill_group_sentinel(response);
    assert_int_equal(w_validate_group_name(group, response), 0);
    assert_group_sentinel_from(response, 0);

    assert_int_equal(w_validate_group_name(group, NULL), 0);
}

static void test_w_validate_group_name_valid_single(void **state) {
    check_group_valid("group1");
}

static void test_w_validate_group_name_valid_multi(void **state) {
    check_group_valid("g1,g2");
    check_group_valid("g1,g2,g3");
}

static void test_w_validate_group_name_allowed_punctuation(void **state) {
    check_group_valid("a.:;_-=+!@()b");
}

static void test_w_validate_group_name_single_max_length(void **state) {
    char *group = build_group("", "a", MAX_GROUP_NAME, "");
    check_group_valid(group);
    free(group);
}

static void test_w_validate_group_name_multi_three_max_length(void **state) {
    char group[3 * (MAX_GROUP_NAME + 1)];

    memset(group, 'a', sizeof(group) - 1);
    group[MAX_GROUP_NAME] = ',';
    group[2 * MAX_GROUP_NAME + 1] = ',';
    group[sizeof(group) - 1] = '\0';

    check_group_valid(group);
}

static void test_w_validate_group_name_empty(void **state) {
    char response[GROUP_RESPONSE_SIZE];
    const char *expected = GROUP_ERR_PREFIX "Empty Group";

    expect_string(__wrap__mdebug1, formatted_msg, GROUP_DBG_EMPTY);
    fill_group_sentinel(response);
    assert_int_equal(w_validate_group_name("", response), -8);
    assert_string_equal(response, expected);
    assert_group_sentinel_from(response, strlen(expected) + 1);

    expect_string(__wrap__mdebug1, formatted_msg, GROUP_DBG_EMPTY);
    assert_int_equal(w_validate_group_name("", NULL), -8);
}

static void test_w_validate_group_name_single_too_large(void **state) {
    char *group = build_group("", "a", MAX_GROUP_NAME + 1, "");
    check_group_error(group, -2, group, GROUP_TOO_LARGE, GROUP_DBG_TOO_LARGE);
    free(group);
}

static void test_w_validate_group_name_multigroup_too_large(void **state) {
    char *group = build_group("", "a,", OS_SIZE_65536, "");
    check_group_error(group, -3, group, "... multigroup is too large", GROUP_DBG_MULTI);
    free(group);
}

static void test_w_validate_group_name_white_space(void **state) {
    check_group_error("a b,c", -4, "a b,c", "... white spaces are not allowed", NULL);
    check_group_error("a,b c,d", -4, "a,b c,d", "... white spaces are not allowed", NULL);
    check_group_error("a,b c", -4, "a,b c", "... white spaces are not allowed", NULL);
}

static void test_w_validate_group_name_white_space_before_oversized(void **state) {
    char *group = build_group("a b,", "a", MAX_GROUP_NAME + 1, "");
    check_group_error(group, -4, group, "... white spaces are not allowed", NULL);
    free(group);
}

static void test_w_validate_group_name_consecutive_commas(void **state) {
    check_group_error("a,,b", -5, "a,,b", "... consecutive ',' are not allowed", NULL);
}

static void test_w_validate_group_name_only_commas_multi(void **state) {
    check_group_error(",,,", -5, ",,,", "... consecutive ',' are not allowed", NULL);
}

static void test_w_validate_group_name_only_one_comma(void **state) {
    check_group_error(",", -1, ",", GROUP_PROHIBITED, NULL);
}

static void test_w_validate_group_name_leading_trailing_comma(void **state) {
    check_group_error(",a", -6, ",a", "... cannot start or end with ','", NULL);
    check_group_error("a,b,", -6, "a,b,", "... cannot start or end with ','", NULL);
}

static void test_w_validate_group_name_invalid_char_single(void **state) {
    check_group_error("a/b", -1, "a/b", GROUP_PROHIBITED, NULL);
    check_group_error("a*b", -1, "a*b", GROUP_PROHIBITED, NULL);
    check_group_error("a\"b", -1, "a\"b", GROUP_PROHIBITED, NULL);
    check_group_error("a\\b", -1, "a\\b", GROUP_PROHIBITED, NULL);
}

static void test_w_validate_group_name_invalid_char_multi(void **state) {
    check_group_error("a,b/c", -1, "a,b/c", GROUP_PROHIBITED, NULL);
}

static void test_w_validate_group_name_max_length_in_multigroup(void **state) {
    char *group = build_group("", "a", MAX_GROUP_NAME, ",b");
    check_group_valid(group);
    free(group);
}

/* Oversized group inside a multigroup: the response quotes that group's own token. */

static void test_w_validate_group_name_oversized_null_response(void **state) {
    char *group = build_group("", "a", MAX_GROUP_NAME + 1, ",b");
    assert_int_equal(w_validate_group_name(group, NULL), -7);
    free(group);
}

static void test_w_validate_group_name_oversized_first(void **state) {
    char *token = build_group("", "a", MAX_GROUP_NAME + 1, "");
    char *group = build_group("", "a", MAX_GROUP_NAME + 1, ",b");

    check_group_error(group, -7, token, GROUP_TOO_LARGE, NULL);
    free(group);
    free(token);
}

static void test_w_validate_group_name_oversized_middle(void **state) {
    char *token = build_group("", "a", MAX_GROUP_NAME + 1, "");
    char *group = build_group("a,", "a", MAX_GROUP_NAME + 1, ",c");

    check_group_error(group, -7, token, GROUP_TOO_LARGE, NULL);
    free(group);
    free(token);
}

static void test_w_validate_group_name_oversized_last(void **state) {
    char *token = build_group("", "a", MAX_GROUP_NAME + 1, "");
    char *group = build_group("a,b,", "a", MAX_GROUP_NAME + 1, "");

    check_group_error(group, -7, token, GROUP_TOO_LARGE, NULL);
    free(group);
    free(token);
}

/* The 256th char differs, so it must not appear in the response. */
static void test_w_validate_group_name_oversized_one_past_limit(void **state) {
    char *token = build_group("", "a", MAX_GROUP_NAME, "b");
    char *group = build_group("", "a", MAX_GROUP_NAME, "b,c");

    check_group_error(group, -7, token, GROUP_TOO_LARGE, NULL);
    free(group);
    free(token);
}

static void test_w_validate_group_name_oversized_far_over_limit(void **state) {
    char *token = build_group("", "a", 4000, "");
    char *group = build_group("", "a", 4000, ",b");

    check_group_error(group, -7, token, GROUP_TOO_LARGE, NULL);
    free(group);
    free(token);
}

/* Non-uniform bytes, so a corrupted read shows as a wrong character. */
static void test_w_validate_group_name_oversized_distinct_bytes(void **state) {
    char *token = build_group("", "0123456789", 300, "");
    char *group = build_group("", "0123456789", 300, ",b");

    check_group_error(group, -7, token, GROUP_TOO_LARGE, NULL);
    free(group);
    free(token);
}

/* Total length OS_SIZE_65536 - 1: the multigroup size check passes and the group check fires. */
static void test_w_validate_group_name_oversized_near_multigroup_cap(void **state) {
    const size_t token_len = MAX_GROUP_NAME + 2;
    const size_t filler = (OS_SIZE_65536 - 1 - token_len) / 2;
    char *token = build_group("", "a", token_len, "");
    char *fill = build_group("", ",b", 2 * filler, "");
    char *group = build_group(token, "", 0, fill);

    assert_int_equal(strlen(group), OS_SIZE_65536 - 1);
    check_group_error(group, -7, token, GROUP_TOO_LARGE, NULL);
    free(group);
    free(fill);
    free(token);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_agent_add_payload),
        cmocka_unit_test(test_create_agent_add_payload_carries_token_id),
        cmocka_unit_test(test_create_agent_add_payload_carries_reenroll_credential),
        cmocka_unit_test(test_create_agent_add_payload_carries_source),
        cmocka_unit_test(test_parse_agent_add_response),
        cmocka_unit_test(test_parse_agent_add_response_logs_only_without_error_code),
        cmocka_unit_test(test_os_write_agent_info_success),
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
        // Tests getPrimaryIP
        cmocka_unit_test(test_getPrimaryIP_no_sysinfo_network),
        cmocka_unit_test(test_getPrimaryIP_no_sysinfo_free),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_return_error),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_no_object),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_no_iface),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_no_iface_array),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_empty_array),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_no_gateway),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_invalid_gateway_type),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_empty_gateway),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_ipv6_gateway_ipv6_address),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_ipv6_gateway_ipv4_address),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_ipv4_gateway_ipv6_address),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_ipv4_gateway_ipv4_address),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_valid_gateway_no_address_array),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_valid_gateway_address_invalid_type),
        cmocka_unit_test(test_getPrimaryIP_sysinfo_network_iface_valid_gateway_multiple_address_array),
        #endif
        // Tests w_validate_group_name
        cmocka_unit_test(test_w_validate_group_name_valid_single),
        cmocka_unit_test(test_w_validate_group_name_valid_multi),
        cmocka_unit_test(test_w_validate_group_name_allowed_punctuation),
        cmocka_unit_test(test_w_validate_group_name_single_max_length),
        cmocka_unit_test(test_w_validate_group_name_multi_three_max_length),
        cmocka_unit_test(test_w_validate_group_name_empty),
        cmocka_unit_test(test_w_validate_group_name_single_too_large),
        cmocka_unit_test(test_w_validate_group_name_multigroup_too_large),
        cmocka_unit_test(test_w_validate_group_name_white_space),
        cmocka_unit_test(test_w_validate_group_name_white_space_before_oversized),
        cmocka_unit_test(test_w_validate_group_name_consecutive_commas),
        cmocka_unit_test(test_w_validate_group_name_only_commas_multi),
        cmocka_unit_test(test_w_validate_group_name_only_one_comma),
        cmocka_unit_test(test_w_validate_group_name_leading_trailing_comma),
        cmocka_unit_test(test_w_validate_group_name_invalid_char_single),
        cmocka_unit_test(test_w_validate_group_name_invalid_char_multi),
        cmocka_unit_test(test_w_validate_group_name_max_length_in_multigroup),
        // Oversized group in a multigroup: kept last so a sanitizer abort does not hide the cases above
        cmocka_unit_test(test_w_validate_group_name_oversized_null_response),
        cmocka_unit_test(test_w_validate_group_name_oversized_first),
        cmocka_unit_test(test_w_validate_group_name_oversized_middle),
        cmocka_unit_test(test_w_validate_group_name_oversized_last),
        cmocka_unit_test(test_w_validate_group_name_oversized_one_past_limit),
        cmocka_unit_test(test_w_validate_group_name_oversized_far_over_limit),
        cmocka_unit_test(test_w_validate_group_name_oversized_distinct_bytes),
        cmocka_unit_test(test_w_validate_group_name_oversized_near_multigroup_cap),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
