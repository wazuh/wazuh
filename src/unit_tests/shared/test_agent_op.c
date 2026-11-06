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
#include "../../addagent/manage_agents.h"

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
extern char *w_get_agent_profile_from_config(OS_XML *xml);

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
        expect_string(__wrap__mdebug1, formatted_msg, "Could not connect to socket 'queue/cluster/c-internal.sock': ERROR (0).");
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
    expect_string(__wrap__mdebug1, formatted_msg, "Could not connect to socket 'queue/cluster/c-internal.sock': ERROR (0).");
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

static void test_os_write_agent_info_no_success(void **state) {
    test_mode = 1;

    expect_string(__wrap_wfopen, path, AGENT_INFO_FILE);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, NULL);

    errno = 1;

    will_return(__wrap_strerror, "Operation not permitted");
    char response[OS_MAXSTR];
    snprintf(response, sizeof(response),
         "(1103): Could not open file '%s' due to [(%d)-(%s)].",
         AGENT_INFO_FILE, errno, "Operation not permitted");

    expect_string(__wrap__merror, formatted_msg, response);    
    int ret = os_write_agent_info("agent", "192.168.56.10", "001", NULL);

    errno = 0;
    test_mode = 0;
    assert_int_equal(ret, 0);
}

/* os_read_agent_profile */

static char *get_profile_from_string(const char *config) {
    OS_XML xml;
    char *profile;

    assert_int_equal(OS_ReadXMLString(config, &xml), 0);
    profile = w_get_agent_profile_from_config(&xml);
    OS_ClearXML(&xml);

    return profile;
}

static void test_w_get_agent_profile_from_config_set(void **state) {
    char *profile = get_profile_from_string(
        "<ossec_config><client><server><address>1.1.1.1</address></server>"
        "<config-profile>profA,profB</config-profile></client></ossec_config>");

    assert_string_equal(profile, "profA,profB");
    free(profile);
}

static void test_w_get_agent_profile_from_config_not_set(void **state) {
    char *profile = get_profile_from_string(
        "<ossec_config><client><server><address>1.1.1.1</address></server></client>"
        "<labels><label key=\"config-profile\">profA</label></labels></ossec_config>");

    assert_string_equal(profile, "-");
    free(profile);
}

static void test_w_get_agent_profile_from_config_empty(void **state) {
    char *profile = get_profile_from_string(
        "<ossec_config><client><config-profile></config-profile></client></ossec_config>");

    assert_string_equal(profile, "");
    free(profile);
}

static void test_w_get_agent_profile_from_config_last_wins(void **state) {
    char *profile = get_profile_from_string(
        "<ossec_config><client><config-profile>profA</config-profile></client></ossec_config>"
        "<ossec_config><client><config-profile>profB</config-profile></client>"
        "<client><notify_time>10</notify_time></client></ossec_config>");

    assert_string_equal(profile, "profB");
    free(profile);
}

static void test_os_read_agent_profile_no_config(void **state) {
    char message[OS_MAXSTR];

    test_mode = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "Calling os_read_agent_profile().");
    expect_string(__wrap_wfopen, path, OSSECCONF);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    snprintf(message, sizeof(message), "(1226): Error reading XML file '%s': XMLERR: File '%s' not found. (line 0).",
             OSSECCONF, OSSECCONF);
    expect_string(__wrap__merror, formatted_msg, message);

    char *profile = os_read_agent_profile();

    test_mode = 0;
    assert_null(profile);
}

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
        cmocka_unit_test(test_parse_agent_add_response),
        cmocka_unit_test(test_os_write_agent_info_success),
        cmocka_unit_test(test_os_write_agent_info_no_success),
        cmocka_unit_test(test_w_get_agent_profile_from_config_set),
        cmocka_unit_test(test_w_get_agent_profile_from_config_not_set),
        cmocka_unit_test(test_w_get_agent_profile_from_config_empty),
        cmocka_unit_test(test_w_get_agent_profile_from_config_last_wins),
        cmocka_unit_test(test_os_read_agent_profile_no_config),
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
