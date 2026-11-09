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

#include "../../remoted/remoted.h"
#include "../../remoted/state.h"

#include "../wrappers/posix/select_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/remoted/state_wrappers.h"
#include "../wrappers/wazuh/remoted/config_wrappers.h"
#include "../wrappers/wazuh/remoted/manager_wrappers.h"

char* remcom_output_builder(int error_code, const char* message, cJSON* data_json);
size_t remcom_dispatch(char * command, char ** output);

/* setup/teardown */

static int test_teardown(void ** state) {
    char* string = *state;
    os_free(string);
    return 0;
}

static int closed_fds[2];
static size_t closed_fds_count;

static int setup_closed_fds(void ** state) {
    closed_fds_count = 0;
    return 0;
}

static void assert_closed_fds(int peer, int socket) {
    assert_int_equal(closed_fds_count, 2);
    assert_int_equal(closed_fds[0], peer);
    assert_int_equal(closed_fds[1], socket);
}

// Wrappers

int __wrap_accept() {
    return mock();
}

// Counts every close, so an extra one fails the assertion; only the first two are kept.
int __wrap_close(int fd) {
    if (closed_fds_count < sizeof(closed_fds) / sizeof(closed_fds[0])) {
        closed_fds[closed_fds_count] = fd;
    }

    closed_fds_count++;
    return 0;
}

void __wrap_req_sender(int peer, char *buffer, ssize_t length) {
    check_expected(peer);
    check_expected(buffer);
    check_expected(length);
}

/* Tests */

void test_remcom_output_builder(void ** state) {
    int error_code = 5;
    const char* message = "test msg";

    cJSON* data_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(data_json, "test1", 18);
    cJSON_AddStringToObject(data_json, "test2", "remoted");

    char* msg = remcom_output_builder(error_code, message, data_json);

    *state = msg;

    assert_non_null(msg);
    assert_string_equal(msg, "{\"error\":5,\"message\":\"test msg\",\"data\":{\"test1\":18,\"test2\":\"remoted\"}}");
}

void test_remcom_dispatch_getstats(void ** state) {
    char* request = "{\"command\":\"getstats\"}";
    char *response = NULL;

    cJSON* data_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(data_json, "test1", 18);
    cJSON_AddStringToObject(data_json, "test2", "remoted");

    will_return(__wrap_rem_create_state_json, data_json);

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":0,\"message\":\"ok\",\"data\":{\"test1\":18,\"test2\":\"remoted\"}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getconfig(void ** state) {
    char* request = "{\"command\":\"getconfig\",\"parameters\":{\"section\":\"remote\"}}";
    char *response = NULL;

    cJSON* data_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(data_json, "test1", 15);
    cJSON_AddStringToObject(data_json, "test2", "remoted");

    will_return(__wrap_getRemoteConfig, data_json);

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":0,\"message\":\"ok\",\"data\":{\"test1\":15,\"test2\":\"remoted\"}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getconfig_unknown_section(void ** state) {
    char* request = "{\"command\":\"getconfig\",\"parameters\":{\"section\":\"testtest\"}}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":7,\"message\":\"Unrecognized or not configured section\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getconfig_empty_section(void ** state) {
    char* request = "{\"command\":\"getconfig\",\"parameters\":{}}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":6,\"message\":\"Empty section\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getconfig_empty_parameters(void ** state) {
    char* request = "{\"command\":\"getconfig\"}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":5,\"message\":\"Empty parameters\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_empty_parameters(void ** state) {
    char* request = "{\"command\":\"getagentsstats\"}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":5,\"message\":\"Empty parameters\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_invalid_agents(void ** state) {
    char* request = "{\"command\":\"getagentsstats\", \"module\":\"api\", \"parameters\": {\"agents\": \"agents\"}}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":8,\"message\":\"Invalid agents parameter\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_empty_last_id(void ** state) {
    char* request = "{\"command\":\"getagentsstats\", \"module\":\"api\", \"parameters\": {\"agents\": \"all\"}}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":10,\"message\":\"Empty last id\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_too_many_agents(void ** state) {
    char* request = "{\"command\":\"getagentsstats\", \"module\":\"api\", \"parameters\": {\"agents\": [1,2,3,4,5,6,7,8,9,10,11, \
                        12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47, \
                        48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83, \
                        84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114, \
                        115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141, \
                        142,143,144,145,146,147,148,149,150,151]}}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":11,\"message\":\"Too many agents\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_all_empty_agents(void ** state) {
    char* request = "{\"command\":\"getagentsstats\", \"module\":\"api\", \"parameters\": {\"agents\": \"all\", \"last_id\": 0}}";
    char *response = NULL;

    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, REM_MAX_NUM_AGENTS_STATS);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, NULL);

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":9,\"message\":\"Error getting agents from DB\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_all_due(void ** state) {
    char* request = "{\"command\":\"getagentsstats\", \"module\":\"api\", \"parameters\": {\"agents\": \"all\", \"last_id\": 0}}";
    char *response = NULL;
    cJSON* data_json = cJSON_CreateObject();

    int *connected_agents;
    os_calloc(151, sizeof(int), connected_agents);
    for (size_t i = 0; i < 150; i++) {
        connected_agents[i] = i+1;
    }
    connected_agents[150] = OS_INVALID;


    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, REM_MAX_NUM_AGENTS_STATS);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, connected_agents);

    expect_value(__wrap_rem_create_agents_state_json, agents_ids, connected_agents);
    will_return(__wrap_rem_create_agents_state_json, data_json);

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":1,\"message\":\"due\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_all_ok(void ** state) {
    char* request = "{\"command\":\"getagentsstats\", \"module\":\"api\", \"parameters\": {\"agents\": \"all\", \"last_id\": 0}}";
    char *response = NULL;
    cJSON* data_json = cJSON_CreateObject();

    int *connected_agents;
    os_calloc(2, sizeof(int), connected_agents);
    connected_agents[0] = 1;
    connected_agents[1] = OS_INVALID;


    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, REM_MAX_NUM_AGENTS_STATS);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, connected_agents);

    expect_value(__wrap_rem_create_agents_state_json, agents_ids, connected_agents);
    will_return(__wrap_rem_create_agents_state_json, data_json);

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":0,\"message\":\"ok\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_array_empty_agents(void ** state) {
    char* request = "{\"command\":\"getagentsstats\", \"module\":\"api\", \"parameters\": {\"agents\": []}}";
    char *response = NULL;

    will_return(__wrap_json_parse_agents, NULL);

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":9,\"message\":\"Error getting agents from DB\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_getagentsstats_array_ok(void ** state) {
    char* request = "{\"command\":\"getagentsstats\", \"module\":\"api\", \"parameters\": {\"agents\": [1]}}";
    char *response = NULL;
    cJSON* data_json = cJSON_CreateObject();

    int *connected_agents;
    os_calloc(2, sizeof(int), connected_agents);
    connected_agents[0] = 1;
    connected_agents[1] = OS_INVALID;

    will_return(__wrap_json_parse_agents, connected_agents);

    expect_value(__wrap_rem_create_agents_state_json, agents_ids, connected_agents);
    will_return(__wrap_rem_create_agents_state_json, data_json);

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":0,\"message\":\"ok\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_assigngroup(void ** state) {
    char* request = "{\"command\":\"assigngroup\", \"parameters\": {\"agent\": \"001\", \"md5\": \"1234567890abcdef\"}}";
    char *response = NULL;

    cJSON* data_json = cJSON_CreateObject();
    cJSON_AddStringToObject(data_json, "group", "test1");

    expect_string(__wrap_assign_group_to_agent, agent_id, "001");
    expect_string(__wrap_assign_group_to_agent, md5, "1234567890abcdef");
    will_return(__wrap_assign_group_to_agent, data_json);

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":0,\"message\":\"ok\",\"data\":{\"group\":\"test1\"}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_assigngroup_invalid_parameters(void ** state) {
    char* request = "{\"command\":\"assigngroup\", \"parameters\": {\"md5\": \"1234567890abcdef\"}}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":12,\"message\":\"Invalid agent or md5 parameter\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_assigngroup_empty_parameters(void ** state) {
    char* request = "{\"command\":\"assigngroup\"}}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":5,\"message\":\"Empty parameters\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_unknown_command(void ** state) {
    char* request = "{\"command\":\"unknown\"}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":4,\"message\":\"Unrecognized command\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_empty_command(void ** state) {
    char* request = "{}";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":3,\"message\":\"Empty command\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_dispatch_invalid_json(void ** state) {
    char* request = "unknown";
    char *response = NULL;

    size_t size = remcom_dispatch(request, &response);

    *state = response;

    assert_non_null(response);
    assert_string_equal(response, "{\"error\":2,\"message\":\"Invalid JSON input\",\"data\":{}}");
    assert_int_equal(size, strlen(response));
}

void test_remcom_main(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{\"command\":\"getstats\"}";
    size_t input_size = strlen(input) + 1;

    cJSON* data_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(data_json, "test1", 18);
    cJSON_AddStringToObject(data_json, "test2", "remoted");

    char *response = "{\"error\":0,\"message\":\"ok\",\"data\":{\"test1\":18,\"test2\":\"remoted\"}}";
    size_t response_size = strlen(response);

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    will_return(__wrap_rem_create_state_json, data_json);

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, response_size);
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);

    assert_closed_fds(peer, socket);
}

void test_remcom_main_full_size_request(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = NULL;

    char *response = "{\"error\":2,\"message\":\"Invalid JSON input\",\"data\":{}}";
    size_t response_size = strlen(response);

    // The receive fills the whole buffer with no terminator, as a request of exactly OS_MAXSTR
    // bytes does. Without the extra byte, parsing it reads past the buffer.
    os_calloc(OS_MAXSTR + 1, sizeof(char), input);
    memset(input, 'x', OS_MAXSTR);
    input[0] = '{';

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_MAXSTR);

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, response_size);
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);

    assert_closed_fds(peer, socket);
    os_free(input);
}

void test_remcom_main_non_json_request_keeps_peer_open(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "001 agent request";
    size_t input_size = strlen(input);

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_value(__wrap_req_sender, peer, peer);
    expect_string(__wrap_req_sender, buffer, input);
    expect_value(__wrap_req_sender, length, input_size);

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);

    // req_sender() owns the peer from here on, so only the listening socket is closed.
    assert_int_equal(closed_fds_count, 1);
    assert_int_equal(closed_fds[0], socket);
}

void test_remcom_main_empty(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{\"command\":\"getstats\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Empty message from local client");

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);

    assert_closed_fds(peer, socket);
}

void test_remcom_main_error(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{\"command\":\"getstats\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__merror, formatted_msg, "At OS_RecvSecureTCP(): 'Success'");

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);

    assert_closed_fds(peer, socket);
}

void test_remcom_main_sockerror(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{\"command\":\"getstats\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "At OS_RecvSecureTCP(): response size is bigger than expected");

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);

    assert_closed_fds(peer, socket);
}

void test_remcom_main_accept_error(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{\"command\":\"getstats\"}";

    errno = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    expect_string(__wrap__merror, formatted_msg, "At accept(): 'Success'");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "At OS_RecvSecureTCP(): response size is bigger than expected");

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);
}

void test_remcom_main_select_zero(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{\"command\":\"getstats\"}";

    errno = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "At OS_RecvSecureTCP(): response size is bigger than expected");

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);
}

void test_remcom_main_select_error_eintr(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{\"command\":\"getstats\"}";

    errno = EINTR;

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "At OS_RecvSecureTCP(): response size is bigger than expected");

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread finished");

    remcom_main(NULL);
}

void test_remcom_main_select_error(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{\"command\":\"getstats\"}";

    errno = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, -1);

    expect_string(__wrap__merror_exit, formatted_msg, "At select(): 'Success'");

    expect_assert_failure(remcom_main(NULL));
}

void test_remcom_main_bind_error(void **state)
{
    int socket = 0;
    int peer = 1111;

    expect_string(__wrap__mdebug1, formatted_msg, "Local requests thread ready");

    expect_string(__wrap_OS_BindUnixDomain, path, REMOTE_LOCAL_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, -1);

    expect_string(__wrap__merror, formatted_msg, "Unable to bind to socket 'queue/sockets/remote': (0) 'Success'");

    remcom_main(NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test remcom_output_builder
        cmocka_unit_test_teardown(test_remcom_output_builder, test_teardown),
        // Test remcom_dispatch
        cmocka_unit_test_teardown(test_remcom_dispatch_getstats, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getconfig, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getconfig_unknown_section, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getconfig_empty_section, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getconfig_empty_parameters, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_empty_parameters, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_invalid_agents, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_empty_last_id, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_too_many_agents, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_all_empty_agents, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_all_due, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_all_ok, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_array_empty_agents, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_getagentsstats_array_ok, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_assigngroup, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_assigngroup_invalid_parameters, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_assigngroup_empty_parameters, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_unknown_command, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_empty_command, test_teardown),
        cmocka_unit_test_teardown(test_remcom_dispatch_invalid_json, test_teardown),
        // Test remcom_main
        cmocka_unit_test_setup(test_remcom_main, setup_closed_fds),
        cmocka_unit_test_setup(test_remcom_main_non_json_request_keeps_peer_open, setup_closed_fds),
        cmocka_unit_test_setup(test_remcom_main_empty, setup_closed_fds),
        cmocka_unit_test_setup(test_remcom_main_error, setup_closed_fds),
        cmocka_unit_test_setup(test_remcom_main_sockerror, setup_closed_fds),
        cmocka_unit_test(test_remcom_main_accept_error),
        cmocka_unit_test(test_remcom_main_select_zero),
        cmocka_unit_test(test_remcom_main_select_error_eintr),
        cmocka_unit_test(test_remcom_main_select_error),
        cmocka_unit_test(test_remcom_main_bind_error),
        // Last, as AddressSanitizer aborts the run if the request is read unterminated.
        cmocka_unit_test_setup(test_remcom_main_full_size_request, setup_closed_fds),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
