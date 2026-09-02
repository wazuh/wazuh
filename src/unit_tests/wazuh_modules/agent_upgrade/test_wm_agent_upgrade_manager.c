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

#include "../../wrappers/common.h"
#include "../../wrappers/posix/pthread_wrappers.h"
#include "../../wrappers/posix/select_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/http_op_wrappers.h"
#include "../../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"
#include "../../wrappers/wazuh/shared/sym_load_wrappers.h"

#include "wmodules.h"
#include "wm_agent_upgrade_manager.h"
#include "shared.h"

void wm_agent_upgrade_listen_messages(const wm_manager_configs* manager_configs);

// Setup / teardown

static int setup_group(void **state) {
    wm_manager_configs *config = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    *state = config;
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    wm_manager_configs *config = *state;
    os_free(config);
    test_mode = 0;
    return 0;
}

// Wrappers

int __wrap_accept() {
    return mock();
}

// Tests

void test_wm_agent_upgrade_listen_messages_upgrade_command(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;

    char *input = "{"
                  "   \"command\": \"upgrade\","
                  "   \"parameters\": {"
                  "        \"agents\": [1],"
                  "        \"wpk_repo\": \"packages.wazuh.com/wpk\""
                  "    }"
                  "}";

    size_t input_size = strlen(input) + 1;
    wm_upgrade_task *upgrade_task = NULL;
    int *agents = NULL;
    char *response = NULL;

    os_calloc(1, sizeof(wm_upgrade_task), upgrade_task);
    os_calloc(2, sizeof(int), agents);
    os_calloc(OS_SIZE_256, sizeof(char), response);

    agents[0] = 1;
    agents[1] = -1;

    sprintf(response, "{"
                      "    \"error\":0,"
                      "    \"data\":["
                      "         {"
                      "            \"error\":0,"
                      "            \"message\":\"Success\","
                      "            \"agent\":1,"
                      "            \"task_id\":1"
                      "         }"
                      "     ],"
                      "    \"message\":\"Success\""
                      "}");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: '{"
                                                                               "   \"command\": \"upgrade\","
                                                                               "   \"parameters\": {"
                                                                               "        \"agents\": [1],"
                                                                               "        \"wpk_repo\": \"packages.wazuh.com/wpk\""
                                                                               "    }"
                                                                               "}'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, (void*)upgrade_task);
    will_return(__wrap_wm_agent_upgrade_parse_message, agents);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, WM_UPGRADE_UPGRADE);

    expect_value(__wrap_wm_agent_upgrade_process_upgrade_command, agent_ids, agents);
    expect_value(__wrap_wm_agent_upgrade_process_upgrade_command, task, upgrade_task);
    will_return(__wrap_wm_agent_upgrade_process_upgrade_command, response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{"
                                                                              "    \"error\":0,"
                                                                              "    \"data\":["
                                                                              "         {"
                                                                              "            \"error\":0,"
                                                                              "            \"message\":\"Success\","
                                                                              "            \"agent\":1,"
                                                                              "            \"task_id\":1"
                                                                              "         }"
                                                                              "     ],"
                                                                              "    \"message\":\"Success\""
                                                                              "}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_upgrade_custom_command(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;

    char *input = "{"
                  "   \"command\": \"upgrade_custom\","
                  "   \"parameters\": {"
                  "        \"agents\": [2],"
                  "        \"file_path\":\"/test/wazuh.wpk\""
                  "    }"
                  "}";

    size_t input_size = strlen(input) + 1;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;
    int *agents = NULL;
    char *response = NULL;

    os_calloc(1, sizeof(wm_upgrade_custom_task), upgrade_custom_task);
    os_calloc(2, sizeof(int), agents);
    os_calloc(OS_SIZE_256, sizeof(char), response);

    agents[0] = 2;
    agents[1] = -1;

    sprintf(response, "{"
                      "    \"error\":0,"
                      "    \"data\":["
                      "         {"
                      "            \"error\":0,"
                      "            \"message\":\"Success\","
                      "            \"agent\":2,"
                      "            \"task_id\":2"
                      "         }"
                      "     ],"
                      "    \"message\":\"Success\""
                      "}");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: '{"
                                                                               "   \"command\": \"upgrade_custom\","
                                                                               "   \"parameters\": {"
                                                                               "        \"agents\": [2],"
                                                                               "        \"file_path\":\"/test/wazuh.wpk\""
                                                                               "    }"
                                                                               "}'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, (void*)upgrade_custom_task);
    will_return(__wrap_wm_agent_upgrade_parse_message, agents);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, WM_UPGRADE_UPGRADE_CUSTOM);

    expect_value(__wrap_wm_agent_upgrade_process_upgrade_custom_command, agent_ids, agents);
    expect_value(__wrap_wm_agent_upgrade_process_upgrade_custom_command, task, upgrade_custom_task);
    will_return(__wrap_wm_agent_upgrade_process_upgrade_custom_command, response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{"
                                                                              "    \"error\":0,"
                                                                              "    \"data\":["
                                                                              "         {"
                                                                              "            \"error\":0,"
                                                                              "            \"message\":\"Success\","
                                                                              "            \"agent\":2,"
                                                                              "            \"task_id\":2"
                                                                              "         }"
                                                                              "     ],"
                                                                              "    \"message\":\"Success\""
                                                                              "}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    wm_agent_upgrade_listen_messages(config);
}


void test_wm_agent_upgrade_listen_messages_parse_error(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    size_t input_size = strlen(input) + 1;

    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, "error", WM_UPGRADE_UNKNOWN_ERROR);
    cJSON_AddStringToObject(response_json, "message", upgrade_error_codes[WM_UPGRADE_UNKNOWN_ERROR]);

    char *response = "{\"error\":17,\"message\":\"Upgrade procedure could not start\",\"data\":[{\"error\":17,\"message\":\"Upgrade procedure could not start\"}]}";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: 'Bad JSON'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response, error_id, WM_UPGRADE_UNKNOWN_ERROR);
    will_return(__wrap_wm_agent_upgrade_parse_response, response_json);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{\"error\":17,\"message\":\"Upgrade procedure could not start\",\"data\":[{\"error\":17,\"message\":\"Upgrade procedure could not start\"}]}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_parse_error_with_message(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    size_t input_size = strlen(input) + 1;
    char *response = NULL;

    os_calloc(OS_SIZE_128, sizeof(char), response);

    sprintf(response, "{\"error\":1,\"data\":[{\"error\":1,\"message\":\"Could not parse message JSON\"}],\"message\":\"Could not parse message JSON\"}");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: 'Bad JSON'");

    expect_string(__wrap_wm_agent_upgrade_parse_message, buffer, input);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, NULL);
    will_return(__wrap_wm_agent_upgrade_parse_message, response);
    will_return(__wrap_wm_agent_upgrade_parse_message, OS_INVALID);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{\"error\":1,\"data\":[{\"error\":1,\"message\":\"Could not parse message JSON\"}],\"message\":\"Could not parse message JSON\"}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_receive_empty(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8159): Empty message from local client.");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_receive_error(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8111): Error in recv(): 'Success'");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_receive_sock_error(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_accept_error_eintr(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_accept_error(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = 1;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8110): Error in accept(): 'Operation not permitted'");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_select_zero(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_select_error_eintr(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_select_error(void **state)
{
    wm_manager_configs *config = *state;
    int socket = 0;
    errno = 1;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    expect_value_count(__wrap_sleep, seconds, 1, WM_AGENT_UPGRADE_START_WAIT_TIME);


    will_return(__wrap_select, -1);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8109): Error in select(): 'Operation not permitted'. Exiting...");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_listen_messages_bind_error(void **state)
{
    wm_manager_configs *config = *state;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, -1);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8108): Unable to bind to socket 'queue/sockets/task-upgrade.sock': 'Operation not permitted'");

    wm_agent_upgrade_listen_messages(config);
}

void test_wm_agent_upgrade_start_manager_module_enabled(void **state)
{
    wm_manager_configs *config = *state;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_any(__wrap__mtinfo, formatted_msg);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, -1);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8108): Unable to bind to socket 'queue/sockets/task-upgrade.sock': 'Operation not permitted'");

    wm_agent_upgrade_start_manager_module(config, 1);
}

void test_wm_agent_upgrade_start_manager_module_disabled(void **state)
{
    wm_manager_configs *config = *state;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8152): Module Agent Upgrade disabled. Exiting...");

    expect_assert_failure(wm_agent_upgrade_start_manager_module(config, 0));
}

// Tests for wm_agent_upgrade_send_tasks_information
//
// The task manager serves HTTP/1.1 over its socket, so these drive the uhttp_* client rather than
// the connect/send/recv trio this function used to call. __wrap_uhttp_post() takes three queued
// values in order -- response body, return code, HTTP status -- and delivers the body through the
// buffer the caller installed with uhttp_client_set_response_buffer(), which is what makes the
// success case exercise the real parse rather than a handed-over pointer.

/// @brief A non-NULL handle for uhttp_client_new() to hand back. Never dereferenced: every uhttp_*
///        entry point the function calls is wrapped, so the value only has to be distinguishable
///        from NULL.
static uhttp_client_t *const TEST_HTTP_CLIENT = (uhttp_client_t *)0xC0FFEE;

void test_wm_agent_upgrade_send_tasks_information_client_error(void **state)
{
    (void) state;

    cJSON *message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "command", "upgrade");

    // The client cannot even be built -- no socket, no request, and nothing to free.
    will_return(__wrap_uhttp_client_new, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8104): Cannot connect to 'queue/sockets/task.sock'. Could not reach task manager module.");

    cJSON *result = wm_agent_upgrade_send_tasks_information(message);

    assert_null(result);

    cJSON_Delete(message);
}

void test_wm_agent_upgrade_send_tasks_information_transport_error(void **state)
{
    (void) state;

    cJSON *message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "command", "upgrade");

    will_return(__wrap_uhttp_client_new, TEST_HTTP_CLIENT);

    expect_any(__wrap__mtdebug1, tag);
    expect_any(__wrap__mtdebug1, formatted_msg);

    // The request never reached a server: no status was ever read off the wire, which is what
    // separates "the task manager is not there" from "the task manager said no".
    will_return(__wrap_uhttp_post, NULL);
    will_return(__wrap_uhttp_post, -1);
    will_return(__wrap_uhttp_post, 0);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8104): Cannot connect to 'queue/sockets/task.sock'. Could not reach task manager module.");

    cJSON *result = wm_agent_upgrade_send_tasks_information(message);

    assert_null(result);

    cJSON_Delete(message);
}

void test_wm_agent_upgrade_send_tasks_information_http_error(void **state)
{
    (void) state;

    cJSON *message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "command", "upgrade");

    will_return(__wrap_uhttp_client_new, TEST_HTTP_CLIENT);

    expect_any(__wrap__mtdebug1, tag);
    expect_any(__wrap__mtdebug1, formatted_msg);

    // A real answer, refusing the task. Reported with its status rather than as an unreachable
    // module, so an operator can tell a rejected request from an absent daemon.
    will_return(__wrap_uhttp_post, "{\"error\":\"bad request\"}");
    will_return(__wrap_uhttp_post, -1);
    will_return(__wrap_uhttp_post, 400);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "The task manager refused the upgrade task with HTTP 400.");

    cJSON *result = wm_agent_upgrade_send_tasks_information(message);

    assert_null(result);

    cJSON_Delete(message);
}

void test_wm_agent_upgrade_send_tasks_information_invalid_json(void **state)
{
    (void) state;

    cJSON *message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "command", "upgrade");

    will_return(__wrap_uhttp_client_new, TEST_HTTP_CLIENT);

    expect_any(__wrap__mtdebug1, tag);
    expect_any(__wrap__mtdebug1, formatted_msg);

    // 2xx with a body that is not JSON.
    will_return(__wrap_uhttp_post, "invalid json {");
    will_return(__wrap_uhttp_post, 0);
    will_return(__wrap_uhttp_post, 200);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8105): Response from task manager does not have a valid JSON format.");

    cJSON *result = wm_agent_upgrade_send_tasks_information(message);

    assert_null(result);

    cJSON_Delete(message);
}

void test_wm_agent_upgrade_send_tasks_information_success(void **state)
{
    (void) state;

    cJSON *message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "command", "upgrade");

    will_return(__wrap_uhttp_client_new, TEST_HTTP_CLIENT);

    expect_any(__wrap__mtdebug1, tag);
    expect_any(__wrap__mtdebug1, formatted_msg);

    // A created task is answered with its id and nothing else; the HTTP status carries what the
    // old "status" member used to.
    will_return(__wrap_uhttp_post, "{\"task_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}");
    will_return(__wrap_uhttp_post, 0);
    will_return(__wrap_uhttp_post, 200);

    expect_any(__wrap__mtdebug1, tag);
    expect_any(__wrap__mtdebug1, formatted_msg);

    cJSON *result = wm_agent_upgrade_send_tasks_information(message);

    assert_non_null(result);
    cJSON *task_id = cJSON_GetObjectItem(result, "task_id");
    assert_non_null(task_id);
    assert_string_equal(cJSON_GetStringValue(task_id),
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    // The url must be ABSOLUTE. libcurl parses it before it looks at CURLOPT_UNIX_SOCKET_PATH and
    // rejects a bare path with CURLE_URL_MALFORMAT and no HTTP status -- which this function would
    // report as an unreachable task manager, so the mistake looks like an outage rather than a bug.
    const uhttp_captured_options_t *sent = uhttp_wrappers_last_options();
    assert_string_equal(sent->url, "http://localhost/v1/tasks");
    assert_string_equal(sent->unix_socket_path, "queue/sockets/task.sock");

    cJSON_Delete(message);
    cJSON_Delete(result);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_agent_upgrade_listen_messages
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_upgrade_command),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_upgrade_custom_command),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_parse_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_parse_error_with_message),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_empty),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_sock_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_zero),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_bind_error),
        // wm_agent_upgrade_start_manager_module
        cmocka_unit_test(test_wm_agent_upgrade_start_manager_module_enabled),
        cmocka_unit_test(test_wm_agent_upgrade_start_manager_module_disabled),
        // wm_agent_upgrade_send_tasks_information
        cmocka_unit_test(test_wm_agent_upgrade_send_tasks_information_client_error),
        cmocka_unit_test(test_wm_agent_upgrade_send_tasks_information_transport_error),
        cmocka_unit_test(test_wm_agent_upgrade_send_tasks_information_http_error),
        cmocka_unit_test(test_wm_agent_upgrade_send_tasks_information_invalid_json),
        cmocka_unit_test(test_wm_agent_upgrade_send_tasks_information_success),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
