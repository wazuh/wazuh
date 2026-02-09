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
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>

#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/select_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.h"
#include "../../headers/shared.h"

#ifndef TEST_WINAGENT
void wm_agent_upgrade_listen_messages(const wm_agent_configs* agent_configs);
#endif
void wm_agent_upgrade_check_status(const wm_agent_configs* agent_config);
bool wm_upgrade_agent_search_upgrade_result(int *queue_fd);
void wm_upgrade_agent_send_ack_message(int *queue_fd, wm_upgrade_agent_state state);

// Setup / teardown

static int setup_group(void **state) {
    wm_agent_configs *config = NULL;
    os_calloc(1, sizeof(wm_agent_configs), config);
    *state = config;
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    wm_agent_configs *config = *state;
    os_free(config);
    test_mode = 0;
    return 0;
}

static int setup_test_executions(void **state) {
    wm_max_eps = 1;
    return 0;
}

// Wrappers

int __wrap_accept() {
    return mock();
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    check_expected_ptr(function_pointer);
    return 1;
}

// Tests

void test_wm_upgrade_agent_send_ack_message_successful(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFUL;

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":0,"
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":0,"
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    wm_upgrade_agent_send_ack_message(&queue, upgrade_state);

    assert_int_equal(queue, 0);
}

void test_wm_upgrade_agent_send_ack_message_failed(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":2,"
                                                           "\"message\":\"Upgrade failed\","
                                                           "\"status\":\"Failed\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":2,"
                                                                 "\"message\":\"Upgrade failed\","
                                                                 "\"status\":\"Failed\"}}'");

    wm_upgrade_agent_send_ack_message(&queue, upgrade_state);

    assert_int_equal(queue, 0);
}

void test_wm_upgrade_agent_send_ack_message_error(void **state)
{
    (void) state;
    int queue = 0;
    int result = -1;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":2,"
                                                           "\"message\":\"Upgrade failed\","
                                                           "\"status\":\"Failed\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue 'queue/sockets/queue' not accessible: 'Success'");

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":2,"
                                                                 "\"message\":\"Upgrade failed\","
                                                                 "\"status\":\"Failed\"}}'");

    wm_upgrade_agent_send_ack_message(&queue, upgrade_state);

    assert_int_equal(queue, 1);
}

void test_wm_upgrade_agent_send_ack_message_error_exit(void **state)
{
    (void) state;
    int queue = 0;
    int result = -1;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":2,"
                                                           "\"message\":\"Upgrade failed\","
                                                           "\"status\":\"Failed\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue 'queue/sockets/queue' not accessible: 'Success'");

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, -1);

    expect_string(__wrap__mterror_exit, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror_exit, formatted_msg, "(1211): Unable to access queue: 'queue/sockets/queue'. Giving up.");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":2,"
                                                                 "\"message\":\"Upgrade failed\","
                                                                 "\"status\":\"Failed\"}}'");

    wm_upgrade_agent_send_ack_message(&queue, upgrade_state);

    assert_int_equal(queue, -1);
}

void test_wm_upgrade_agent_search_upgrade_result_successful(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFUL;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "0\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "0\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":0,"
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":0,"
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    int ret = wm_upgrade_agent_search_upgrade_result(&queue);

    assert_int_equal(ret, 1);
    assert_int_equal(queue, 0);
}

void test_wm_upgrade_agent_search_upgrade_result_failed_missing_dependency(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED_DEPENDENCY;

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "1\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "1\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":1,"
                                                           "\"message\":\"Upgrade failed due missing dependency\","
                                                           "\"status\":\"Failed\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":1,"
                                                                 "\"message\":\"Upgrade failed due missing dependency\","
                                                                 "\"status\":\"Failed\"}}'");

    int ret = wm_upgrade_agent_search_upgrade_result(&queue);

    assert_int_equal(ret, 1);
    assert_int_equal(queue, 0);
}

void test_wm_upgrade_agent_search_upgrade_result_failed(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "2\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "2\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":2,"
                                                           "\"message\":\"Upgrade failed\","
                                                           "\"status\":\"Failed\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":2,"
                                                                 "\"message\":\"Upgrade failed\","
                                                                 "\"status\":\"Failed\"}}'");

    int ret = wm_upgrade_agent_search_upgrade_result(&queue);

    assert_int_equal(ret, 1);
    assert_int_equal(queue, 0);
}

void test_wm_upgrade_agent_search_upgrade_result_error_open(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    int ret = wm_upgrade_agent_search_upgrade_result(&queue);

    assert_int_equal(ret, 0);
    assert_int_equal(queue, 0);
}

void test_wm_upgrade_agent_search_upgrade_result_error_code(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "5\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "5\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    int ret = wm_upgrade_agent_search_upgrade_result(&queue);

    assert_int_equal(ret, 0);
    assert_int_equal(queue, 0);
}

void test_wm_agent_upgrade_check_status_successful(void **state)
{
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFUL;
    wm_agent_configs *config = *state;

    config->upgrade_wait_start = 1;
    config->upgrade_wait_max = 10;
    config->upgrade_wait_factor_increase = 3;

    allow_upgrades = false;

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME * 1000);
#else
    expect_value(__wrap_sleep, seconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "0\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "0\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":0,"
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":0,"
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, config->upgrade_wait_start * 1000);
#else
    expect_value(__wrap_sleep, seconds, config->upgrade_wait_start);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    wm_agent_upgrade_check_status(config);

    assert_int_equal(allow_upgrades, true);
}

void test_wm_agent_upgrade_check_status_time_limit(void **state)
{
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFUL;
    wm_agent_configs *config = *state;

    config->upgrade_wait_start = 1;
    config->upgrade_wait_max = 10;
    config->upgrade_wait_factor_increase = 3;

    allow_upgrades = false;

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME * 1000);
#else
    expect_value(__wrap_sleep, seconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "0\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "0\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":0,"
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":0,"
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, config->upgrade_wait_start  * 1000);
#else
    expect_value(__wrap_sleep, seconds, config->upgrade_wait_start);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "0\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "0\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":0,"
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":0,"
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, config->upgrade_wait_start * config->upgrade_wait_factor_increase  * 1000);
#else
    expect_value(__wrap_sleep, seconds, config->upgrade_wait_start * config->upgrade_wait_factor_increase);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "0\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "0\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":0,"
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":0,"
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, config->upgrade_wait_start * config->upgrade_wait_factor_increase * config->upgrade_wait_factor_increase  * 1000);
#else
    expect_value(__wrap_sleep, seconds, config->upgrade_wait_start * config->upgrade_wait_factor_increase * config->upgrade_wait_factor_increase);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "0\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "0\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"parameters\":{\"error\":0,"
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"parameters\":{\"error\":0,"
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, config->upgrade_wait_max  * 1000);
#else
    expect_value(__wrap_sleep, seconds, config->upgrade_wait_max);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    wm_agent_upgrade_check_status(config);

    assert_int_equal(allow_upgrades, true);
}

void test_wm_agent_upgrade_check_status_queue_error(void **state)
{
    int queue = -1;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFUL;
    wm_agent_configs *config = *state;

    config->upgrade_wait_start = 1;
    config->upgrade_wait_max = 10;
    config->upgrade_wait_factor_increase = 3;

    allow_upgrades = false;

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME  * 1000);
#else
    expect_value(__wrap_sleep, seconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME);
#endif

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8113): Could not open default queue to send upgrade notification.");

    wm_agent_upgrade_check_status(config);

    assert_int_equal(allow_upgrades, true);
}

#ifndef TEST_WINAGENT

void test_wm_agent_upgrade_listen_messages_ok(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{"
                  "   \"command\": \"upgrade\","
                  "   \"parameters\": {"
                  "        \"file\":\"test.wpk\","
                  "        \"installer\":\"test.sh\""
                  "    }"
                  "}";

    size_t input_size = strlen(input) + 1;
    char *response = NULL;
    os_calloc(OS_SIZE_256, sizeof(char), response);

    sprintf(response, "{"
                      "    \"error\":0,"
                      "    \"data\":[],"
                      "    \"message\":\"ok\""
                      "}");

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: '{"
                                                                               "   \"command\": \"upgrade\","
                                                                               "   \"parameters\": {"
                                                                               "        \"file\":\"test.wpk\","
                                                                               "        \"installer\":\"test.sh\""
                                                                               "    }"
                                                                               "}'");

    expect_memory(__wrap_wm_agent_upgrade_process_command, buffer, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_process_command, response);
    will_return(__wrap_wm_agent_upgrade_process_command, strlen(response));

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{"
                                                                              "    \"error\":0,"
                                                                              "    \"data\":[],"
                                                                              "    \"message\":\"ok\""
                                                                              "}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_empty(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8159): Empty message from local client.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8111): Error in recv(): 'Success'");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_sock_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_accept_error_eintr(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_accept_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = 1;

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8110): Error in accept(): 'Operation not permitted'");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_zero(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
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

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_error_eintr(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
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

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_error(void **state)
{
    int socket = 0;
    errno = 1;

    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, socket);

    will_return(__wrap_select, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8109): Error in select(): 'Operation not permitted'. Exiting...");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_bind_error(void **state)
{
    expect_string(__wrap_OS_BindUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_BindUnixDomain, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8108): Unable to bind to socket 'queue/ossec/upgrade': 'Operation not permitted'");

    wm_agent_upgrade_listen_messages(NULL);
}

#endif

void test_wm_agent_upgrade_start_agent_module_enabled(void **state)
{
    int queue = -1;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFUL;
    wm_agent_configs *config = *state;

    config->upgrade_wait_start = 1;
    config->upgrade_wait_max = 10;
    config->upgrade_wait_factor_increase = 3;

    allow_upgrades = false;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8153): Module Agent Upgrade started.");

#ifndef TEST_WINAGENT
    expect_memory(__wrap_CreateThread, function_pointer, wm_agent_upgrade_listen_messages, sizeof(wm_agent_upgrade_listen_messages));
#endif

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME  * 1000);
#else
    expect_value(__wrap_sleep, seconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME);
#endif

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8113): Could not open default queue to send upgrade notification.");

    wm_agent_upgrade_start_agent_module(config, 1);

    assert_int_equal(allow_upgrades, true);
}

void test_wm_agent_upgrade_start_agent_module_disabled(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;

#ifndef TEST_WINAGENT
    expect_memory(__wrap_CreateThread, function_pointer, wm_agent_upgrade_listen_messages, sizeof(wm_agent_upgrade_listen_messages));
#endif

    wm_agent_upgrade_start_agent_module(config, 0);

    assert_int_equal(allow_upgrades, false);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_upgrade_agent_send_ack_message
        cmocka_unit_test_setup(test_wm_upgrade_agent_send_ack_message_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_send_ack_message_failed, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_send_ack_message_error, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_send_ack_message_error_exit, setup_test_executions),
        // wm_upgrade_agent_search_upgrade_result
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_failed, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_failed_missing_dependency, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_error_open, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_error_code, setup_test_executions),
        // wm_agent_upgrade_check_status
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_time_limit, setup_test_executions),
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_queue_error, setup_test_executions),
#ifndef TEST_WINAGENT
        // wm_agent_upgrade_listen_messages
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_ok),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_empty),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_sock_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_zero),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_bind_error),
#endif
        // wm_agent_upgrade_start_agent_module
        cmocka_unit_test_setup(test_wm_agent_upgrade_start_agent_module_enabled, setup_test_executions),
        cmocka_unit_test(test_wm_agent_upgrade_start_agent_module_disabled)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
