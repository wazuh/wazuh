/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.h"
#include "../../headers/shared.h"

void wm_upgrade_agent_send_ack_message(int *queue_fd, wm_upgrade_agent_state state);
bool wm_upgrade_agent_search_upgrade_result(int *queue_fd);

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
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue '/queue/ossec/queue' not accessible: 'Success'");

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
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
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue '/queue/ossec/queue' not accessible: 'Success'");

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, -1);

    expect_string(__wrap__mterror_exit, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror_exit, formatted_msg, "(1211): Unable to access queue: '/queue/ossec/queue'. Giving up.");

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

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

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

void test_wm_upgrade_agent_search_upgrade_result_failed(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

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

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

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

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

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

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME * 1000);
#else
    expect_value(__wrap_sleep, seconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME);
#endif

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

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

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    wm_agent_upgrade_check_status(config);
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

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

#ifdef TEST_WINAGENT
    expect_value(wrap_Sleep, dwMilliseconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME * 1000);
#else
    expect_value(__wrap_sleep, seconds, WM_AGENT_UPGRADE_RESULT_WAIT_TIME);
#endif

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

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

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

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

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

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

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, (FILE*)1);

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

    expect_string(__wrap_fopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    wm_agent_upgrade_check_status(config);
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

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
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
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_error_open, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_error_code, setup_test_executions),
        // wm_agent_upgrade_check_status
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_time_limit, setup_test_executions),
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_queue_error, setup_test_executions)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
