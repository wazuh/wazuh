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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.h"
#include "../../headers/shared.h"

static int unit_testing;

#if defined(TEST_AGENT) || defined(TEST_WINAGENT)

void wm_upgrade_agent_send_ack_message(int queue_fd, wm_upgrade_agent_state state);
bool wm_upgrade_agent_search_upgrade_result(int queue_fd);

#endif

// Setup / teardown

static int setup_group(void **state) {
    wm_agent_configs *config = NULL;
    os_calloc(1, sizeof(wm_agent_configs), config);
    *state = config;
    unit_testing = 1;
    return 0;
}

static int teardown_group(void **state) {
    wm_agent_configs *config = *state;
    os_free(config);
    unit_testing = 0;
    return 0;
}

#if defined(TEST_AGENT) || defined(TEST_WINAGENT)

static int setup_test_executions(void **state) {
    wm_max_eps = 1;
    return 0;
}

// Wrappers

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtdebug1(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) {
    check_expected(usec);
    check_expected(queue);
    check_expected(message);
    check_expected(locmsg);
    check_expected(loc);

    return mock();
}

extern FILE* __real_fopen(const char* path, const char* mode);
FILE* __wrap_fopen(const char* path, const char* mode) {
    if(unit_testing) {
        check_expected(mode);
        return mock_ptr_type(FILE*);
    }
    return __real_fopen(path, mode);
}

int __wrap_fgets(char *s, int size, FILE *stream) {
    strncpy(s, mock_type(char *), size);
    return mock();
}

int __wrap_fclose() {
    return 0;
}

int __wrap_StartMQ(const char *path, short int type) {
    check_expected(path);
    check_expected(type);
    return mock();
}

int __wrap_sleep(unsigned int seconds) {
    check_expected(seconds);
    return mock();
}

int __wrap_close() {
    return 1;
}

// Tests

void test_wm_upgrade_agent_send_ack_message_successful(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFULL;

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"params\":{\"error\":0," 
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":0," 
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    wm_upgrade_agent_send_ack_message(queue, upgrade_state);
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
                                               "\"params\":{\"error\":2,"
                                                           "\"message\":\"Upgrade failed\","
                                                           "\"status\":\"Failed\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":2,"
                                                                 "\"message\":\"Upgrade failed\","
                                                                 "\"status\":\"Failed\"}}'");

    wm_upgrade_agent_send_ack_message(queue, upgrade_state);
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
                                               "\"params\":{\"error\":2,"
                                                           "\"message\":\"Upgrade failed\","
                                                           "\"status\":\"Failed\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue '/queue/ossec/queue' not accessible: 'Success'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":2,"
                                                                 "\"message\":\"Upgrade failed\","
                                                                 "\"status\":\"Failed\"}}'");

    wm_upgrade_agent_send_ack_message(queue, upgrade_state);
}

void test_wm_upgrade_agent_search_upgrade_result_successful(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFULL;

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fgets, "0\n");
    will_return(__wrap_fgets, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"params\":{\"error\":0," 
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":0," 
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    int ret = wm_upgrade_agent_search_upgrade_result(queue);

    assert_int_equal(ret, 1);
}

void test_wm_upgrade_agent_search_upgrade_result_failed(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fgets, "2\n");
    will_return(__wrap_fgets, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"params\":{\"error\":2,"
                                                           "\"message\":\"Upgrade failed\","
                                                           "\"status\":\"Failed\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":2,"
                                                                 "\"message\":\"Upgrade failed\","
                                                                 "\"status\":\"Failed\"}}'");

    int ret = wm_upgrade_agent_search_upgrade_result(queue);

    assert_int_equal(ret, 1);
}

void test_wm_upgrade_agent_search_upgrade_result_error_open(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    int ret = wm_upgrade_agent_search_upgrade_result(queue);

    assert_int_equal(ret, 0);
}

void test_wm_upgrade_agent_search_upgrade_result_error_code(void **state)
{
    (void) state;
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_FAILED;

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fgets, "5\n");
    will_return(__wrap_fgets, 1);

    int ret = wm_upgrade_agent_search_upgrade_result(queue);

    assert_int_equal(ret, 0);
}

void test_wm_agent_upgrade_check_status_successful(void **state)
{
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFULL;
    wm_agent_configs *config = *state;

    config->upgrade_wait_start = 1;
    config->upgrade_wait_max = 10;
    config->ugprade_wait_factor_increase = 3;

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fgets, "0\n");
    will_return(__wrap_fgets, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"params\":{\"error\":0," 
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":0," 
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    expect_value(__wrap_sleep, seconds, config->upgrade_wait_start);
    will_return(__wrap_sleep, 1);

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    wm_agent_upgrade_check_status(*config);
}

void test_wm_agent_upgrade_check_status_time_limit(void **state)
{
    int queue = 0;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFULL;
    wm_agent_configs *config = *state;

    config->upgrade_wait_start = 1;
    config->upgrade_wait_max = 10;
    config->ugprade_wait_factor_increase = 3;

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fgets, "0\n");
    will_return(__wrap_fgets, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"params\":{\"error\":0," 
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":0," 
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    expect_value(__wrap_sleep, seconds, config->upgrade_wait_start);
    will_return(__wrap_sleep, 1);

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fgets, "0\n");
    will_return(__wrap_fgets, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"params\":{\"error\":0," 
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":0," 
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    expect_value(__wrap_sleep, seconds, config->upgrade_wait_start * config->ugprade_wait_factor_increase);
    will_return(__wrap_sleep, 1);

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fgets, "0\n");
    will_return(__wrap_fgets, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"params\":{\"error\":0," 
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":0," 
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    expect_value(__wrap_sleep, seconds, config->upgrade_wait_start * config->ugprade_wait_factor_increase * config->ugprade_wait_factor_increase);
    will_return(__wrap_sleep, 1);

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fgets, "0\n");
    will_return(__wrap_fgets, 1);

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue);
    expect_string(__wrap_wm_sendmsg, message, "{\"command\":\"upgrade_update_status\","
                                               "\"params\":{\"error\":0," 
                                                           "\"message\":\"Upgrade was successful\","
                                                           "\"status\":\"Done\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, WM_AGENT_UPGRADE_MODULE_NAME);
    expect_value(__wrap_wm_sendmsg, loc, UPGRADE_MQ);

    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8163): Sending upgrade ACK event: "
                                                   "'{\"command\":\"upgrade_update_status\","
                                                     "\"params\":{\"error\":0," 
                                                                 "\"message\":\"Upgrade was successful\","
                                                                 "\"status\":\"Done\"}}'");

    expect_value(__wrap_sleep, seconds, config->upgrade_wait_max);
    will_return(__wrap_sleep, 1);

    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    wm_agent_upgrade_check_status(*config);
}

void test_wm_agent_upgrade_check_status_queue_error(void **state)
{
    int queue = -1;
    int result = 0;
    wm_upgrade_agent_state upgrade_state = WM_UPGRADE_SUCCESSFULL;
    wm_agent_configs *config = *state;

    config->upgrade_wait_start = 1;
    config->upgrade_wait_max = 10;
    config->ugprade_wait_factor_increase = 3;

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, queue);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8113): Could not open default queue to send upgrade notification.");

    wm_agent_upgrade_check_status(*config);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
        // wm_upgrade_agent_send_ack_message
        cmocka_unit_test_setup(test_wm_upgrade_agent_send_ack_message_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_send_ack_message_failed, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_send_ack_message_error, setup_test_executions),
        // wm_upgrade_agent_search_upgrade_result
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_failed, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_error_open, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_error_code, setup_test_executions),
        // wm_agent_upgrade_check_status
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_time_limit, setup_test_executions),
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_queue_error, setup_test_executions)
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
