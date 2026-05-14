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

#include "../../headers/shared.h"
#include "../../analysisd/logtest.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

int Read_Logtest(XML_NODE node);
cJSON *getRuleTestConfig();

/* setup/teardown */



/* wraps */

int __wrap_get_nproc(void) {
    return mock();
}

cJSON * __wrap_cJSON_CreateObject(void) {
    return mock_type(cJSON *);
}

cJSON* __wrap_cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string) {
    if (name) check_expected(name);
    if (string) check_expected(string);
    return mock_type(cJSON *);
}

cJSON* __wrap_cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number) {
    if (name) check_expected(name);
    if (number) check_expected(number);
    return mock_type(cJSON *);
}


void __wrap_cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item) {
    if (string) check_expected(string);
    if (item) check_expected(item);
}

/* tests */

/* Read_Logtest */

void test_Read_Logtest_element_NULL(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = NULL;
    nodes[0]->content = strdup("yes");

    expect_string(__wrap__merror, formatted_msg, XML_ELEMNULL);

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_content_NULL(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("enabled");
    nodes[0]->content = NULL;

    expect_string(__wrap__merror, formatted_msg, "(1234): Invalid NULL content for element: enabled.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_invalid_enabled(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("enabled");
    nodes[0]->content = strdup("test");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'enabled': test.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_valid_disabled(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("enabled");
    nodes[0]->content = strdup("no");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_valid_enabled(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("enabled");
    nodes[0]->content = strdup("yes");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_invalid_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("test");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'threads': test.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_auto_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("auto");

    will_return(__wrap_get_nproc, 1);

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_smaller_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("-1");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'threads': -1.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_bigger_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("1000000");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'threads': 1000000.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_limit_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("256");

    expect_string(__wrap__mwarn, formatted_msg, "(7000): Number of logtest threads too high. Only creates 128 threads");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_valid_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("64");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_invalid_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("test");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'max_sessions': test.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_smaller_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("-1");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'max_sessions': -1.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_bigger_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("1000000");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'max_sessions': 1000000.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_limit_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("700");

    expect_string(__wrap__mwarn, formatted_msg, "(7001): Number of maximum users connected in logtest too high. Only allows 500 users");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_valid_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("200");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_invalid_session_timeout(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("session_timeout");
    nodes[0]->content = strdup("test");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'session_timeout': test.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_smaller_session_timeout(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("session_timeout");
    nodes[0]->content = strdup("-1");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'session_timeout': -1.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_limit_session_timeout(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("session_timeout");
    nodes[0]->content = strdup("32000000");

    expect_string(__wrap__mwarn, formatted_msg, "(7002): Number of maximum user timeouts in logtest too high. Only allows 31536000s maximum timeouts");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_valid_session_timeout(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("session_timeout");
    nodes[0]->content = strdup("1000000");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

void test_Read_Logtest_invalid_element(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    nodes[0]->element = strdup("test");
    nodes[0]->content = strdup("unit_test");

    expect_string(__wrap__merror, formatted_msg, "(1230): Invalid element in the configuration: 'test'.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
}

/* getRuleTestConfig */
void test_getRuleTestConfig_disabled(void **state)
{
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    w_logtest_conf.enabled = false;
    w_logtest_conf.threads = LOGTEST_LIMIT_THREAD;
    w_logtest_conf.max_sessions = LOGTEST_LIMIT_MAX_SESSIONS;
    w_logtest_conf.session_timeout = LOGTEST_LIMIT_SESSION_TIMEOUT;

    expect_string(__wrap_cJSON_AddStringToObject, name, "enabled");
    expect_string(__wrap_cJSON_AddStringToObject, string, "no");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "threads");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 128);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "max_sessions");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 500);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "session_timeout");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 31536000);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddItemToObject, string, "rule_test");
    expect_value(__wrap_cJSON_AddItemToObject, item, (cJSON *)1);

    cJSON* ret = getRuleTestConfig();

}

void test_getRuleTestConfig_enabled(void **state)
{
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    w_logtest_conf.enabled = true;
    w_logtest_conf.threads = LOGTEST_LIMIT_THREAD;
    w_logtest_conf.max_sessions = LOGTEST_LIMIT_MAX_SESSIONS;
    w_logtest_conf.session_timeout = LOGTEST_LIMIT_SESSION_TIMEOUT;

    expect_string(__wrap_cJSON_AddStringToObject, name, "enabled");
    expect_string(__wrap_cJSON_AddStringToObject, string, "yes");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "threads");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 128);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "max_sessions");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 500);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "session_timeout");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 31536000);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddItemToObject, string, "rule_test");
    expect_value(__wrap_cJSON_AddItemToObject, item, (cJSON *)1);

    cJSON* ret = getRuleTestConfig();

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests Read_Logtest
        cmocka_unit_test(test_Read_Logtest_element_NULL),
        cmocka_unit_test(test_Read_Logtest_content_NULL),
        cmocka_unit_test(test_Read_Logtest_invalid_enabled),
        cmocka_unit_test(test_Read_Logtest_valid_disabled),
        cmocka_unit_test(test_Read_Logtest_valid_enabled),
        cmocka_unit_test(test_Read_Logtest_invalid_threads),
        cmocka_unit_test(test_Read_Logtest_auto_threads),
        cmocka_unit_test(test_Read_Logtest_smaller_threads),
        cmocka_unit_test(test_Read_Logtest_bigger_threads),
        cmocka_unit_test(test_Read_Logtest_limit_threads),
        cmocka_unit_test(test_Read_Logtest_valid_threads),
        cmocka_unit_test(test_Read_Logtest_invalid_max_sessions),
        cmocka_unit_test(test_Read_Logtest_smaller_max_sessions),
        cmocka_unit_test(test_Read_Logtest_bigger_max_sessions),
        cmocka_unit_test(test_Read_Logtest_limit_max_sessions),
        cmocka_unit_test(test_Read_Logtest_valid_max_sessions),
        cmocka_unit_test(test_Read_Logtest_invalid_session_timeout),
        cmocka_unit_test(test_Read_Logtest_smaller_session_timeout),
        cmocka_unit_test(test_Read_Logtest_limit_session_timeout),
        cmocka_unit_test(test_Read_Logtest_valid_session_timeout),
        cmocka_unit_test(test_Read_Logtest_invalid_element),
        // Tests getRuleTestConfig
        cmocka_unit_test(test_getRuleTestConfig_disabled),
        cmocka_unit_test(test_getRuleTestConfig_enabled)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
