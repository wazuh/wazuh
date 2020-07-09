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

#include "../../headers/shared.h"
#include "../../analysisd/logtest.h"

int Read_Logtest(XML_NODE node);

/* setup/teardown */



/* wraps */

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

/* tests */

/* Read_Logtest */

void test_Read_Logtest_invalid_element(void **state)
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

void test_Read_Logtest_invalid_content(void **state)
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

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'enabled': test.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

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

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("enabled");
    nodes[0]->content = strdup("yes");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_invalid_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("test");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'threads': test.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_smaller_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("-1");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'threads': -1.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_bigger_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("1000000");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'threads': 1000000.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_auto_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("auto");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_valid_threads(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("threads");
    nodes[0]->content = strdup("64");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_invalid_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("test");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'max_sessions': test.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_smaller_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("-1");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'max_sessions': -1.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_bigger_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("1000000");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'max_sessions': 1000000.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_valid_max_sessions(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("max_sessions");
    nodes[0]->content = strdup("1000000");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'max_sessions': 1000000.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_invalid_session_timeout(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("session_timeout");
    nodes[0]->content = strdup("test");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'session_timeout': test.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_smaller_session_timeout(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("session_timeout");
    nodes[0]->content = strdup("-1");

    expect_string(__wrap__mwarn, formatted_msg, "(1235): Invalid value for element 'session_timeout': -1.");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_INVALID);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

void test_Read_Logtest_valid_session_timeout(void **state)
{
    xml_node **nodes;
    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));

    os_calloc(4, sizeof(char), logtest_conf.enabled);

    nodes[0]->element = strdup("session_timeout");
    nodes[0]->content = strdup("1000000");

    int ret = Read_Logtest(nodes);
    assert_int_equal(ret, OS_SUCCESS);

    os_free(nodes[0]->element);
    os_free(nodes[0]->content);
    os_free(nodes[0]);
    os_free(nodes);
    os_free(logtest_conf.enabled);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests Read_Logtest
        cmocka_unit_test(test_Read_Logtest_invalid_element),
        cmocka_unit_test(test_Read_Logtest_invalid_content),
        cmocka_unit_test(test_Read_Logtest_invalid_enabled),
        cmocka_unit_test(test_Read_Logtest_valid_enabled),
        cmocka_unit_test(test_Read_Logtest_invalid_threads),
        cmocka_unit_test(test_Read_Logtest_smaller_threads),
        cmocka_unit_test(test_Read_Logtest_bigger_threads),
        cmocka_unit_test(test_Read_Logtest_valid_threads),
        cmocka_unit_test(test_Read_Logtest_invalid_max_sessions),
        cmocka_unit_test(test_Read_Logtest_smaller_max_sessions),
        cmocka_unit_test(test_Read_Logtest_bigger_max_sessions),
        cmocka_unit_test(test_Read_Logtest_valid_max_sessions),
        cmocka_unit_test(test_Read_Logtest_invalid_session_timeout),
        cmocka_unit_test(test_Read_Logtest_smaller_session_timeout),
        cmocka_unit_test(test_Read_Logtest_valid_session_timeout)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
