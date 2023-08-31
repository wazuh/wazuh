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

#include "shared.h"
#include "../config/localfile-config.h"
#include "../config/config.h"
#include "../wrappers/wazuh/os_xml/os_xml_wrappers.h"

const char * multiline_attr_match_str(w_multiline_match_type_t match_type);
const char * multiline_attr_replace_str(w_multiline_replace_type_t replace_type);
unsigned int w_get_attr_timeout(xml_node * node);
w_multiline_replace_type_t w_get_attr_replace(xml_node * node);
w_multiline_match_type_t w_get_attr_match(xml_node * node);
int w_logcollector_get_macos_log_type(const char * content);

/* setup/teardown */

/* wraps */

/* tests */

/* multiline_attr_replace_str */
void test_multiline_attr_replace_str_no_replace(void ** state) {
    w_multiline_replace_type_t replace_type = ML_REPLACE_NO_REPLACE;
    const char expected_retval[] = "no-replace";
    const char * retval = multiline_attr_replace_str(replace_type);
    assert_string_equal(retval, expected_retval);
}

void test_multiline_attr_replace_str_none(void ** state) {
    w_multiline_replace_type_t replace_type = ML_REPLACE_NONE;
    const char expected_retval[] = "none";
    const char * retval = multiline_attr_replace_str(replace_type);
    assert_string_equal(retval, expected_retval);
}

void test_multiline_attr_replace_str_ws(void ** state) {
    w_multiline_replace_type_t replace_type = ML_REPLACE_WSPACE;
    const char expected_retval[] = "wspace";
    const char * retval = multiline_attr_replace_str(replace_type);
    assert_string_equal(retval, expected_retval);
}

void test_multiline_attr_replace_str_tab(void ** state) {
    w_multiline_replace_type_t replace_type = ML_REPLACE_TAB;
    const char expected_retval[] = "tab";
    const char * retval = multiline_attr_replace_str(replace_type);
    assert_string_equal(retval, expected_retval);
}

/* multiline_attr_match_str */
void test_multiline_attr_match_str_start(void ** state) {
    w_multiline_match_type_t match_type = ML_MATCH_START;
    const char expected_retval[] = "start";
    const char * retval = multiline_attr_match_str(match_type);
    assert_string_equal(retval, expected_retval);
}

void test_multiline_attr_match_str_all(void ** state) {
    w_multiline_match_type_t match_type = ML_MATCH_ALL;
    const char expected_retval[] = "all";
    const char * retval = multiline_attr_match_str(match_type);
    assert_string_equal(retval, expected_retval);
}

void test_multiline_attr_match_str_end(void ** state) {
    w_multiline_match_type_t match_type = ML_MATCH_END;
    const char expected_retval[] = "end";
    const char * retval = multiline_attr_match_str(match_type);
    assert_string_equal(retval, expected_retval);
}

/* w_get_attr_timeout */
void test_w_get_attr_timeout_missing(void ** state) {

    test_mode = 1;
    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, NULL);
    retval = w_get_attr_timeout(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_empty(void ** state) {

    test_mode = 1;
    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value '' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_timeout(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_not_number(void ** state) {

    test_mode = 1;
    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "test");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value 'test' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_timeout(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_mixed(void ** state) {

    test_mode = 1;
    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "11test11");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value '11test11' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_timeout(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_zero(void ** state) {

    test_mode = 1;
    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "0");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value '0' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_timeout(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_out_range(void ** state) {

    test_mode = 1;
    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;
    char str_timeout[10] = {0};
    char str_msg[300] = {0};

    sprintf(str_timeout, "%i", MULTI_LINE_REGEX_MAX_TIMEOUT + 4);
    sprintf(str_msg, "(8000): Invalid value '%s' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.", str_timeout);

    will_return(__wrap_w_get_attr_val_by_name, str_timeout);
    expect_string(__wrap__mwarn, formatted_msg, str_msg);

    retval = w_get_attr_timeout(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_out_ok(void ** state) {

    test_mode = 1;
    unsigned int expect_retval = 30;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "30");
    retval = w_get_attr_timeout(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

// Test w_get_attr_replace
void test_w_get_attr_replace_missing(void ** state) {

    test_mode = 1;
    w_multiline_replace_type_t expect_retval = ML_REPLACE_NO_REPLACE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, NULL);
    retval = w_get_attr_replace(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_no_replace(void ** state) {

    test_mode = 1;
    w_multiline_replace_type_t expect_retval = ML_REPLACE_NO_REPLACE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "no-replace");
    retval = w_get_attr_replace(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_ws(void ** state) {

    test_mode = 1;
    w_multiline_replace_type_t expect_retval = ML_REPLACE_WSPACE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "wspace");
    retval = w_get_attr_replace(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_tab(void ** state) {

    test_mode = 1;
    w_multiline_replace_type_t expect_retval = ML_REPLACE_TAB;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "tab");
    retval = w_get_attr_replace(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_none(void ** state) {

    test_mode = 1;
    w_multiline_replace_type_t expect_retval = ML_REPLACE_NONE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "none");
    retval = w_get_attr_replace(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_invalid(void ** state) {

    test_mode = 1;
    w_multiline_replace_type_t expect_retval = ML_REPLACE_NO_REPLACE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "invalid_attr");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value 'invalid_attr' for attribute 'replace' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_replace(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

/* w_get_attr_match */
void test_w_get_attr_match_invalid(void ** state) {

    test_mode = 1;
    w_multiline_match_type_t expect_retval = ML_MATCH_START;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "invalid_attr");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value 'invalid_attr' for attribute 'match' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_match(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_match_missing(void ** state) {

    test_mode = 1;
    w_multiline_match_type_t expect_retval = ML_MATCH_START;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, NULL);
    retval = w_get_attr_match(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_match_start(void ** state) {

    test_mode = 1;
    w_multiline_match_type_t expect_retval = ML_MATCH_START;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "start");
    retval = w_get_attr_match(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_match_all(void ** state) {

    test_mode = 1;
    w_multiline_match_type_t expect_retval = ML_MATCH_ALL;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "all");
    retval = w_get_attr_match(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_match_end(void ** state) {

    test_mode = 1;
    w_multiline_match_type_t expect_retval = ML_MATCH_END;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "end");
    retval = w_get_attr_match(NULL);

    test_mode = 0;
    assert_int_equal(expect_retval, retval);
}

/*  w_logcollector_get_macos_log_type  */
void test_w_logcollector_get_macos_log_type_content_NULL(void ** state) {
    const char * content = NULL;

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, 0);
}

void test_w_logcollector_get_macos_log_type_content_empty(void ** state) {
    const char * content = "";

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, 0);
}

void test_w_logcollector_get_macos_log_type_content_ignore_values(void ** state) {
    const char * content = "  hello, ,world  ";

    expect_string(__wrap__mwarn, formatted_msg, "(8003): Invalid value 'hello' for attribute 'type' in 'query' option."\
                  " Attribute will be ignored.");

    expect_string(__wrap__mwarn, formatted_msg, "(8003): Invalid value 'world' for attribute 'type' in 'query' option."\
                  " Attribute will be ignored.");

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, 0);
}

void test_w_logcollector_get_macos_log_type_content_activity(void ** state) {
    const char * content = " activity ";

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, MACOS_LOG_TYPE_ACTIVITY);
}

void test_w_logcollector_get_macos_log_type_content_log(void ** state) {
    const char * content = "log ";

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, MACOS_LOG_TYPE_LOG);
}

void test_w_logcollector_get_macos_log_type_content_trace(void ** state) {
    const char * content = " trace, ";

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, MACOS_LOG_TYPE_TRACE);
}

void test_w_logcollector_get_macos_log_type_content_trace_activity(void ** state) {
    const char * content = " trace, activity,,";

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, MACOS_LOG_TYPE_TRACE | MACOS_LOG_TYPE_ACTIVITY);
}

void test_w_logcollector_get_macos_log_type_content_trace_log_activity(void ** state) {
    const char * content = " trace, ,activity,,log ";

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, MACOS_LOG_TYPE_TRACE | MACOS_LOG_TYPE_ACTIVITY | MACOS_LOG_TYPE_LOG);
}

void test_w_logcollector_get_macos_log_type_content_log_multiword_invalid(void ** state) {
    const char * content = "log, trace  activity";

    expect_string(__wrap__mwarn, formatted_msg,
                  "(8003): Invalid value 'trace  activity' for attribute 'type' in 'query' option."
                  " Attribute will be ignored.");

    int ret = w_logcollector_get_macos_log_type(content);
    assert_int_equal(ret, MACOS_LOG_TYPE_LOG);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests replace_char
        cmocka_unit_test(test_multiline_attr_match_str_start),
        cmocka_unit_test(test_multiline_attr_match_str_all),
        cmocka_unit_test(test_multiline_attr_match_str_end),
        // Tests multiline_attr_replace_str
        cmocka_unit_test(test_multiline_attr_replace_str_no_replace),
        cmocka_unit_test(test_multiline_attr_replace_str_none),
        cmocka_unit_test(test_multiline_attr_replace_str_ws),
        cmocka_unit_test(test_multiline_attr_replace_str_tab),
        // Tests w_get_attr_timeout
        cmocka_unit_test(test_w_get_attr_timeout_missing),
        cmocka_unit_test(test_w_get_attr_timeout_empty),
        cmocka_unit_test(test_w_get_attr_timeout_zero),
        cmocka_unit_test(test_w_get_attr_timeout_not_number),
        cmocka_unit_test(test_w_get_attr_timeout_mixed),
        cmocka_unit_test(test_w_get_attr_timeout_out_range),
        cmocka_unit_test(test_w_get_attr_timeout_out_ok),
        // Tests w_get_attr_replace
        cmocka_unit_test(test_w_get_attr_replace_missing),
        cmocka_unit_test(test_w_get_attr_replace_no_replace),
        cmocka_unit_test(test_w_get_attr_replace_ws),
        cmocka_unit_test(test_w_get_attr_replace_tab),
        cmocka_unit_test(test_w_get_attr_replace_none),
        cmocka_unit_test(test_w_get_attr_replace_invalid),
        // Tests w_get_attr_match
        cmocka_unit_test(test_w_get_attr_match_missing),
        cmocka_unit_test(test_w_get_attr_match_start),
        cmocka_unit_test(test_w_get_attr_match_all),
        cmocka_unit_test(test_w_get_attr_match_end),
        cmocka_unit_test(test_w_get_attr_match_invalid),
        // Tests w_logcollector_get_macos_log_type
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_NULL),
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_empty),
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_ignore_values),
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_activity),
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_log),
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_trace),
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_trace_activity),
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_trace_log_activity),
        cmocka_unit_test(test_w_logcollector_get_macos_log_type_content_log_multiword_invalid),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
