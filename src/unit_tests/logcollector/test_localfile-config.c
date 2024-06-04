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
#include "../wrappers/externals/pcre2/pcre2_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"

const char * multiline_attr_match_str(w_multiline_match_type_t match_type);
const char * multiline_attr_replace_str(w_multiline_replace_type_t replace_type);
unsigned int w_get_attr_timeout(xml_node * node);
w_multiline_replace_type_t w_get_attr_replace(xml_node * node);
w_multiline_match_type_t w_get_attr_match(xml_node * node);
int w_logcollector_get_macos_log_type(const char * content);

// Journal
#define VALID_PCRE2_REGEX "valid regex \\w+"
#define INVALID_PCRE2_REGEX "invalid regex [a \\w+{-1"

_w_journal_filter_unit_t * create_unit_filter(const char * field, char * expression, bool ignore_if_missing);
void free_unit_filter(_w_journal_filter_unit_t * unit);
cJSON * unit_filter_as_json(_w_journal_filter_unit_t * unit);
cJSON * filter_as_json(w_journal_filter_t * filter);

/* setup/teardown */
static int setup_group(void **state) {
    test_mode = 1;
    w_test_pcre2_wrappers(false);
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    w_test_pcre2_wrappers(true);
    return 0;
}

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

    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, NULL);
    retval = w_get_attr_timeout(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_empty(void ** state) {

    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value '' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_timeout(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_not_number(void ** state) {

    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "test");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value 'test' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_timeout(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_mixed(void ** state) {

    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "11test11");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value '11test11' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_timeout(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_zero(void ** state) {

    unsigned int expect_retval = MULTI_LINE_REGEX_TIMEOUT;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "0");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value '0' for attribute 'timeout' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_timeout(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_out_range(void ** state) {

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

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_timeout_out_ok(void ** state) {

    unsigned int expect_retval = 30;
    unsigned int retval;

    will_return(__wrap_w_get_attr_val_by_name, "30");
    retval = w_get_attr_timeout(NULL);

    assert_int_equal(expect_retval, retval);
}

// Test w_get_attr_replace
void test_w_get_attr_replace_missing(void ** state) {

    w_multiline_replace_type_t expect_retval = ML_REPLACE_NO_REPLACE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, NULL);
    retval = w_get_attr_replace(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_no_replace(void ** state) {

    w_multiline_replace_type_t expect_retval = ML_REPLACE_NO_REPLACE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "no-replace");
    retval = w_get_attr_replace(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_ws(void ** state) {

    w_multiline_replace_type_t expect_retval = ML_REPLACE_WSPACE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "wspace");
    retval = w_get_attr_replace(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_tab(void ** state) {

    w_multiline_replace_type_t expect_retval = ML_REPLACE_TAB;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "tab");
    retval = w_get_attr_replace(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_none(void ** state) {

    w_multiline_replace_type_t expect_retval = ML_REPLACE_NONE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "none");
    retval = w_get_attr_replace(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_replace_invalid(void ** state) {

    w_multiline_replace_type_t expect_retval = ML_REPLACE_NO_REPLACE;
    w_multiline_replace_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "invalid_attr");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value 'invalid_attr' for attribute 'replace' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_replace(NULL);

    assert_int_equal(expect_retval, retval);
}

/* w_get_attr_match */
void test_w_get_attr_match_invalid(void ** state) {

    w_multiline_match_type_t expect_retval = ML_MATCH_START;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "invalid_attr");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(8000): Invalid value 'invalid_attr' for attribute 'match' in "
                  "'multiline_regex' option. Default value will be used.");
    retval = w_get_attr_match(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_match_missing(void ** state) {

    w_multiline_match_type_t expect_retval = ML_MATCH_START;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, NULL);
    retval = w_get_attr_match(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_match_start(void ** state) {

    w_multiline_match_type_t expect_retval = ML_MATCH_START;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "start");
    retval = w_get_attr_match(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_match_all(void ** state) {

    w_multiline_match_type_t expect_retval = ML_MATCH_ALL;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "all");
    retval = w_get_attr_match(NULL);

    assert_int_equal(expect_retval, retval);
}

void test_w_get_attr_match_end(void ** state) {

    w_multiline_match_type_t expect_retval = ML_MATCH_END;
    w_multiline_match_type_t retval;

    will_return(__wrap_w_get_attr_val_by_name, "end");
    retval = w_get_attr_match(NULL);

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

/* init_w_journal_log_config_t */
void test_init_w_journal_log_config_t_ok(void ** state) {
    w_journal_log_config_t * config = NULL;
    bool ret = init_w_journal_log_config_t(&config);
    assert_true(ret);
    assert_non_null(config);
    assert_false(config->disable_filters);
    assert_null(config->filters);
    os_free(config);
}

void test_init_w_journal_log_config_t_fail(void ** state) {
    w_journal_log_config_t * config = (w_journal_log_config_t *) 0x1;
    bool ret = init_w_journal_log_config_t(&config);
    assert_false(ret);
    assert_non_null(config);
}

/* w_journal_log_config_free */
void test_w_journal_log_config_free_null(void ** state) {
    w_journal_log_config_t * config = NULL;

    w_journal_log_config_free(NULL);
    w_journal_log_config_free(&config);
}

void test_w_journal_log_config_free_ok(void ** state) {

    w_journal_log_config_t * config = NULL;

    assert_true(init_w_journal_log_config_t(&config));
    w_journal_log_config_free(&config);
}

/* free_unit_filter */
void test_free_unit_filter_null(void ** state) {
    _w_journal_filter_unit_t * ufilter = NULL;
    free_unit_filter(ufilter);
}

void test_free_unit_filter_ok(void ** state) {
    _w_journal_filter_unit_t * ufilter = calloc(1, sizeof(_w_journal_filter_unit_t));
    ufilter->field = strdup("test");
    w_calloc_expression_t(&ufilter->exp, EXP_TYPE_PCRE2);
    w_expression_compile(ufilter->exp, VALID_PCRE2_REGEX, 0);

    free_unit_filter(ufilter);
}

/* create_unit_filter */
void test_create_unit_filter_null_param(void ** state) {

    assert_null(create_unit_filter("field", NULL, false));
    assert_null(create_unit_filter(NULL, VALID_PCRE2_REGEX, false));
}

void test_create_unit_filter_inv_expresion(void ** state) {

    assert_null(create_unit_filter("fied", INVALID_PCRE2_REGEX, false));
}

void test_create_unit_filter_ok(void ** state) {
    _w_journal_filter_unit_t * ufilter = create_unit_filter("fied_test", VALID_PCRE2_REGEX, true);

    assert_non_null(ufilter);
    assert_true(ufilter->ignore_if_missing);
    assert_string_equal(ufilter->exp->pcre2->raw_pattern, VALID_PCRE2_REGEX);
    assert_string_equal(ufilter->field, "fied_test");

    free_unit_filter(ufilter);
}

/* unit_filter_as_json */
void test_unit_filter_as_json_null_params(void ** state) {

    _w_journal_filter_unit_t unit = {.exp = NULL, .field = NULL, .ignore_if_missing = false};

    assert_null(unit_filter_as_json(NULL));

    assert_null(unit_filter_as_json(&unit));

    unit.field = "test field";
    assert_null(unit_filter_as_json(&unit));
}

void test_unit_filter_as_json_ok(void ** state) {

    _w_journal_filter_unit_t unit = {.exp = NULL, .field = "test field", .ignore_if_missing = true};

    w_calloc_expression_t(&unit.exp, EXP_TYPE_PCRE2);
    w_expression_compile(unit.exp, VALID_PCRE2_REGEX, 0);

    will_return(__wrap_cJSON_CreateObject, (void *) 0x1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "field");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test field");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "expression");
    expect_string(__wrap_cJSON_AddStringToObject, string, VALID_PCRE2_REGEX);
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *) 1);

    assert_non_null(unit_filter_as_json(&unit));

    w_free_expression(unit.exp);
}

/* w_journal_filter_add_condition */
void test_w_journal_filter_add_condition_null_params(void ** state) {
    w_journal_filter_t * filters = NULL;
    assert_int_not_equal(0, w_journal_filter_add_condition(&filters, "field", NULL, false));
    assert_int_not_equal(0, w_journal_filter_add_condition(&filters, NULL, VALID_PCRE2_REGEX, false));
    assert_int_not_equal(0, w_journal_filter_add_condition(NULL, "field", VALID_PCRE2_REGEX, false));
}

void test_w_journal_filter_add_condition_bad_exp(void ** state) {
    w_journal_filter_t * filters = NULL;
    assert_int_not_equal(0, w_journal_filter_add_condition(&filters, "field", INVALID_PCRE2_REGEX, false));
}

void test_w_journal_filter_add_condition_ok_first_cond(void ** state) {
    w_journal_filter_t * filters = NULL;

    assert_int_equal(0, w_journal_filter_add_condition(&filters, "field", VALID_PCRE2_REGEX, false));

    assert_non_null(filters);
    assert_int_equal(1, filters->units_size);
    assert_non_null(filters->units);
    assert_non_null(filters->units[0]);
    assert_non_null(filters->units[0]->exp->pcre2->code);
    assert_null(filters->units[1]);

    w_journal_filter_free(filters); // test w_journal_filter_free
}

void test_w_journal_filter_add_condition_ok_other_cond(void ** state) {

    w_journal_filter_t * filters = NULL;

    assert_int_equal(0, w_journal_filter_add_condition(&filters, "field", VALID_PCRE2_REGEX, false));

    assert_non_null(filters);
    assert_int_equal(1, filters->units_size);
    assert_non_null(filters->units);
    assert_non_null(filters->units[0]);
    assert_non_null(filters->units[0]->exp->pcre2->code);
    assert_int_equal(filters->units[0]->ignore_if_missing, false);
    assert_null(filters->units[1]);

    // Add second filter
    assert_int_equal(0, w_journal_filter_add_condition(&filters, "field2", VALID_PCRE2_REGEX, true));

    assert_int_equal(2, filters->units_size);
    assert_non_null(filters->units);
    assert_non_null(filters->units[0]);
    assert_non_null(filters->units[0]->exp->pcre2->code);
    assert_string_equal(filters->units[0]->field, "field");
    assert_non_null(filters->units[1]);
    assert_non_null(filters->units[1]->exp->pcre2->code);
    assert_int_equal(filters->units[1]->ignore_if_missing, true);
    assert_string_equal(filters->units[1]->field, "field2");

    assert_null(filters->units[2]);

    w_journal_filter_free(filters); // test w_journal_filter_free
}

/* w_journal_filter_free */
void test_w_journal_filter_free_null(void ** state) { w_journal_filter_free(NULL); }

/* Test filter_as_json */
void test_filter_as_json_null_params(void ** state) {

    w_journal_filter_t filter = {0};

    assert_null(filter_as_json(NULL));
    assert_null(filter_as_json(&filter));
}

void test_filter_as_json_fail_array(void ** state) {

    w_journal_filter_t * filter = NULL;

    assert_int_equal(0, w_journal_filter_add_condition(&filter, "test field", VALID_PCRE2_REGEX, false));

    will_return(__wrap_cJSON_CreateArray, (cJSON *) NULL);

    assert_null(filter_as_json(filter));

    w_journal_filter_free(filter);
}

void test_filter_as_json_one_unit(void ** state) {

    w_journal_filter_t * filter = NULL;

    assert_int_equal(0, w_journal_filter_add_condition(&filter, "test field", VALID_PCRE2_REGEX, false));

    will_return(__wrap_cJSON_CreateArray, (cJSON *) 0x1);

    // start: unit filter as json
    will_return(__wrap_cJSON_CreateObject, (void *) 0x1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "field");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test field");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "expression");
    expect_string(__wrap_cJSON_AddStringToObject, string, VALID_PCRE2_REGEX);
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *) 1);
    // end: unit filter as json

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    assert_non_null(filter_as_json(filter));

    w_journal_filter_free(filter);
}

/* w_journal_add_filter_to_list */
void test_w_journal_add_filter_to_list_null_params(void ** state) {

    w_journal_filters_list_t list = NULL;
    w_journal_filter_t filter;
    assert_false(w_journal_add_filter_to_list(&list, NULL));
    assert_false(w_journal_add_filter_to_list(NULL, &filter));
}

void test_w_journal_add_filter_to_list_new_list(void ** state) {

    w_journal_filters_list_t list = NULL;
    w_journal_filter_t filter = {0};

    assert_true(w_journal_add_filter_to_list(&list, &filter));

    assert_non_null(list);
    assert_non_null(list[0]);
    assert_ptr_equal(list[0], &filter);
    assert_null(list[1]);

    os_free(list);
}

void test_w_journal_add_filter_to_list_exist_list(void ** state) {

    w_journal_filters_list_t list = NULL;
    w_journal_filter_t filter = {0};

    assert_true(w_journal_add_filter_to_list(&list, &filter));

    assert_non_null(list);
    assert_non_null(list[0]);
    assert_ptr_equal(list[0], &filter);
    assert_null(list[1]);

    // Add second item
    w_journal_filter_t filter2 = {0};
    assert_true(w_journal_add_filter_to_list(&list, &filter2));

    assert_non_null(list[0]);
    assert_ptr_equal(list[0], &filter);
    assert_non_null(list[1]);
    assert_ptr_equal(list[1], &filter2);
    assert_null(list[2]);

    os_free(list);
}

// Test w_journal_filter_list_as_json
void test_w_journal_filter_list_as_json_null_params(void ** state) { assert_null(w_journal_filter_list_as_json(NULL)); }

void test_w_journal_filter_list_as_json_fail_array(void ** state) {

    w_journal_filters_list_t list = NULL;

    // Prepare the filter
    w_journal_filter_t * filter = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&filter, "test field", VALID_PCRE2_REGEX, false));
    // Add filter to the list
    assert_true(w_journal_add_filter_to_list(&list, filter));

    // Print the list
    // start: Print as json
    will_return(__wrap_cJSON_CreateArray, (cJSON *) NULL);
    assert_null(w_journal_filter_list_as_json(list));

    w_journal_filters_list_free(list); // Test w_journal_filters_list_free
}

void test_w_journal_filter_list_as_json_success(void ** state) {

    w_journal_filters_list_t list = NULL;

    // Prepare the filter
    w_journal_filter_t * filter = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&filter, "test field", VALID_PCRE2_REGEX, false));
    // Add filter to the list
    assert_true(w_journal_add_filter_to_list(&list, filter));

    // Print the list

    // start: Print as json
    will_return(__wrap_cJSON_CreateArray, (cJSON *) 0x1);

    // - filter_as_json
    will_return(__wrap_cJSON_CreateArray, (cJSON *) 0x1);
    // - - unit_filter_as_json
    will_return(__wrap_cJSON_CreateObject, (void *) 0x1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "field");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test field");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "expression");
    expect_string(__wrap_cJSON_AddStringToObject, string, VALID_PCRE2_REGEX);
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);
    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *) 1);
    // - end: filter_as_json
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    assert_non_null(w_journal_filter_list_as_json(list));

    w_journal_filters_list_free(list); // Test w_journal_filters_list_free
}

// ------------------------------------------------
/* journald_add_condition_to_filter */
void test_journald_add_condition_to_filter_invalid_params(void ** state) {

    assert_false(journald_add_condition_to_filter(NULL, NULL));
    assert_false(journald_add_condition_to_filter(NULL, (w_journal_filter_t **) 0x1));
    assert_false(journald_add_condition_to_filter((xml_node *) 0x1, NULL));
}

void test_journald_add_condition_to_filter_non_field(void ** state) {

    xml_node node = {0};
    char * node_content = "regex xml content";
    node.content = node_content;

    w_journal_filter_t * filter = NULL;

    // Null field
    will_return(__wrap_w_get_attr_val_by_name, NULL);
    expect_string(__wrap__mwarn, formatted_msg, "(8019): The field for the journal filter cannot be empty.");

    assert_false(journald_add_condition_to_filter(&node, &filter));
}

void test_journald_add_condition_to_filter_empty_field(void ** state) {

    xml_node node = {0};
    char * node_content = "regex xml content";
    node.content = node_content;

    w_journal_filter_t * filter = NULL;

    // Null field
    will_return(__wrap_w_get_attr_val_by_name, "");
    expect_string(__wrap__mwarn, formatted_msg, "(8019): The field for the journal filter cannot be empty.");

    assert_false(journald_add_condition_to_filter(&node, &filter));
}

void test_journald_add_condition_to_filter_empty_regex(void ** state) {

    xml_node node = {0};
    char * node_content = "";
    node.content = node_content;

    w_journal_filter_t * filter = NULL;

    // Null field
    will_return(__wrap_w_get_attr_val_by_name, "field");
    expect_string(__wrap__mwarn, formatted_msg, "(8020): The expression for the journal filter cannot be empty.");

    assert_false(journald_add_condition_to_filter(&node, &filter));
}

void test_journald_add_condition_to_filter_null_regex(void ** state) {

    xml_node node = {0};
    node.content = NULL;

    w_journal_filter_t * filter = NULL;

    // Null field
    will_return(__wrap_w_get_attr_val_by_name, "field");
    expect_string(__wrap__mwarn, formatted_msg, "(8020): The expression for the journal filter cannot be empty.");

    assert_false(journald_add_condition_to_filter(&node, &filter));
}

void test_journald_add_condition_to_filter_ingore_no(void ** state) {

    xml_node node = {0};
    node.content = VALID_PCRE2_REGEX;

    w_journal_filter_t * filter = NULL;

    will_return(__wrap_w_get_attr_val_by_name, "field");
    will_return(__wrap_w_get_attr_val_by_name, "no");

    // w_journal_filter_add_condition ok
    assert_true(journald_add_condition_to_filter(&node, &filter));

    assert_non_null(filter);
    assert_int_equal(filter->units_size, 1);
    assert_non_null(filter->units);
    assert_non_null(filter->units[0]);
    assert_string_equal(filter->units[0]->exp->pcre2->raw_pattern, VALID_PCRE2_REGEX);
    assert_string_equal(filter->units[0]->field, "field");
    assert_false(filter->units[0]->ignore_if_missing);
    assert_null(filter->units[1]);

    w_journal_filter_free(filter);
}

void test_journald_add_condition_to_filter_ingore_missing(void ** state) {

    xml_node node = {0};
    node.content = VALID_PCRE2_REGEX;

    w_journal_filter_t * filter = NULL;

    will_return(__wrap_w_get_attr_val_by_name, "field");
    will_return(__wrap_w_get_attr_val_by_name, NULL);

    // w_journal_filter_add_condition ok
    assert_true(journald_add_condition_to_filter(&node, &filter));

    assert_non_null(filter);
    assert_int_equal(filter->units_size, 1);
    assert_non_null(filter->units);
    assert_non_null(filter->units[0]);
    assert_string_equal(filter->units[0]->exp->pcre2->raw_pattern, VALID_PCRE2_REGEX);
    assert_string_equal(filter->units[0]->field, "field");
    assert_false(filter->units[0]->ignore_if_missing);
    assert_null(filter->units[1]);

    w_journal_filter_free(filter);
}

void test_journald_add_condition_to_filter_ingore_wrong(void ** state) {

    xml_node node = {0};
    node.content = VALID_PCRE2_REGEX;

    w_journal_filter_t * filter = NULL;

    will_return(__wrap_w_get_attr_val_by_name, "field");
    will_return(__wrap_w_get_attr_val_by_name, "bad attribute");
    expect_string(__wrap__mwarn,
                  formatted_msg,
                  "(8000): Invalid value 'bad attribute' for attribute 'ignore_if_missing' in 'journal' option. "
                  "Default value will be used.");

    // w_journal_filter_add_condition ok
    assert_true(journald_add_condition_to_filter(&node, &filter));

    assert_non_null(filter);
    assert_int_equal(filter->units_size, 1);
    assert_non_null(filter->units);
    assert_non_null(filter->units[0]);
    assert_string_equal(filter->units[0]->exp->pcre2->raw_pattern, VALID_PCRE2_REGEX);
    assert_string_equal(filter->units[0]->field, "field");
    assert_false(filter->units[0]->ignore_if_missing);
    assert_null(filter->units[1]);

    w_journal_filter_free(filter);
}

void test_journald_add_condition_to_filter_ingore_yes(void ** state) {

    xml_node node = {0};
    node.content = VALID_PCRE2_REGEX;

    w_journal_filter_t * filter = NULL;

    will_return(__wrap_w_get_attr_val_by_name, "field");
    will_return(__wrap_w_get_attr_val_by_name, "yes");

    // w_journal_filter_add_condition ok
    assert_true(journald_add_condition_to_filter(&node, &filter));

    assert_non_null(filter);
    assert_int_equal(filter->units_size, 1);
    assert_non_null(filter->units);
    assert_non_null(filter->units[0]);
    assert_string_equal(filter->units[0]->exp->pcre2->raw_pattern, VALID_PCRE2_REGEX);
    assert_string_equal(filter->units[0]->field, "field");
    assert_true(filter->units[0]->ignore_if_missing);
    assert_null(filter->units[1]);

    w_journal_filter_free(filter);
}

void test_journald_add_condition_to_filter_fail_regex(void ** state) {

    xml_node node = {0};
    node.content = INVALID_PCRE2_REGEX;

    w_journal_filter_t * filter = NULL;

    will_return(__wrap_w_get_attr_val_by_name, "field");
    will_return(__wrap_w_get_attr_val_by_name, "no");

    expect_string(
        __wrap__mwarn,
        formatted_msg,
        "(8021): Error compiling the PCRE2 expression 'invalid regex [a \\w+{-1' for field 'field' in journal filter.");
    // w_journal_filter_add_condition fail
    assert_false(journald_add_condition_to_filter(&node, &filter));
}

/* w_multiline_log_config_free */
void test_w_multiline_log_config_free_null(void **state)
{
    w_multiline_log_config_free(NULL);

    w_multiline_config_t *config = NULL;
    w_multiline_log_config_free(&config);
}

void test_w_multiline_log_config_free_success(void ** state) {
    w_multiline_config_t * config = NULL;
    os_calloc(1, sizeof(w_multiline_config_t), config);

    // Set a valid config

    // Regex config
    w_calloc_expression_t(&config->regex, EXP_TYPE_PCRE2);
    assert_true(w_expression_compile(config->regex, "valid regex .*", 0));

    // collector config
    config->match_type = ML_MATCH_START;
    config->replace_type = ML_REPLACE_NO_REPLACE;
    config->timeout = 10;

    // Simulate non-empty ctxt
    os_calloc(1, sizeof(w_multiline_ctxt_t), config->ctxt);
    os_calloc(100, sizeof(char), config->ctxt->buffer);

    w_multiline_log_config_free(&config);
    assert_null(config);
}

// Test w_multiline_log_config_clone
void test_w_multiline_log_config_clone_null(void ** state) {
    assert_null(w_multiline_log_config_clone(NULL));
}

void test_w_multiline_log_config_clone_success(void ** state) {


    w_multiline_config_t * config = NULL;
    os_calloc(1, sizeof(w_multiline_config_t), config);

    // Set a valid config
    w_calloc_expression_t(&config->regex, EXP_TYPE_PCRE2);
    assert_true(w_expression_compile(config->regex, "valid regex .*", 0));

    // collector config
    config->match_type = ML_MATCH_END;
    config->replace_type = ML_REPLACE_NONE;
    config->timeout = 10;

    // Simulate non-empty ctxt
    os_calloc(1, sizeof(w_multiline_ctxt_t), config->ctxt);
    os_calloc(100, sizeof(char), config->ctxt->buffer);


    // Test clone
    w_multiline_config_t * cloned_config = w_multiline_log_config_clone(config);
    w_multiline_log_config_free(&config);

    // Checks
    assert_non_null(cloned_config);
    assert_non_null(cloned_config->regex);
    assert_string_equal(w_expression_get_regex_pattern(cloned_config->regex), "valid regex .*");

    assert_int_equal(cloned_config->match_type, ML_MATCH_END);
    assert_int_equal(cloned_config->replace_type, ML_REPLACE_NONE);
    assert_int_equal(cloned_config->timeout, 10);

    assert_null(cloned_config->ctxt); // Should be a empty context

    w_multiline_log_config_free(&cloned_config);

}

/* main */

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
        // Test init_w_journal_log_config_t
        cmocka_unit_test(test_init_w_journal_log_config_t_fail),
        cmocka_unit_test(test_init_w_journal_log_config_t_ok),
        // Test w_journal_log_config_free
        cmocka_unit_test(test_w_journal_log_config_free_null),
        cmocka_unit_test(test_w_journal_log_config_free_ok),
        // Test free_unit_filter
        cmocka_unit_test(test_free_unit_filter_null),
        cmocka_unit_test(test_free_unit_filter_ok),
        // Test create_unit_filter
        cmocka_unit_test(test_create_unit_filter_null_param),
        cmocka_unit_test(test_create_unit_filter_inv_expresion),
        cmocka_unit_test(test_create_unit_filter_ok),
        // Test unit_filter_as_json
        cmocka_unit_test(test_unit_filter_as_json_null_params),
        cmocka_unit_test(test_unit_filter_as_json_ok),
        // Test w_journal_filter_add_condition
        cmocka_unit_test(test_w_journal_filter_add_condition_null_params),
        cmocka_unit_test(test_w_journal_filter_add_condition_bad_exp),
        cmocka_unit_test(test_w_journal_filter_add_condition_ok_first_cond),
        cmocka_unit_test(test_w_journal_filter_add_condition_ok_other_cond),
        // Test w_journal_filter_add_condition w_journal_filter_free
        cmocka_unit_test(test_w_journal_filter_free_null),
        // Test filter_as_json
        cmocka_unit_test(test_filter_as_json_null_params),
        cmocka_unit_test(test_filter_as_json_fail_array),
        cmocka_unit_test(test_filter_as_json_one_unit),
        // Test w_journal_add_filter_to_list
        cmocka_unit_test(test_w_journal_add_filter_to_list_null_params),
        cmocka_unit_test(test_w_journal_add_filter_to_list_new_list),
        cmocka_unit_test(test_w_journal_add_filter_to_list_exist_list),
        // Test w_journal_filter_list_as_json
        cmocka_unit_test(test_w_journal_filter_list_as_json_null_params),
        cmocka_unit_test(test_w_journal_filter_list_as_json_fail_array),
        cmocka_unit_test(test_w_journal_filter_list_as_json_success),
        // Test journald_add_condition_to_filter
        cmocka_unit_test(test_journald_add_condition_to_filter_invalid_params),
        cmocka_unit_test(test_journald_add_condition_to_filter_non_field),
        cmocka_unit_test(test_journald_add_condition_to_filter_empty_field),
        cmocka_unit_test(test_journald_add_condition_to_filter_empty_regex),
        cmocka_unit_test(test_journald_add_condition_to_filter_null_regex),
        cmocka_unit_test(test_journald_add_condition_to_filter_ingore_no),
        cmocka_unit_test(test_journald_add_condition_to_filter_ingore_missing),
        cmocka_unit_test(test_journald_add_condition_to_filter_ingore_wrong),
        cmocka_unit_test(test_journald_add_condition_to_filter_ingore_yes),
        cmocka_unit_test(test_journald_add_condition_to_filter_fail_regex),
        // Test w_multiline_log_config_free
        cmocka_unit_test(test_w_multiline_log_config_free_null),
        cmocka_unit_test(test_w_multiline_log_config_free_success),
        // Test w_multiline_log_config_clone
        cmocka_unit_test(test_w_multiline_log_config_clone_null),
        cmocka_unit_test(test_w_multiline_log_config_clone_success),

    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
    //return cmocka_run_group_tests(tests, NULL, NULL);
}
