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

#include "../../analysisd/rules.h"
#include "../../analysisd/config.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/analysisd.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_xml/os_xml_wrappers.h"

char *loadmemory(char *at, const char *str, OSList* log_msg);
int get_info_attributes(char **attributes, char **values, OSList* log_msg);
bool w_check_attr_negate(xml_node *node, int rule_id, OSList* log_msg);
bool w_check_attr_field_name(xml_node * node, FieldInfo ** field, int rule_id, OSList* log_msg);
w_exp_type_t w_check_attr_type(xml_node *node, w_exp_type_t default_type, int rule_id, OSList* log_msg);
void w_free_rules_tmp_params(rules_tmp_params_t * rule_tmp_params);

/* setup/teardown */

/* wraps */
void __wrap__os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                    const char * file, char * msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(level);
    check_expected_ptr(list);
    check_expected(formatted_msg);
}

/* tests */
// loadmemory
void test_loadmemory_null_append_ok(void ** state)
{
    char * at = NULL;
    char * str;

    const size_t len = 1000;
    char * expect_retval;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), expect_retval);
    memset(expect_retval, (int) '-', len - 1);
    expect_retval[len-1] = '\0';

    retval = loadmemory(at,str, NULL);

    assert_string_equal(retval, expect_retval);

    os_free(str);
    os_free(retval);
    os_free(expect_retval);

}

void test_loadmemory_null_append_oversize(void ** state)
{
    char * at = NULL;
    char * str;
    OSList list_msg = {0};

    const size_t len = 2049;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    char expect_msg[OS_SIZE_4096];

    snprintf(expect_msg, OS_SIZE_4096, "(1104): Maximum string size reached for: %s.", str);
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expect_msg);

    retval = loadmemory(at,str, &list_msg);

    assert_null(retval);

    os_free(str);

}

void test_loadmemory_append_oversize(void ** state)
{
    char * at = NULL;
    char * str = NULL;
    OSList list_msg = {0};

    const size_t len = 2050;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), at);
    memset(at, (int) '+', len - 1);
    str[len-1] = '\0';

    char expect_msg[OS_SIZE_20480];

    snprintf(expect_msg, OS_SIZE_20480, "(1104): Maximum string size reached for: %s.", str);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expect_msg);

    retval = loadmemory(at,str, &list_msg);

    assert_null(retval);

    os_free(str);
    os_free(at);

}

void test_loadmemory_append_ok(void ** state)
{
    char * at = NULL;
    char * str = NULL;
    OSList list_msg = {0};

    const size_t len = 512;
    char * retval;
    char * expect_retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), at);
    memset(at, (int) '+', len - 1);
    at[len-1] = '\0';

    os_calloc(len * 2, sizeof(char), expect_retval);
    strncat(expect_retval, at, len * 2);
    strncat(expect_retval, str, len * 2);

    retval = loadmemory(at,str, &list_msg);

    assert_non_null(retval);
    assert_string_equal(retval, expect_retval);

    os_free(str);
    os_free(retval);
    os_free(expect_retval);

}

// get_info_attributes
void test_get_info_attributes_null(void ** state)
{
    OSList log_msg = {0};
    char ** values = NULL;
    char ** attributes = NULL;

    int retval;
    const int expect_retval = 0;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);
}

void test_get_info_attributes_empty(void ** state)
{
    OSList log_msg = {0};
    char ** values = NULL;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = NULL;

    int retval;
    const int expect_retval = 0;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
}

void test_get_info_attributes_without_value(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = NULL;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = -1;

    char excpect_msg[OS_SIZE_2048];
    snprintf(excpect_msg, OS_SIZE_2048, "rules_op: Element info attribute \"%s\" does not have a value", attributes[0]);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, excpect_msg);

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_text(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "text";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = 0;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_link(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "link";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = 1;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_cve(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "cve";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = 2;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_osvdb(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "osvdb";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = 3;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_invalid_value(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "bad_type";
    char * values_k = "test_value";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = -1;

    char excpect_msg[OS_SIZE_2048];
    snprintf(excpect_msg, OS_SIZE_2048, "rules_op: Element info has invalid attribute \"%s\"", attributes[0]);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, excpect_msg);

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_invalid_type(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "bad_value";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = -1;

    char excpect_msg[OS_SIZE_2048];
    snprintf(excpect_msg, OS_SIZE_2048, "rules_op: Element info attribute \"%s\""
                            " has invalid value \"%s\"", attributes[0], values[0]);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, excpect_msg);

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

// w_check_attr_negate

void w_check_attr_negate_non_attr(void **state)
{
    OSList log_msg = {0};
    xml_node node = {0, NULL, NULL, NULL, NULL};
    int rule_id = 1234;
    bool ret_val;

    ret_val = w_check_attr_negate(&node, rule_id, &log_msg);

    assert_false(ret_val);
}

void w_check_attr_negate_attr_to_yes(void **state)
{
    OSList log_msg = {0};
    xml_node node;
    int rule_id = 1234;
    bool ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("negate", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("yes", node.values[0]);

    ret_val = w_check_attr_negate(&node, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_true(ret_val);
}

void w_check_attr_negate_attr_to_no(void **state)
{
    OSList log_msg = {0};
    xml_node node;
    int rule_id = 1234;
    bool ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("negate", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("no", node.values[0]);

    ret_val = w_check_attr_negate(&node, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_false(ret_val);
}

void w_check_attr_negate_attr_unknow_val(void **state)
{
    xml_node node;
    int rule_id = 1234;
    bool ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("negate", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("hello", node.values[0]);

    OSList log_msg = {0};
    char expected_msg[OS_SIZE_2048];
    snprintf(expected_msg, OS_SIZE_2048, "(7600): Invalid value 'hello' for attribute 'negate' in rule 1234.");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expected_msg);

    ret_val = w_check_attr_negate(&node, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_false(ret_val);
}

void w_check_attr_negate_attr_non_negate_attr(void **state)
{
    OSList log_msg = {0};
    xml_node node;
    int rule_id = 1234;
    bool ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("hello", node.attributes[0]);
    node.attributes[1] = NULL;

    ret_val = w_check_attr_negate(&node, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.attributes);

    assert_false(ret_val);
}

// w_check_attr_field_name

void w_check_attr_field_name_non_attr(void **state)
{
    OSList log_msg = {0};
    xml_node node = {0, NULL, NULL, NULL, NULL};
    int rule_id = 1234;
    FieldInfo *field = NULL;
    bool ret_val;

    ret_val = w_check_attr_field_name(&node, &field, rule_id, &log_msg);

    assert_false(ret_val);
}

void w_check_attr_field_name_static_field(void **state)
{
    xml_node node;
    int rule_id = 1234;
    FieldInfo *field = NULL;
    bool ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("name", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("action", node.values[0]);

    OSList log_msg = {0};
    char expected_msg[OS_SIZE_2048];
    snprintf(expected_msg, OS_SIZE_2048, "Failure to read rule 1234. Field 'action' is static.");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expected_msg);

    ret_val = w_check_attr_field_name(&node, &field, rule_id, &log_msg);

    assert_false(ret_val);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);
}

void w_check_attr_field_name_non_name_attr(void **state)
{
    xml_node node;
    int rule_id = 1234;
    FieldInfo *field = NULL;
    bool ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("hello", node.attributes[0]);
    node.attributes[1] = NULL;

    OSList log_msg = {0};
    char expected_msg[OS_SIZE_2048];
    snprintf(expected_msg, OS_SIZE_2048, "Failure to read rule 1234. No such attribute 'name' for field.");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expected_msg);

    ret_val = w_check_attr_field_name(&node, &field, rule_id, &log_msg);

    assert_false(ret_val);

    os_free(node.attributes[0]);
    os_free(node.attributes);
}

void w_check_attr_field_name_dynamic_field(void **state)
{
    OSList log_msg = {0};
    xml_node node;
    int rule_id = 1234;
    FieldInfo *field = NULL;
    bool ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("name", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("dynamicField", node.values[0]);

    ret_val = w_check_attr_field_name(&node, &field, rule_id, &log_msg);

    assert_true(ret_val);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);
    os_free(field->name);
    os_free(field);
}

// w_check_attr_type

void w_check_attr_type_non_attr(void **state)
{
    xml_node node = {0, NULL, NULL, NULL, NULL};
    int rule_id = 1234;
    w_exp_type_t ret_val;
    OSList log_msg = {0};

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSMATCH, rule_id, &log_msg);

    assert_int_equal(ret_val, EXP_TYPE_OSMATCH);
}

void w_check_attr_type_non_type_attr(void **state)
{
    xml_node node;
    int rule_id = 1234;
    w_exp_type_t ret_val;
    OSList log_msg = {0};

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("non_type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("osmatch", node.values[0]);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSREGEX, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_int_equal(ret_val, EXP_TYPE_OSREGEX);
}

void w_check_attr_type_attr_to_osmatch(void **state)
{
    xml_node node;
    int rule_id = 1234;
    w_exp_type_t ret_val;
    OSList log_msg = {0};

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("osmatch", node.values[0]);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSREGEX, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_int_equal(ret_val, EXP_TYPE_OSMATCH);
}

void w_check_attr_type_attr_to_osregex(void **state)
{
    xml_node node;
    int rule_id = 1234;
    w_exp_type_t ret_val;
    OSList log_msg = {0};

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("osregex", node.values[0]);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSMATCH, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_int_equal(ret_val, EXP_TYPE_OSREGEX);
}

void w_check_attr_type_attr_to_pcre2(void **state)
{
    xml_node node;
    int rule_id = 1234;
    w_exp_type_t ret_val;
    OSList log_msg = {0};

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("pcre2", node.values[0]);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSMATCH, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_int_equal(ret_val, EXP_TYPE_PCRE2);
}

void w_check_attr_type_attr_unknow_val(void **state)
{
    xml_node node;
    int rule_id = 1234;
    w_exp_type_t ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("hello", node.values[0]);

    OSList log_msg = {0};
    char excpect_msg[70] = "(7600): Invalid value 'hello' for attribute 'type' in rule 1234.";

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, excpect_msg);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSMATCH, rule_id, &log_msg);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_int_equal(ret_val, EXP_TYPE_OSMATCH);
}

// Test w_free_rules_tmp_params

void w_free_rules_tmp_params_all(void ** state){

    rules_tmp_params_t rule_tmp_params = {0};

    rule_tmp_params.regex = strdup("test 123");
    rule_tmp_params.match = strdup("test 123");
    rule_tmp_params.url = strdup("test 123");
    rule_tmp_params.if_matched_regex = strdup("test 123");
    rule_tmp_params.if_matched_group = strdup("test 123");
    rule_tmp_params.user = strdup("test 123");
    rule_tmp_params.id = strdup("test 123");
    rule_tmp_params.srcport = strdup("test 123");
    rule_tmp_params.dstport = strdup("test 123");
    rule_tmp_params.srcgeoip = strdup("test 123");
    rule_tmp_params.dstgeoip = strdup("test 123");
    rule_tmp_params.protocol = strdup("test 123");
    rule_tmp_params.system_name = strdup("test 123");
    rule_tmp_params.status = strdup("test 123");
    rule_tmp_params.hostname = strdup("test 123");
    rule_tmp_params.data = strdup("test 123");
    rule_tmp_params.extra_data = strdup("test 123");
    rule_tmp_params.program_name = strdup("test 123");
    rule_tmp_params.location = strdup("test 123");
    rule_tmp_params.action = strdup("test 123");

    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);

    rule_tmp_params.rule_arr_opt = node;

    expect_function_call(__wrap_OS_ClearNode);

    w_free_rules_tmp_params(&rule_tmp_params);
}

void w_free_rules_tmp_params_only_rule_arr(void ** state){

    rules_tmp_params_t rule_tmp_params = {0};
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);

    rule_tmp_params.rule_arr_opt = node;

    expect_function_call(__wrap_OS_ClearNode);

    w_free_rules_tmp_params(&rule_tmp_params);
}

void w_free_rules_tmp_params_only_params(void ** state){

    rules_tmp_params_t rule_tmp_params = {0};

    rule_tmp_params.regex = strdup("test 123");
    rule_tmp_params.match = strdup("test 123");
    rule_tmp_params.url = strdup("test 123");
    rule_tmp_params.if_matched_regex = strdup("test 123");
    rule_tmp_params.if_matched_group = strdup("test 123");
    rule_tmp_params.user = strdup("test 123");
    rule_tmp_params.id = strdup("test 123");
    rule_tmp_params.srcport = strdup("test 123");
    rule_tmp_params.dstport = strdup("test 123");
    rule_tmp_params.srcgeoip = strdup("test 123");
    rule_tmp_params.dstgeoip = strdup("test 123");
    rule_tmp_params.protocol = strdup("test 123");
    rule_tmp_params.system_name = strdup("test 123");
    rule_tmp_params.status = strdup("test 123");
    rule_tmp_params.hostname = strdup("test 123");
    rule_tmp_params.data = strdup("test 123");
    rule_tmp_params.extra_data = strdup("test 123");
    rule_tmp_params.program_name = strdup("test 123");
    rule_tmp_params.location = strdup("test 123");
    rule_tmp_params.action = strdup("test 123");
    rule_tmp_params.rule_arr_opt = NULL;


    w_free_rules_tmp_params(&rule_tmp_params);
}


void w_free_rules_tmp_params_null(void ** state){

    w_free_rules_tmp_params(NULL);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests _loadmemory
        cmocka_unit_test(test_loadmemory_null_append_ok),
        cmocka_unit_test(test_loadmemory_null_append_oversize),
        cmocka_unit_test(test_loadmemory_append_oversize),
        cmocka_unit_test(test_loadmemory_append_ok),
        // Tests get_info_attributes
        cmocka_unit_test(test_get_info_attributes_null),
        cmocka_unit_test(test_get_info_attributes_empty),
        cmocka_unit_test(test_get_info_attributes_without_value),
        cmocka_unit_test(test_get_info_attributes_text),
        cmocka_unit_test(test_get_info_attributes_link),
        cmocka_unit_test(test_get_info_attributes_cve),
        cmocka_unit_test(test_get_info_attributes_osvdb),
        cmocka_unit_test(test_get_info_attributes_invalid_value),
        cmocka_unit_test(test_get_info_attributes_invalid_type),
        // Test w_check_attr_negate
        cmocka_unit_test(w_check_attr_negate_non_attr),
        cmocka_unit_test(w_check_attr_negate_attr_to_yes),
        cmocka_unit_test(w_check_attr_negate_attr_to_no),
        cmocka_unit_test(w_check_attr_negate_attr_unknow_val),
        cmocka_unit_test(w_check_attr_negate_attr_non_negate_attr),
        // Test w_check_attr_field_name
        cmocka_unit_test(w_check_attr_field_name_non_attr),
        cmocka_unit_test(w_check_attr_field_name_static_field),
        cmocka_unit_test(w_check_attr_field_name_non_name_attr),
        cmocka_unit_test(w_check_attr_field_name_dynamic_field),
        // Test w_check_attr_type
        cmocka_unit_test(w_check_attr_type_non_attr),
        cmocka_unit_test(w_check_attr_type_non_type_attr),
        cmocka_unit_test(w_check_attr_type_attr_to_osmatch),
        cmocka_unit_test(w_check_attr_type_attr_to_osregex),
        cmocka_unit_test(w_check_attr_type_attr_to_pcre2),
        cmocka_unit_test(w_check_attr_type_attr_unknow_val),
        // Test w_free_rules_tmp_params
        cmocka_unit_test(w_free_rules_tmp_params_all),
        cmocka_unit_test(w_free_rules_tmp_params_only_rule_arr),
        cmocka_unit_test(w_free_rules_tmp_params_only_params),
        cmocka_unit_test(w_free_rules_tmp_params_null),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
