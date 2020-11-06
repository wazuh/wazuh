
/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>

#include "../../analysisd/rules.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"


extern bool w_check_attr_negate(xml_node *node, int rule_id);
extern bool w_check_attr_field_name(xml_node * node, FieldInfo ** field, int rule_id);
extern w_exp_type_t w_check_attr_type(xml_node *node, w_exp_type_t default_type, int rule_id);

/* setup/teardown */

/* wraps */

/* tests */

// w_check_attr_negate

void w_check_attr_negate_non_attr(void **state)
{
    xml_node node = {0, NULL, NULL, NULL, NULL};
    int rule_id = 1234;
    bool ret_val;

    ret_val = w_check_attr_negate(&node, rule_id);

    assert_false(ret_val);
}

void w_check_attr_negate_attr_to_yes(void **state)
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
    os_strdup("yes", node.values[0]);

    ret_val = w_check_attr_negate(&node, rule_id);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_true(ret_val);
}

void w_check_attr_negate_attr_to_no(void **state)
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
    os_strdup("no", node.values[0]);

    ret_val = w_check_attr_negate(&node, rule_id);

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

    expect_string(__wrap__mwarn, formatted_msg, "(7600): Invalid value 'hello' for attribute 'negate' in rule 1234");

    ret_val = w_check_attr_negate(&node, rule_id);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_false(ret_val);
}

void w_check_attr_negate_attr_non_negate_attr(void **state)
{
    xml_node node;
    int rule_id = 1234;
    bool ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("hello", node.attributes[0]);
    node.attributes[1] = NULL;

    ret_val = w_check_attr_negate(&node, rule_id);

    os_free(node.attributes[0]);
    os_free(node.attributes);

    assert_false(ret_val);
}

// w_check_attr_field_name

void w_check_attr_field_name_non_attr(void **state)
{
    xml_node node = {0, NULL, NULL, NULL, NULL};
    int rule_id = 1234;
    FieldInfo *field = NULL;
    bool ret_val;

    ret_val = w_check_attr_field_name(&node, &field, rule_id);

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

    expect_string(__wrap__merror, formatted_msg, "Failure to read rule 1234. Field 'action' is static.");

    ret_val = w_check_attr_field_name(&node, &field, rule_id);

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

    expect_string(__wrap__merror, formatted_msg, "Failure to read rule 1234. No such attribute 'name' for field.");

    ret_val = w_check_attr_field_name(&node, &field, rule_id);

    assert_false(ret_val);

    os_free(node.attributes[0]);
    os_free(node.attributes);
}

void w_check_attr_field_name_dynamic_field(void **state)
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
    os_strdup("dynamicField", node.values[0]);

    ret_val = w_check_attr_field_name(&node, &field, rule_id);

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

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSMATCH, rule_id);

    assert_int_equal(ret_val, EXP_TYPE_OSMATCH);
}

void w_check_attr_type_non_type_attr(void **state)
{
    xml_node node;
    int rule_id = 1234;
    w_exp_type_t ret_val;

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("non_type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("osmatch", node.values[0]);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSREGEX, rule_id);

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

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("osmatch", node.values[0]);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSREGEX, rule_id);

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

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("osregex", node.values[0]);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSMATCH, rule_id);

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

    node.key = 0;
    node.element = NULL;
    os_calloc(2, sizeof(char*), node.attributes);
    os_strdup("type", node.attributes[0]);
    node.attributes[1] = NULL;
    os_calloc(1, sizeof(char*), node.values);
    os_strdup("pcre2", node.values[0]);

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSMATCH, rule_id);

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

    expect_string(__wrap__mwarn, formatted_msg, "(7600): Invalid value 'hello' for attribute 'type' in rule 1234");

    ret_val = w_check_attr_type(&node, EXP_TYPE_OSMATCH, rule_id);

    os_free(node.attributes[0]);
    os_free(node.values[0]);
    os_free(node.attributes);
    os_free(node.values);

    assert_int_equal(ret_val, EXP_TYPE_OSMATCH);
}

int main(void)
{
    const struct CMUnitTest tests[] = {

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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
