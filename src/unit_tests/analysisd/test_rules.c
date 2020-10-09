
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


extern int w_check_attr_negate(xml_node *node, int rule_id);


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
    os_calloc(1, sizeof(char*), node.attributes);
    os_strdup("negate", node.attributes[0]);
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
    os_calloc(1, sizeof(char*), node.attributes);
    os_strdup("negate", node.attributes[0]);
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
    os_calloc(1, sizeof(char*), node.attributes);
    os_strdup("negate", node.attributes[0]);
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


int main(void)
{
    const struct CMUnitTest tests[] = {

        // Test w_check_attr_negate
        cmocka_unit_test(w_check_attr_negate_non_attr),
        cmocka_unit_test(w_check_attr_negate_attr_to_yes),
        cmocka_unit_test(w_check_attr_negate_attr_to_no),
        cmocka_unit_test(w_check_attr_negate_attr_unknow_val),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
