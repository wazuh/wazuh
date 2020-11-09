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

#ifndef ARGV0
#define ARGV0 "ossec-analysisd"
#endif

#include "../../analysisd/decoders/decode-xml.c"
#include "../wrappers/common.h"

bool w_get_attr_regex_type(xml_node * node, w_exp_type_t * type);
int w_get_attr_offset(xml_node * node);

/* setup/teardown */

/* tests */

// w_get_attr_regex_type

void w_get_attr_regex_type_not_found(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "attr_name_2", NULL};
    char * values[] = {"attr_val_1", "attr_val_2", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_false(retval);
    assert_int_equal(type, -2);
}

void w_get_attr_regex_type_osregex(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "type", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "osregex", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_true(retval);
    assert_int_equal(type, EXP_TYPE_OSREGEX);
}

void w_get_attr_regex_type_osmatch(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "type", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "osmatch", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_true(retval);
    assert_int_equal(type, EXP_TYPE_OSMATCH);
}

void w_get_attr_regex_type_pcre2(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "type", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "PCRE2", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_true(retval);
    assert_int_equal(type, EXP_TYPE_PCRE2);
}

void w_get_attr_regex_type_invalid(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "type", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "invalid type", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_true(retval);
    assert_int_equal(type, EXP_TYPE_INVALID);
}

// w_get_attr_offset

void w_get_attr_offset_not_found(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "attr_name_2", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "attr_val_2", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, 0);
}

void w_get_attr_offset_after_parent(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "offset", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "after_parent", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, AFTER_PARENT);
}

void w_get_attr_offset_after_prematch(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "offset", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "after_prematch", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, AFTER_PREMATCH);
}
void w_get_attr_offset_after_after_regex(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "offset", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "after_regex", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, AFTER_PREVREGEX);
}

void w_get_attr_offset_error(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "offset", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "bad_value", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, AFTER_ERROR);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_get_attr_regex_type
        cmocka_unit_test(w_get_attr_regex_type_not_found),
        cmocka_unit_test(w_get_attr_regex_type_osregex),
        cmocka_unit_test(w_get_attr_regex_type_osmatch),
        cmocka_unit_test(w_get_attr_regex_type_pcre2),
        cmocka_unit_test(w_get_attr_regex_type_invalid),

        // w_get_attr_offset
        cmocka_unit_test(w_get_attr_offset_not_found),
        cmocka_unit_test(w_get_attr_offset_after_parent),
        cmocka_unit_test(w_get_attr_offset_after_prematch),
        cmocka_unit_test(w_get_attr_offset_after_after_regex),
        cmocka_unit_test(w_get_attr_offset_error),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
