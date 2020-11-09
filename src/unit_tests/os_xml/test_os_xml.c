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

#include "../../os_xml/os_xml.h"
#include "../wrappers/common.h"

const char * w_get_attr_val_by_name(xml_node * node, const char * name);


/* setup/teardown */

/* tests */

// w_get_attr_val_by_name

void w_get_attr_val_by_name_null_attr(void ** state) {

    xml_node node = {0};
    const char * retval;

    retval = w_get_attr_val_by_name(&node, "test_attr_name");

    assert_null(retval);
}

void w_get_attr_val_by_name_not_found(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "attr_name_2", NULL};
    char * values[] = {"attr_val_1", "attr_val_2", NULL};

    node.attributes = attributes;
    node.values = values;
    const char * retval;

    retval = w_get_attr_val_by_name(&node, "test_attr_name");

    assert_null(retval);
}

void w_get_attr_val_by_name_found(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "test_attr_name", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "test_attr_value", "attr_val_3", NULL};

    node.attributes = attributes;
    node.values = values;
    const char * retval;

    retval = w_get_attr_val_by_name(&node, "test_attr_name");

    assert_non_null(retval);
    assert_string_equal(retval, "test_attr_value");
}

int main(void) {
    const struct CMUnitTest tests[] = {

        // Test w_get_attr_val_by_name
        cmocka_unit_test(w_get_attr_val_by_name_null_attr),
        cmocka_unit_test(w_get_attr_val_by_name_not_found),
        cmocka_unit_test(w_get_attr_val_by_name_found)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
