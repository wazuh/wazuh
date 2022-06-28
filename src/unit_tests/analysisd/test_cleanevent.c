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
#include <stdlib.h>

#include "analysisd/cleanevent.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Tests */

void test_extract_module_from_message(void ** state) {
    char message[32] = "1:/var/log/demo.log:Hello world";

    char *module = extract_module_from_message(message);

    assert_string_equal(module, "/var/log/demo.log");
}

void test_extract_module_from_message_arrow(void ** state) {
    char message[61] = "1:[001] (testing) 192.168.1.1->/var/log/demo.log:Hello world";

    char *module = extract_module_from_message(message);

    assert_string_equal(module, "/var/log/demo.log");
}

void test_extract_module_from_message_end_error(void ** state) {
    char message[32] = "1:/var/log/demo.log;Hello world";

    expect_string(__wrap__merror, formatted_msg, "(1106): String not correctly formatted.");

    char *module = extract_module_from_message(message);

    assert_null(module);
}

void test_extract_module_from_message_arrow_error(void ** state) {
    char message[61] = "1:[001] (testing) 192.168.1.1-</var/log/demo.log:Hello world";

    expect_string(__wrap__merror, formatted_msg, "(1106): String not correctly formatted.");

    char *module = extract_module_from_message(message);

    assert_null(module);
}

void test_extract_module_from_location(void ** state) {
    char *location = "/var/log/demo.log";

    const char *module = extract_module_from_location(location);

    assert_string_equal(module, "/var/log/demo.log");
}

void test_extract_module_from_location_arrow(void ** state) {
    char *location = "[001] (testing) 192.168.1.1->/var/log/demo.log";

    const char *module = extract_module_from_location(location);

    assert_string_equal(module, "/var/log/demo.log");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test extract_module_from_message
        cmocka_unit_test(test_extract_module_from_message),
        cmocka_unit_test(test_extract_module_from_message_arrow),
        cmocka_unit_test(test_extract_module_from_message_end_error),
        cmocka_unit_test(test_extract_module_from_message_arrow_error),
        // Test extract_module_from_location
        cmocka_unit_test(test_extract_module_from_location),
        cmocka_unit_test(test_extract_module_from_location_arrow),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
