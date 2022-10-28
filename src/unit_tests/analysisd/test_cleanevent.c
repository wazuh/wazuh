/*
 * Copyright (C) 2022, Wazuh Inc.
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

static int test_setup(void **state) {
    Eventinfo *lf = NULL;
    os_calloc(1, sizeof(Eventinfo), lf);
    *state = lf;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    Eventinfo *lf = (Eventinfo *)*state;
    os_free(lf->full_log);
    os_free(lf->location);
    os_free(lf->location);
    os_free(lf->agent_id);
    os_free(lf->hostname);
    os_free(lf);

    return OS_SUCCESS;
}

/* Tests */

static void test_OS_CleanMSG_fail(void **state) {

    Eventinfo lf;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%s", "fail message");
    expect_string(__wrap__merror, formatted_msg, "(1106): String not correctly formatted.");

    int value = OS_CleanMSG(msg, &lf);

    assert_int_equal(value, -1);

    os_free(msg);
}

static void test_OS_CleanMSG_fail_short_msg(void **state) {

    Eventinfo lf;

    char *msg = NULL;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%s", "1:a");
    expect_string(__wrap__merror, formatted_msg, "(1106): String not correctly formatted.");

    int value = OS_CleanMSG(msg, &lf);

    assert_int_equal(value, -1);

    os_free(msg);
}

static void test_OS_CleanMSG_ossec_min_msg(void **state) {

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "a", "b");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->full_log, "b");
    assert_string_equal(lf->location, "a");

    os_free(msg);
}

static void test_OS_CleanMSG_ossec_arrow_msg(void **state) {

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s->%s", '5', "[015] (DESKTOP) any", "fim_registry:payload");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->full_log, "payload");
    assert_string_equal(lf->location, "(DESKTOP) any->fim_registry");

    os_free(msg);
}

static void test_OS_CleanMSG_ossec_test_msg(void **state) {

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "location test", "payload test");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->full_log, "payload test");
    assert_string_equal(lf->location, "location test");

    os_free(msg);
}

static void test_OS_CleanMSG_ossec_syslog_msg(void **state) {

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "payload test");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->full_log, "payload test");
    assert_string_equal(lf->location, "/var/log/syslog");

    os_free(msg);
}

static void test_OS_CleanMSG_syslog_ipv4_msg(void **state) {

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '2', "127.0.0.1", "payload test");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->full_log, "payload test");
    assert_string_equal(lf->location, "127.0.0.1");

    os_free(msg);
}

static void test_OS_CleanMSG_syslog_ipv6_msg(void **state) {

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '2', "0000|:0000|:0000|:0000|:0000|:0000|:0000|:0001", "payload test");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->full_log, "payload test");
    assert_string_equal(lf->location, "0000:0000:0000:0000:0000:0000:0000:0001");

    os_free(msg);
}

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
        // Test OS_CleanMSG
        cmocka_unit_test(test_OS_CleanMSG_fail),
        cmocka_unit_test(test_OS_CleanMSG_fail_short_msg),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_ossec_min_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_ossec_arrow_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_ossec_test_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_ossec_syslog_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_syslog_ipv4_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_syslog_ipv6_msg, test_setup, test_teardown),
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
