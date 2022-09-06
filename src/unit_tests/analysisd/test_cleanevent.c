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

#include "../../analysisd/cleanevent.h"


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

int main(void) {
    const struct CMUnitTest tests[] = {

        cmocka_unit_test(test_OS_CleanMSG_fail),
        cmocka_unit_test(test_OS_CleanMSG_fail_short_msg),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_ossec_min_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_ossec_arrow_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_ossec_test_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_ossec_syslog_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_syslog_ipv4_msg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_syslog_ipv6_msg, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}