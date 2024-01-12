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

#include "../analysisd/cleanevent.h"

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

static void test_OS_CleanMSG_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "2015 Dec 29 10:00:01 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->program_name, "AUTH");
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "2015 Dec 29 10:00:01 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");
    assert_string_equal(lf->dec_timestamp, "2015 Dec 29 10:00:01");

    os_free(msg);
}

static void test_OS_CleanMSG_macos_ULS_syslog_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "2021-04-21 10:16:09.404756-0700 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->program_name, "AUTH");
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "2021-04-21 10:16:09.404756-0700 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");
    assert_string_equal(lf->dec_timestamp, "2021-04-21 10:16:09.404756-0700");

    os_free(msg);
}

static void test_OS_CleanMSG_proftpd_1_3_5_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "2015-04-16 21:51:02,805 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->program_name, "AUTH");
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "2015-04-16 21:51:02,805 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");
    assert_string_equal(lf->dec_timestamp, "2015-04-16 21:51:02,805");

    os_free(msg);
}

static void test_OS_CleanMSG_syslog_ng_isodate_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "2007-06-14T15:48:55-04:00 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->program_name, "AUTH");
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "2007-06-14T15:48:55-04:00 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");
    assert_string_equal(lf->dec_timestamp, "2007-06-14T15:48:55-04:00");

    os_free(msg);
}

static void test_OS_CleanMSG_rsyslog_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "2009-05-22T09:36:46.214994-07:00 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->program_name, "AUTH");
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "2009-05-22T09:36:46.214994-07:00 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");
    assert_string_equal(lf->dec_timestamp, "2009-05-22T09:36:46.214994-07:00");

    os_free(msg);
}

static void test_OS_CleanMSG_syslog_isodate_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "2022-12-19T15:02:53.288+00:00 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->program_name, "AUTH");
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "2022-12-19T15:02:53.288+00:00 wazuh-agent01 AUTH:INFO sshd[223468]: LOG BODY");
    assert_string_equal(lf->dec_timestamp, "2022-12-19T15:02:53.288+00:00");

    os_free(msg);
}

static void test_OS_CleanMSG_apache_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/apache", "[Fri Feb 11 18:06:35 2004] [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/apache");
    assert_string_equal(lf->full_log, "[Fri Feb 11 18:06:35 2004] [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]");
    assert_string_equal(lf->dec_timestamp, "Fri Feb 11 18:06:35 2004");

    os_free(msg);
}

static void test_OS_CleanMSG_suricata_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "01/28/1979-09:13:16.240702  [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "01/28/1979-09:13:16.240702  [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]");
    assert_string_equal(lf->dec_timestamp, "01/28/1979-09:13:16.240702");

    os_free(msg);
}

static void test_OS_CleanMSG_osx_asl_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "[Time 2006.12.28 15:53:55 UTC] [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->program_name, "sshd");
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "[Time 2006.12.28 15:53:55 UTC] [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]");
    assert_null(lf->dec_timestamp);

    os_free(msg);
}

static void test_OS_CleanMSG_snort_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "01/28-09:13:16.240702  [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);

    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "01/28-09:13:16.240702  [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]");
    assert_string_equal(lf->dec_timestamp, "01/28-09:13:16.240702");

    os_free(msg);
}

static void test_OS_CleanMSG_xferlog_timestamp(void **state){

    Eventinfo *lf = (Eventinfo *)*state;

    char *msg;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), msg);
    snprintf(msg, OS_BUFFER_SIZE, "%c:%s:%s", '1', "/var/log/syslog", "Mon Apr 17 18:27:14 2006 1 64.160.42.130");

    int value = OS_CleanMSG(msg, lf);

    assert_int_equal(value, 0);
    assert_string_equal(lf->agent_id, "000");
    assert_string_equal(lf->location, "/var/log/syslog");
    assert_string_equal(lf->full_log, "Mon Apr 17 18:27:14 2006 1 64.160.42.130");
    assert_string_equal(lf->dec_timestamp, "Mon Apr 17 18:27:14 2006");

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
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_syslog_isodate_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_rsyslog_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_syslog_ng_isodate_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_proftpd_1_3_5_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_macos_ULS_syslog_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_osx_asl_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_apache_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_suricata_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_snort_timestamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_CleanMSG_xferlog_timestamp, test_setup, test_teardown),

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
