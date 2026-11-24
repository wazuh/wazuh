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
#include <string.h>

#include "shared.h"
#include "../../os_maild/maild.h"

#define GUARD_BYTE 'X'

/* Global variables */
unsigned int mail_timeout;
unsigned int   _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];

alert_data *__wrap_Read_FileMon(__attribute__((unused)) file_queue *fileq,
                                __attribute__((unused)) const struct tm *p,
                                __attribute__((unused)) unsigned int timeout) {
    return mock_type(alert_data *);
}

/* The test owns the alert data: its location is not the start of an allocation. */
void __wrap_FreeAlertData(__attribute__((unused)) alert_data *al_data) {
}

/* Runs OS_RecvMailQ on an alert whose location is stored right after a guard byte. */
static void run_subject(const char *location, const char *expected_subject) {
    char buffer[OS_SIZE_256] = { GUARD_BYTE };
    char *log[] = { "log line", NULL };
    alert_data al_data = { .rule = 1002, .level = 10, .date = "2026 Oct 31 10:00:01",
                           .comment = "comment", .log = log, .location = buffer + 1 };
    MailConfig mail_config = { .subject_full = 0 };
    file_queue fileq = { 0 };
    struct tm tm = { 0 };
    MailMsg *msg_sms = NULL;
    MailMsg *msg;
    char subject[SUBJECT_SIZE];

    strncpy(buffer + 1, location, sizeof(buffer) - 2);
    _g_subject[0] = '\0';
    snprintf(subject, sizeof(subject), MAIL_SUBJECT, expected_subject, 10);

    will_return(__wrap_Read_FileMon, &al_data);
    expect_any(__wrap__mdebug2, formatted_msg);

    msg = OS_RecvMailQ(&fileq, &tm, &mail_config, &msg_sms);

    assert_non_null(msg);
    assert_int_equal(buffer[0], GUARD_BYTE);
    assert_string_equal(al_data.location, location);
    assert_string_equal(msg->subject, subject);
    assert_null(msg_sms);

    os_free(msg->subject);
    os_free(msg->body);
    os_free(msg);
}

static void test_subject_agent_location(void **state) {
    run_subject("(agent) 192.168.1.10->/var/log/auth.log", "(agent) 192.168.1.10");
}

static void test_subject_location_with_several_separators(void **state) {
    run_subject("(agent) 192.168.1.10->/var/log/a->b", "(agent) 192.168.1.10");
}

static void test_subject_location_starts_with_separator(void **state) {
    run_subject("->/var/log/auth.log", "");
}

static void test_subject_location_starts_with_gt(void **state) {
    run_subject(">EVIL", ">EVIL");
}

static void test_subject_location_with_gt_without_dash(void **state) {
    run_subject("host>/var/log/auth.log", "host>/var/log/auth.log");
}

static void test_subject_location_without_separator(void **state) {
    run_subject("wazuh-monitord", "wazuh-monitord");
}

static MailMsg *run_body(alert_data *al_data) {
    MailConfig mail_config = { .subject_full = 0 };
    file_queue fileq = { 0 };
    struct tm tm = { 0 };
    MailMsg *msg_sms = NULL;
    MailMsg *msg;

    will_return(__wrap_Read_FileMon, al_data);
    expect_any(__wrap__mdebug2, formatted_msg);

    msg = OS_RecvMailQ(&fileq, &tm, &mail_config, &msg_sms);
    assert_non_null(msg);
    return msg;
}

static void assert_before_log_portion(const char *body, const char *text) {
    const char *found = strstr(body, text);
    const char *portion = strstr(body, "Portion of the log(s):");

    assert_non_null(found);
    assert_non_null(portion);
    assert_true(found < portion);
}

static void free_msg(MailMsg *msg) {
    os_free(msg->subject);
    os_free(msg->body);
    os_free(msg);
}

static void test_body_prints_src_user_and_user(void **state) {
    char location[] = "(agent) 192.168.1.10->/var/log/secure";
    char *log[] = { "log line", NULL };
    alert_data al_data = { .rule = 5402, .level = 3, .date = "2026 Nov 24 10:00:00",
                           .comment = "comment", .log = log, .location = location,
                           .srcuser = "carol", .user = "root" };

    MailMsg *msg = run_body(&al_data);

    assert_before_log_portion(msg->body, "Src User: carol\r\nUser: root\r\n");

    free_msg(msg);
}

static void test_body_prints_src_user_only(void **state) {
    char location[] = "(agent) 192.168.1.10->/var/log/secure";
    char *log[] = { "log line", NULL };
    alert_data al_data = { .rule = 5710, .level = 5, .date = "2026 Nov 24 10:00:00",
                           .comment = "comment", .log = log, .location = location,
                           .srcuser = "bob" };

    MailMsg *msg = run_body(&al_data);

    assert_before_log_portion(msg->body, "Src User: bob\r\n");
    assert_null(strstr(msg->body, "\nUser: "));

    free_msg(msg);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_subject_agent_location),
        cmocka_unit_test(test_subject_location_with_several_separators),
        cmocka_unit_test(test_subject_location_starts_with_separator),
        cmocka_unit_test(test_subject_location_starts_with_gt),
        cmocka_unit_test(test_subject_location_with_gt_without_dash),
        cmocka_unit_test(test_subject_location_without_separator),
        cmocka_unit_test(test_body_prints_src_user_and_user),
        cmocka_unit_test(test_body_prints_src_user_only),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
