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
#include "../../os_maild/mail_list.h"

#define SMTP_SOCKET 999
#define SMTP_HOST "smtp.example"
#define BODY "first line\n.\nnext line\n"
#define STUFFED_BODY "first line\r\n..\r\nnext line\r\n"

/* Global variables */
unsigned int mail_timeout;
unsigned int   _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];

static char smtp_sent[OS_MAXSTR];
static const char *last_sent;

/* SMTP server double: records what the client sends and accepts every command */
int __wrap_OS_SendTCP(__attribute__((unused)) int socket, const char *msg) {
    strncat(smtp_sent, msg, sizeof(smtp_sent) - strlen(smtp_sent) - 1);
    last_sent = msg;
    return 0;
}

char *__wrap_OS_RecvTCP(__attribute__((unused)) int socket, __attribute__((unused)) int sizet) {
    char *reply;

    if (smtp_sent[0] == '\0') {
        os_strdup("220 ready", reply);
    } else if (strcmp(last_sent, "DATA\r\n") == 0) {
        os_strdup("354 go ahead", reply);
    } else {
        os_strdup("250 ok", reply);
    }

    return reply;
}

static int setup(void **state) {
    smtp_sent[0] = '\0';
    last_sent = NULL;
    return 0;
}

static void expect_smtp_connect(void) {
    expect_value(__wrap_OS_ConnectTCP, _port, 25);
    expect_string(__wrap_OS_ConnectTCP, _ip, SMTP_HOST);
    expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
    will_return(__wrap_OS_ConnectTCP, SMTP_SOCKET);
}

/* The body is sent stuffed and the only lone dot line is the end of DATA */
static void assert_body_sent(const char *stuffed) {
    const char *end = strstr(smtp_sent, "\r\n.\r\n");

    assert_non_null(strstr(smtp_sent, stuffed));
    assert_non_null(end);
    assert_null(strstr(end + 1, "\r\n.\r\n"));
}

static void test_send_custom_email_stuffs_body(void **state) {
    char *to[] = { "rcpt@example.com", NULL };
    struct tm tm = { 0 };
    FILE *fp = tmpfile();

    assert_non_null(fp);
    fputs(BODY, fp);
    expect_smtp_connect();

    assert_int_equal(OS_SendCustomEmail(to, "report", SMTP_HOST, "wazuh@example.com", NULL, NULL, fp, &tm), 0);
    assert_body_sent(STUFFED_BODY);

    fclose(fp);
}

static void test_sendsms_stuffs_body(void **state) {
    char *gran_to[] = { "sms@example.com", NULL };
    int gran_set[] = { SMS_FORMAT };
    MailConfig mail = { 0 };
    MailMsg sms = { .subject = "alert", .body = BODY };
    struct tm tm = { 0 };

    mail.smtpserver = SMTP_HOST;
    mail.from = "wazuh@example.com";
    mail.gran_to = gran_to;
    mail.gran_set = gran_set;

    expect_smtp_connect();
    will_return(__wrap_OS_SetRecvTimeout, 0);

    assert_int_equal(OS_Sendsms(&mail, &tm, &sms), 0);
    assert_body_sent(STUFFED_BODY);
}

static MailMsg *new_mail(const char *subject, const char *body) {
    MailMsg *msg;

    os_calloc(1, sizeof(MailMsg), msg);
    os_strdup(subject, msg->subject);
    os_strdup(body, msg->body);
    return msg;
}

static void test_sendmail_stuffs_grouped_bodies(void **state) {
    char *to[] = { "rcpt@example.com", NULL };
    MailConfig mail = { 0 };
    struct tm tm = { 0 };
    MailNode *nodes[2];
    MailNode *node;
    int count = 0;

    mail.smtpserver = SMTP_HOST;
    mail.from = "wazuh@example.com";
    mail.to = to;

    /* The second body continues the line the first one leaves open */
    OS_CreateMailList(10);
    OS_AddMailtoList(new_mail("alert", "first line\n."));
    OS_AddMailtoList(new_mail("alert", ".\nnext line\n"));

    /* OS_Sendmail pops the nodes without freeing them */
    for (node = OS_CheckLastMail(); node && count < 2; node = node->prev) {
        nodes[count++] = node;
    }
    assert_int_equal(count, 2);

    expect_smtp_connect();
    will_return(__wrap_OS_SetRecvTimeout, 0);

    assert_int_equal(OS_Sendmail(&mail, &tm), 0);
    assert_body_sent("first line\r\n...\r\nnext line\r\n");

    FreeMail(nodes[0]);
    FreeMail(nodes[1]);
}

static void test_sendsms_cuts_subject_at_line_break(void **state) {
    char *gran_to[] = { "sms@example.com", NULL };
    int gran_set[] = { SMS_FORMAT };
    MailConfig mail = { 0 };
    MailMsg sms = { .subject = "alert\r\n.\r\nnext", .body = BODY };
    struct tm tm = { 0 };

    mail.smtpserver = SMTP_HOST;
    mail.from = "wazuh@example.com";
    mail.gran_to = gran_to;
    mail.gran_set = gran_set;

    expect_smtp_connect();
    will_return(__wrap_OS_SetRecvTimeout, 0);

    assert_int_equal(OS_Sendsms(&mail, &tm, &sms), 0);
    assert_non_null(strstr(smtp_sent, "Subject: alert\r\n\r\n"));
    assert_body_sent(STUFFED_BODY);
}

static void test_sendmail_cuts_subject_at_line_break(void **state) {
    char *to[] = { "rcpt@example.com", NULL };
    MailConfig mail = { 0 };
    struct tm tm = { 0 };
    MailNode *node;

    mail.smtpserver = SMTP_HOST;
    mail.from = "wazuh@example.com";
    mail.to = to;

    OS_CreateMailList(10);
    OS_AddMailtoList(new_mail("alert\n.\nnext", BODY));
    node = OS_CheckLastMail();
    assert_non_null(node);

    expect_smtp_connect();
    will_return(__wrap_OS_SetRecvTimeout, 0);

    assert_int_equal(OS_Sendmail(&mail, &tm), 0);
    assert_non_null(strstr(smtp_sent, "Subject: alert\r\n\r\n"));
    assert_body_sent(STUFFED_BODY);

    FreeMail(node);
}

/* Grouped alerts send the highest level subject, kept in _g_subject */
static void test_sendmail_cuts_grouped_subject_at_line_break(void **state) {
    char *to[] = { "rcpt@example.com", NULL };
    MailConfig mail = { 0 };
    struct tm tm = { 0 };
    MailNode *node;

    mail.smtpserver = SMTP_HOST;
    mail.from = "wazuh@example.com";
    mail.to = to;

    OS_CreateMailList(10);
    OS_AddMailtoList(new_mail("unused", ".first line\nnext line\n"));
    node = OS_CheckLastMail();
    assert_non_null(node);
    snprintf(_g_subject, sizeof(_g_subject), "alert\n.\nnext");
    _g_subject_level = 12;

    expect_smtp_connect();
    will_return(__wrap_OS_SetRecvTimeout, 0);

    assert_int_equal(OS_Sendmail(&mail, &tm), 0);
    assert_non_null(strstr(smtp_sent, "Subject: alert\r\n\r\n"));
    assert_body_sent("..first line\r\nnext line\r\n");

    FreeMail(node);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_send_custom_email_stuffs_body, setup),
        cmocka_unit_test_setup(test_sendsms_stuffs_body, setup),
        cmocka_unit_test_setup(test_sendmail_stuffs_grouped_bodies, setup),
        cmocka_unit_test_setup(test_sendsms_cuts_subject_at_line_break, setup),
        cmocka_unit_test_setup(test_sendmail_cuts_subject_at_line_break, setup),
        cmocka_unit_test_setup(test_sendmail_cuts_grouped_subject_at_line_break, setup),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
