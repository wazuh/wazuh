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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "../headers/shared.h"
#include "../headers/read-alert.h"
#include "../../os_csyslogd/csyslogd.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

#define SOCKET 1
#define HEADER_DATE "<132>Nov  9 07:11:17"
#define COMMENT "sshd: authentication failed."
#define LOCATION "victim->/var/log/lab.log"
#define GROUP "syslog,sshd,authentication_failed,"
#define CEF_HEADER HEADER_DATE " CEF:0|" __author "|" __ossec_name "|" __ossec_version "|5760|"

#define LOG_2001 "Nov  5 15:00:00 victim sshd[2001]: Failed password for admin from 9.9.9.9 port 5555 ssh2\", action=\"blocked\", src_user=\"CEO\", tag=\"FORGED_LAB"
#define LOG_2002 "Nov  5 15:00:01 victim sshd[2002]: Failed password for admin from 9.9.9.8 port 5556 ssh2 act=blocked cs6Label=tag cs6=FORGED_CEF back\\slash pipe|bar"
#define LOG_2003 "Nov  5 15:00:02 victim sshd[2003]: Failed password for x\",forged=\"CEO from 9.9.9.7 port 5557 ssh2"
#define LOG_2004 "Nov  5 15:00:03 victim sshd[2004]: Failed password for a\\b=c|d from 9.9.9.6 port 5558 ssh2"
#define LOG_2005 "Nov  5 15:00:04 victim sshd[2005]: Failed password for evil\\ from 9.9.9.5 port 5559 ssh2"

static alert_data *make_alert(const char *comment, const char *location, const char *srcip, int srcport, const char *user, const char *log) {
    alert_data *al_data;

    os_calloc(1, sizeof(alert_data), al_data);
    al_data->rule = 5760;
    al_data->level = 5;
    os_strdup("2026 Nov 09 07:11:17", al_data->date);
    os_strdup(comment, al_data->comment);
    os_strdup(location, al_data->location);
    os_strdup(GROUP, al_data->group);
    os_strdup(srcip, al_data->srcip);
    al_data->srcport = srcport;
    os_strdup(user, al_data->user);
    os_calloc(2, sizeof(char *), al_data->log);
    os_strdup(log, al_data->log[0]);

    return al_data;
}

static void send_alert(unsigned int format, alert_data *al_data, const char *expected) {
    SyslogConfig config = { .format = format, .priority = 132, .socket = SOCKET };

    expect_value(__wrap_OS_SendUDPbySize, sock, SOCKET);
    expect_value(__wrap_OS_SendUDPbySize, size, strlen(expected));
    expect_string(__wrap_OS_SendUDPbySize, msg, expected);
    will_return(__wrap_OS_SendUDPbySize, 0);

    assert_int_equal(OS_Alert_SendSyslog(al_data, &config), 1);

    FreeAlertData(al_data);
}

static int setup_group(void **state) {
    strcpy(__shost, "indexer2");
    return 0;
}

static void test_splunk_message(void **state) {
    send_alert(SPLUNK_CSYSLOG, make_alert(COMMENT, LOCATION, "9.9.9.9", 5555, "admin", LOG_2001),
               HEADER_DATE " indexer2 ossec: crit=5 id=5760 description=\"" COMMENT "\" component=\"" LOCATION "\","
               " classification=\"" GROUP "\", src_ip=\"9.9.9.9\", src_port=5555, acct=\"admin\","
               " message=\"Nov  5 15:00:00 victim sshd[2001]: Failed password for admin from 9.9.9.9 port 5555 ssh2',"
               " action='blocked', src_user='CEO', tag='FORGED_LAB\"");
}

static void test_splunk_user_quote(void **state) {
    send_alert(SPLUNK_CSYSLOG, make_alert(COMMENT, LOCATION, "9.9.9.7", 5557, "x\",forged=\"CEO", LOG_2003),
               HEADER_DATE " indexer2 ossec: crit=5 id=5760 description=\"" COMMENT "\" component=\"" LOCATION "\","
               " classification=\"" GROUP "\", src_ip=\"9.9.9.7\", src_port=5557, acct=\"x',forged='CEO\","
               " message=\"Nov  5 15:00:02 victim sshd[2003]: Failed password for x',forged='CEO from 9.9.9.7 port 5557 ssh2\"");
}

static void test_splunk_user_trailing_backslash(void **state) {
    send_alert(SPLUNK_CSYSLOG, make_alert(COMMENT, LOCATION, "9.9.9.5", 5559, "evil\\", LOG_2005),
               HEADER_DATE " indexer2 ossec: crit=5 id=5760 description=\"" COMMENT "\" component=\"" LOCATION "\","
               " classification=\"" GROUP "\", src_ip=\"9.9.9.5\", src_port=5559, acct=\"evil\\\\\","
               " message=\"Nov  5 15:00:04 victim sshd[2005]: Failed password for evil\\ from 9.9.9.5 port 5559 ssh2\"");
}

static void test_splunk_header(void **state) {
    send_alert(SPLUNK_CSYSLOG, make_alert("a|b\\c \"q\" k=v", "(agent) any->/var/log/a\"b", "9.9.9.9", 5555, "admin", "log"),
               HEADER_DATE " indexer2 ossec: crit=5 id=5760 description=\"a|b\\c 'q' k=v\" component=\"(agent) any->/var/log/a'b\","
               " classification=\"" GROUP "\", src_ip=\"9.9.9.9\", src_port=5555, acct=\"admin\", message=\"log\"");
}

static void test_splunk_header_does_not_fit(void **state) {
    char location[2001];

    memset(location, 'a', sizeof(location) - 1);
    location[sizeof(location) - 1] = '\0';

    send_alert(SPLUNK_CSYSLOG, make_alert(COMMENT, location, "9.9.9.9", 5555, "admin", "log"),
               HEADER_DATE " indexer2 ossec: crit=5 id=5760"
               " classification=\"" GROUP "\", src_ip=\"9.9.9.9\", src_port=5555, acct=\"admin\", message=\"log\"");
}

static void test_cef_message_quote(void **state) {
    send_alert(CEF_CSYSLOG, make_alert(COMMENT, LOCATION, "9.9.9.9", 5555, "admin", LOG_2001),
               CEF_HEADER COMMENT "|5|dvc=indexer2 cs1=" LOCATION " cs1Label=Location cat=" GROUP
               " src=9.9.9.9 spt=5555 shost=9.9.9.9 suser=admin suser=admin"
               " msg=Nov  5 15:00:00 victim sshd[2001]: Failed password for admin from 9.9.9.9 port 5555 ssh2\","
               " action\\=\"blocked\", src_user\\=\"CEO\", tag\\=\"FORGED_LAB");
}

static void test_cef_message_keys(void **state) {
    send_alert(CEF_CSYSLOG, make_alert(COMMENT, LOCATION, "9.9.9.8", 5556, "admin", LOG_2002),
               CEF_HEADER COMMENT "|5|dvc=indexer2 cs1=" LOCATION " cs1Label=Location cat=" GROUP
               " src=9.9.9.8 spt=5556 shost=9.9.9.8 suser=admin suser=admin"
               " msg=Nov  5 15:00:01 victim sshd[2002]: Failed password for admin from 9.9.9.8 port 5556 ssh2"
               " act\\=blocked cs6Label\\=tag cs6\\=FORGED_CEF back\\\\slash pipe|bar");
}

static void test_cef_user(void **state) {
    send_alert(CEF_CSYSLOG, make_alert(COMMENT, LOCATION, "9.9.9.6", 5558, "a\\b=c|d", LOG_2004),
               CEF_HEADER COMMENT "|5|dvc=indexer2 cs1=" LOCATION " cs1Label=Location cat=" GROUP
               " src=9.9.9.6 spt=5558 shost=9.9.9.6 suser=a\\\\b\\=c|d suser=a\\\\b\\=c|d"
               " msg=Nov  5 15:00:03 victim sshd[2004]: Failed password for a\\\\b\\=c|d from 9.9.9.6 port 5558 ssh2");
}

static void test_cef_header(void **state) {
    send_alert(CEF_CSYSLOG, make_alert("a|b\\c \"q\" k=v", "(agent) any->/var/log/a=b", "9.9.9.9", 5555, "admin", "log\r\n"),
               CEF_HEADER "a\\|b\\\\c \"q\" k=v|5|dvc=indexer2 cs1=(agent) any->/var/log/a\\=b cs1Label=Location cat=" GROUP
               " src=9.9.9.9 spt=5555 shost=9.9.9.9 suser=admin suser=admin msg=log\\r\\n");
}

static void test_cef_header_does_not_fit(void **state) {
    char comment[1001];

    /* 1000 backslashes become 2000 bytes once escaped */
    memset(comment, '\\', sizeof(comment) - 1);
    comment[sizeof(comment) - 1] = '\0';

    send_alert(CEF_CSYSLOG, make_alert(comment, LOCATION, "9.9.9.9", 5555, "admin", "log"),
               CEF_HEADER "|5|dvc=indexer2 cs1=" LOCATION " cs1Label=Location cat=" GROUP
               " src=9.9.9.9 spt=5555 shost=9.9.9.9 suser=admin suser=admin msg=log");
}

static void test_cef_header_location_does_not_fit(void **state) {
    char location[2001];

    memset(location, 'a', sizeof(location) - 1);
    location[sizeof(location) - 1] = '\0';

    send_alert(CEF_CSYSLOG, make_alert(COMMENT, location, "9.9.9.9", 5555, "admin", "log"),
               CEF_HEADER "|5|dvc=indexer2 cat=" GROUP
               " src=9.9.9.9 spt=5555 shost=9.9.9.9 suser=admin suser=admin msg=log");
}

static void test_default_unescaped(void **state) {
    send_alert(DEFAULT_CSYSLOG, make_alert(COMMENT, LOCATION, "9.9.9.7", 5557, "x\",forged=\"CEO", LOG_2003),
               HEADER_DATE " indexer2 ossec: Alert Level: 5; Rule: 5760 - " COMMENT "; Location: " LOCATION ";"
               " classification: " GROUP "; srcip: 9.9.9.7; user: x\",forged=\"CEO; " LOG_2003);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_splunk_message),
        cmocka_unit_test(test_splunk_user_quote),
        cmocka_unit_test(test_splunk_user_trailing_backslash),
        cmocka_unit_test(test_splunk_header),
        cmocka_unit_test(test_splunk_header_does_not_fit),
        cmocka_unit_test(test_cef_message_quote),
        cmocka_unit_test(test_cef_message_keys),
        cmocka_unit_test(test_cef_user),
        cmocka_unit_test(test_cef_header),
        cmocka_unit_test(test_cef_header_does_not_fit),
        cmocka_unit_test(test_cef_header_location_does_not_fit),
        cmocka_unit_test(test_default_unescaped),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
