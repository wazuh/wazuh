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
#include <string.h>

#include "../../headers/shared.h"
#include "../../headers/read-alert.h"

static alert_data* parse_alert_with_flag(const char *input, int flag) {
    FILE *fp = tmpfile();
    assert_non_null(fp);

    size_t len = strlen(input);
    size_t written = fwrite(input, sizeof(char), len, fp);
    assert_int_equal(written, len);

    rewind(fp);

    alert_data *al_data = GetAlertData(flag, fp);
    fclose(fp);

    return al_data;
}

static alert_data* parse_alert_from_string(const char *input) {
    return parse_alert_with_flag(input, 0);
}

static void test_GetAlertData_header_without_log_is_skipped(void **state) {
    (void) state;

    const char input[] =
        "** Alert 1793500000.1: mail  - x\n"
        "Nov  6 11:40:01 host\n"
        "Rule: 1 (level 1) -> 'x'\n"
        "Src IP: 1.2.3.4\n"
        "** Alert 1793500000.2: mail  - y\n"
        "Nov  6 11:40:02 host\n"
        "trigger log line\n"
        "\n";

    expect_string(__wrap__mdebug1, formatted_msg, "Dropping alerts.log record '1793500000.1' without log lines.");

    alert_data *al_data = parse_alert_from_string(input);

    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.2");
    assert_string_equal(al_data->group, "y");
    assert_int_equal(al_data->rule, 0);
    assert_null(al_data->comment);
    assert_null(al_data->srcip);
    assert_non_null(al_data->log);
    assert_string_equal(al_data->log[0], "trigger log line");

    FreeAlertData(al_data);
}

static void test_GetAlertData_record_with_log_ends_at_next_header(void **state) {
    (void) state;

    const char input[] =
        "** Alert 1793500000.1: mail  - syslog,sshd,\n"
        "2026 Nov 06 11:40:01 (agent) any->/var/log/auth.log\n"
        "Rule: 5760 (level 5) -> 'sshd: authentication failed.'\n"
        "first log line\n"
        "\n"
        "** Alert 1793500000.2: mail  - y\n"
        "Nov  6 11:40:02 host\n"
        "second log line\n"
        "\n";

    alert_data *al_data = parse_alert_from_string(input);

    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.1");
    assert_int_equal(al_data->rule, 5760);
    assert_non_null(al_data->log);
    assert_string_equal(al_data->log[0], "first log line");

    FreeAlertData(al_data);
}

static void test_GetAlertData_header_without_log_resets_syscheck(void **state) {
    (void) state;

    const char input[] =
        "** Alert 1793500000.1: mail  - ossec,syscheck,\n"
        "Nov  6 11:40:01 host\n"
        "** Alert 1793500000.2: mail  - y\n"
        "Nov  6 11:40:02 host\n"
        "Integrity checksum changed for: '/etc/passwd'\n"
        "\n";

    expect_string(__wrap__mdebug1, formatted_msg, "Dropping alerts.log record '1793500000.1' without log lines.");

    alert_data *al_data = parse_alert_from_string(input);

    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.2");
    assert_null(al_data->filename);

    FreeAlertData(al_data);
}

static void test_GetAlertData_header_without_log_mail_flag(void **state) {
    (void) state;

    const char input[] =
        "** Alert 1793500000.1: mail  - x\n"
        "Nov  6 11:40:01 host\n"
        "** Alert 1793500000.2: - syslog,\n"
        "Nov  6 11:40:02 host\n"
        "not mailed log line\n"
        "\n"
        "** Alert 1793500000.3: mail  - y\n"
        "Nov  6 11:40:03 host\n"
        "mailed log line\n"
        "\n";

    expect_string(__wrap__mdebug1, formatted_msg, "Dropping alerts.log record '1793500000.1' without log lines.");

    alert_data *al_data = parse_alert_with_flag(input, CRALERT_MAIL_SET);

    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.3");
    assert_non_null(al_data->log);
    assert_string_equal(al_data->log[0], "mailed log line");

    FreeAlertData(al_data);
}

static void test_GetAlertData_long_line_does_not_start_a_record(void **state) {
    (void) state;

    /* fgets() returns OS_MAXSTR - 1 bytes, so the header lands at the start of the second chunk */
    const char head[] =
        "** Alert 1793500000.1: mail  - syslog,\n"
        "2026 Nov 06 11:40:01 (agent) any->/var/log/auth.log\n"
        "Rule: 5760 (level 5) -> 'sshd: authentication failed.'\n";
    const char tail[] =
        "** Alert 1793500000.9: mail  - x\n"
        "Nov  6 11:40:02 >y\n"
        "trigger log line\n"
        "\n";
    size_t pad = OS_MAXSTR - 1;
    char *input;

    os_calloc(sizeof(head) + pad + sizeof(tail), sizeof(char), input);
    strcpy(input, head);
    memset(input + strlen(head), 'A', pad);
    strcat(input, tail);

    FILE *fp = tmpfile();
    assert_non_null(fp);
    assert_int_equal(fwrite(input, sizeof(char), strlen(input), fp), strlen(input));
    rewind(fp);

    alert_data *al_data = GetAlertData(0, fp);
    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.1");
    FreeAlertData(al_data);

    assert_null(GetAlertData(0, fp));

    fclose(fp);
    os_free(input);
}

static void test_GetAlertData_nul_byte_at_eof_without_log(void **state) {
    (void) state;

    /* The NUL hides the newline, so the last line is skipped as a continuation */
    const char input[] =
        "** Alert 1793500000.1: mail  - x\n"
        "Nov  6 11:40:01 host\0x\n"
        "\0";

    FILE *fp = tmpfile();
    assert_non_null(fp);
    assert_int_equal(fwrite(input, sizeof(char), sizeof(input) - 1, fp), sizeof(input) - 1);
    rewind(fp);

    assert_null(GetAlertData(0, fp));

    fclose(fp);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_GetAlertData_header_without_log_is_skipped),
        cmocka_unit_test(test_GetAlertData_record_with_log_ends_at_next_header),
        cmocka_unit_test(test_GetAlertData_header_without_log_resets_syscheck),
        cmocka_unit_test(test_GetAlertData_header_without_log_mail_flag),
        cmocka_unit_test(test_GetAlertData_long_line_does_not_start_a_record),
        cmocka_unit_test(test_GetAlertData_nul_byte_at_eof_without_log),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
