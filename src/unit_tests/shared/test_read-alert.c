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
#ifndef WIN32
#include <unistd.h>
#endif

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

static void test_GetAlertData_buffer_underflow_fix_empty_filename(void **state) {
    (void) state;

    const char input[] =
        "** Alert 1676620577.100: - ossec,syscheck,\n"
        "2023 Feb 17 08:00:00 (agent) 192.168.0.1->syscheck\n"
        "Rule: 550 (level 7) -> 'Integrity checksum changed.'\n"
        "Integrity checksum changed for: ''\n"
        "\n";

    alert_data *al_data = parse_alert_from_string(input);

    assert_non_null(al_data);
    assert_non_null(al_data->filename);
    assert_string_equal(al_data->filename, "");

    FreeAlertData(al_data);
}

static void test_GetAlertData_valid_filename(void **state) {
    (void) state;

    const char input[] =
        "** Alert 1676620577.100: - ossec,syscheck,\n"
        "2023 Feb 17 08:00:00 (agent) 192.168.0.1->syscheck\n"
        "Rule: 550 (level 7) -> 'Integrity checksum changed.'\n"
        "Integrity checksum changed for: '/etc/passwd'\n"
        "\n";

    alert_data *al_data = parse_alert_from_string(input);

    assert_non_null(al_data);
    assert_non_null(al_data->filename);
    assert_string_equal(al_data->filename, "/etc/passwd");

    FreeAlertData(al_data);
}

static void test_GetAlertData_filename_with_spaces(void **state) {
    (void) state;

    const char input[] =
        "** Alert 1676620577.100: - ossec,syscheck,\n"
        "2023 Feb 17 08:00:00 (agent) 192.168.0.1->syscheck\n"
        "Rule: 550 (level 7) -> 'Integrity checksum changed.'\n"
        "Integrity checksum changed for: '/path/with spaces/file.txt'\n"
        "\n";

    alert_data *al_data = parse_alert_from_string(input);

    assert_non_null(al_data);
    assert_non_null(al_data->filename);
    assert_string_equal(al_data->filename, "/path/with spaces/file.txt");

    FreeAlertData(al_data);
}

static void test_GetAlertData_filename_windows_crlf(void **state) {
    (void) state;

    const char input[] =
        "** Alert 1676620577.100: - ossec,syscheck,\n"
        "2023 Feb 17 08:00:00 (agent) 192.168.0.1->syscheck\n"
        "Rule: 550 (level 7) -> 'Integrity checksum changed.'\n"
        "Integrity checksum changed for: '/var/log/auth.log'\r\n"
        "\n";

    alert_data *al_data = parse_alert_from_string(input);

    assert_non_null(al_data);
    assert_non_null(al_data->filename);

    assert_string_equal(al_data->filename, "/var/log/auth.log");

    FreeAlertData(al_data);
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

static const char two_alerts[] =
    "** Alert 1793500000.1: mail  - syslog,sshd,\n"
    "2026 Nov 06 11:40:01 (agent) any->/var/log/auth.log\n"
    "Rule: 5760 (level 5) -> 'sshd: authentication failed.'\n"
    "first log line\n"
    "\n"
    "** Alert 1793500000.2: mail  - y\n"
    "Nov  6 11:40:02 host\n"
    "second log line\n"
    "\n";

static FILE *open_tmpfile_with(const char *input) {
    FILE *fp = tmpfile();
    assert_non_null(fp);
    assert_int_equal(fwrite(input, sizeof(char), strlen(input), fp), strlen(input));
    rewind(fp);
    return fp;
}

#ifndef WIN32
/* The input must fit in the pipe buffer, since nothing reads while writing */
static FILE *open_pipe_with(const char *input) {
    int fds[2];
    assert_int_equal(pipe(fds), 0);
    assert_int_equal(write(fds[1], input, strlen(input)), (ssize_t)strlen(input));
    close(fds[1]);

    FILE *fp = fdopen(fds[0], "r");
    assert_non_null(fp);
    return fp;
}

static void test_GetAlertData_ex_pipe_with_slot_returns_every_alert(void **state) {
    (void) state;
    char *pending = NULL;
    FILE *fp = open_pipe_with(two_alerts);

    alert_data *al_data = GetAlertData_ex(0, fp, &pending);
    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.1");
    assert_string_equal(al_data->log[0], "first log line");
    assert_string_equal(pending, "** Alert 1793500000.2: mail  - y\n");
    FreeAlertData(al_data);

    al_data = GetAlertData_ex(0, fp, &pending);
    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.2");
    assert_string_equal(al_data->log[0], "second log line");
    assert_null(pending);
    FreeAlertData(al_data);

    assert_null(GetAlertData_ex(0, fp, &pending));
    assert_null(pending);

    fclose(fp);
}

static void test_GetAlertData_pipe_without_slot_keeps_old_behavior(void **state) {
    (void) state;
    FILE *fp = open_pipe_with(two_alerts);

    /* Without a slot the reader seeks back over the next header, which a pipe rejects */
    assert_null(GetAlertData(0, fp));

    fclose(fp);
}

/* Laid out like analysisd writes FIM alerts: blank lines inside the alert, before Attributes, What changed and Tags */
static const char fim_then_syslog[] =
    "** Alert 1793500000.10: mail  - ossec,syscheck,syscheck_entry_modified,syscheck_file,\n"
    "2026 Nov 20 10:00:10 (agent) any->syscheck\n"
    "Rule: 550 (level 7) -> 'Integrity checksum changed.'\n"
    "File '/etc/app.conf' modified\n"
    "Mode: realtime\n"
    "Changed attributes: size,md5\n"
    "Size changed from '10' to '25'\n"
    "Old md5sum was: 'old_hash_md5'\n"
    "New md5sum is : 'hash_md5'\n"
    "\n"
    "Attributes:\n"
    " - Size: 25\n"
    " - Permissions: rw-r--r--\n"
    "\n"
    "What changed:\n"
    "1c1\n"
    "< before\n"
    "\n"
    "> after\n"
    "\n"
    "Tags:\n"
    " - prod\n"
    "\n"
    "** Alert 1793500000.11: - syslog,sshd,\n"
    "2026 Nov 20 10:00:11 (agent) any->/var/log/auth.log\n"
    "Rule: 5715 (level 3) -> 'sshd: authentication success.'\n"
    "second log line\n"
    "\n";

static int log_has(const alert_data *al_data, const char *line) {
    for (int i = 0; al_data->log && al_data->log[i]; i++) {
        if (strcmp(al_data->log[i], line) == 0) {
            return 1;
        }
    }
    return 0;
}

static void test_GetAlertData_ex_pipe_keeps_lines_after_blank_lines(void **state) {
    (void) state;
    char *pending = NULL;
    FILE *pipe_fp = open_pipe_with(fim_then_syslog);
    FILE *file_fp = open_tmpfile_with(fim_then_syslog);

    alert_data *a = GetAlertData_ex(0, pipe_fp, &pending);
    alert_data *b = GetAlertData(0, file_fp);
    assert_non_null(a);
    assert_non_null(b);
    assert_string_equal(a->alertid, "1793500000.10");
    assert_true(log_has(a, "Old md5sum was: 'old_hash_md5'"));
    /* Lines after each blank line still belong to this alert */
    assert_true(log_has(a, "Attributes:"));
    assert_true(log_has(a, " - Permissions: rw-r--r--"));
    assert_true(log_has(a, "What changed:"));
    assert_true(log_has(a, "> after"));
    assert_true(log_has(a, " - prod"));
    int k = 0;
    for (; a->log[k] && b->log[k]; k++) {
        assert_string_equal(a->log[k], b->log[k]);
    }
    assert_null(a->log[k]);
    assert_null(b->log[k]);
    FreeAlertData(a);
    FreeAlertData(b);

    a = GetAlertData_ex(0, pipe_fp, &pending);
    assert_non_null(a);
    assert_string_equal(a->alertid, "1793500000.11");
    assert_string_equal(a->log[0], "second log line");
    FreeAlertData(a);

    assert_null(GetAlertData_ex(0, pipe_fp, &pending));
    assert_null(pending);
    fclose(pipe_fp);
    fclose(file_fp);
}
#endif

static void test_GetAlertData_ex_seekable_with_slot_matches_without(void **state) {
    (void) state;
    char *pending = NULL;
    FILE *with_slot = open_tmpfile_with(two_alerts);
    FILE *without_slot = open_tmpfile_with(two_alerts);

    for (int i = 0; i < 2; i++) {
        alert_data *a = GetAlertData_ex(0, with_slot, &pending);
        alert_data *b = GetAlertData(0, without_slot);
        assert_non_null(a);
        assert_non_null(b);
        assert_string_equal(a->alertid, b->alertid);
        assert_int_equal(a->rule, b->rule);
        int k = 0;
        for (; a->log[k] && b->log[k]; k++) {
            assert_string_equal(a->log[k], b->log[k]);
        }
        assert_null(a->log[k]);
        assert_null(b->log[k]);
        FreeAlertData(a);
        FreeAlertData(b);
    }

    assert_null(GetAlertData_ex(0, with_slot, &pending));
    assert_null(GetAlertData(0, without_slot));
    assert_null(pending);

    fclose(with_slot);
    fclose(without_slot);
}

static void test_GetAlertData_ex_slot_skips_header_without_log(void **state) {
    (void) state;
    char *pending = NULL;

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

    FILE *fp = open_tmpfile_with(input);
    alert_data *al_data = GetAlertData_ex(0, fp, &pending);

    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.2");
    assert_string_equal(al_data->group, "y");
    assert_int_equal(al_data->rule, 0);
    assert_null(al_data->comment);
    assert_null(al_data->srcip);
    assert_non_null(al_data->log);
    assert_string_equal(al_data->log[0], "trigger log line");
    assert_null(pending);

    FreeAlertData(al_data);
    fclose(fp);
}

static void test_GetAlertData_ex_slot_long_header_line(void **state) {
    (void) state;
    char *pending = NULL;

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

    FILE *fp = open_tmpfile_with(input);

    alert_data *al_data = GetAlertData_ex(0, fp, &pending);
    assert_non_null(al_data);
    assert_string_equal(al_data->alertid, "1793500000.1");
    assert_null(pending);
    FreeAlertData(al_data);

    assert_null(GetAlertData_ex(0, fp, &pending));
    assert_null(pending);

    fclose(fp);
    os_free(input);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_GetAlertData_buffer_underflow_fix_empty_filename),
        cmocka_unit_test(test_GetAlertData_valid_filename),
        cmocka_unit_test(test_GetAlertData_filename_with_spaces),
        cmocka_unit_test(test_GetAlertData_filename_windows_crlf),
        cmocka_unit_test(test_GetAlertData_header_without_log_is_skipped),
        cmocka_unit_test(test_GetAlertData_record_with_log_ends_at_next_header),
        cmocka_unit_test(test_GetAlertData_header_without_log_resets_syscheck),
        cmocka_unit_test(test_GetAlertData_header_without_log_mail_flag),
        cmocka_unit_test(test_GetAlertData_long_line_does_not_start_a_record),
        cmocka_unit_test(test_GetAlertData_nul_byte_at_eof_without_log),
#ifndef WIN32
        cmocka_unit_test(test_GetAlertData_ex_pipe_with_slot_returns_every_alert),
        cmocka_unit_test(test_GetAlertData_pipe_without_slot_keeps_old_behavior),
        cmocka_unit_test(test_GetAlertData_ex_pipe_keeps_lines_after_blank_lines),
#endif
        cmocka_unit_test(test_GetAlertData_ex_seekable_with_slot_matches_without),
        cmocka_unit_test(test_GetAlertData_ex_slot_skips_header_without_log),
        cmocka_unit_test(test_GetAlertData_ex_slot_long_header_line),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
