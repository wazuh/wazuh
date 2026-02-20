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

#include "shared.h"
#include "read-alert.h"

static alert_data* parse_alert_from_string(const char *input) {
    FILE *fp = tmpfile();
    assert_non_null(fp);

    size_t len = strlen(input);
    size_t written = fwrite(input, sizeof(char), len, fp);
    assert_int_equal(written, len);

    rewind(fp);

    alert_data *al_data = GetAlertData(0, fp);
    fclose(fp);

    return al_data;
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


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_GetAlertData_buffer_underflow_fix_empty_filename),
        cmocka_unit_test(test_GetAlertData_valid_filename),
        cmocka_unit_test(test_GetAlertData_filename_with_spaces),
        cmocka_unit_test(test_GetAlertData_filename_windows_crlf),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
