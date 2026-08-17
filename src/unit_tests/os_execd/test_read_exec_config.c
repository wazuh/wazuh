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
#include <unistd.h>
#include <sys/stat.h>

#include "shared.h"
#include "../../os_execd/execd.h"

#define TEST_AR_SCRIPT  "test-ar.sh"
#define TEST_AR_COMMAND AR_BINDIR "/" TEST_AR_SCRIPT

static char test_dir[PATH_MAX + 1];
static char previous_dir[PATH_MAX + 1];

/* Build the name of the entry number 'index' of the generated ar.conf */
static void ar_entry_name(char *buffer, size_t size, int index) {
    snprintf(buffer, size, "ar-cmd-%03d", index);
}

/* Write an ar.conf holding 'entries' distinct active response commands */
static void write_ar_conf(int entries) {
    char name[OS_FLSIZE];
    FILE *fp = fopen(DEFAULTAR, "w");
    int i;

    assert_non_null(fp);

    for (i = 0; i < entries; i++) {
        ar_entry_name(name, sizeof(name), i);
        assert_true(fprintf(fp, "%s - %s - 0\n", name, TEST_AR_SCRIPT) > 0);
    }

    fclose(fp);
}

/* Append a raw line to the generated ar.conf */
static void append_ar_line(const char *line) {
    FILE *fp = fopen(DEFAULTAR, "a");

    assert_non_null(fp);
    assert_true(fprintf(fp, "%s", line) > 0);
    fclose(fp);
}

static void expect_max_ar_error(void) {
    char expected_msg[OS_MAXSTR];

    snprintf(expected_msg, sizeof(expected_msg), EXEC_MAX_AR, MAX_AR, DEFAULTAR);
    expect_string(__wrap__merror, formatted_msg, expected_msg);
}

/* Assert that the entry number 'index' was loaded */
static void assert_entry_loaded(int index) {
    char name[OS_FLSIZE];
    int timeout = -1;
    char *command;

    ar_entry_name(name, sizeof(name), index);
    command = GetCommandbyName(name, &timeout);

    assert_non_null(command);
    assert_string_equal(command, TEST_AR_COMMAND);
    assert_int_equal(timeout, 0);
}

/* Assert that the entry number 'index' was not loaded */
static void assert_entry_not_loaded(int index) {
    char name[OS_FLSIZE];
    int timeout = -1;

    ar_entry_name(name, sizeof(name), index);
    assert_null(GetCommandbyName(name, &timeout));
}

static int group_setup(void **state) {
    (void)state;
    FILE *fp;

    assert_non_null(getcwd(previous_dir, sizeof(previous_dir)));

    snprintf(test_dir, sizeof(test_dir), "/tmp/wazuh_execd_arconf_XXXXXX");
    assert_non_null(mkdtemp(test_dir));
    assert_int_equal(chdir(test_dir), 0);

    /* ReadExecConfig() resolves DEFAULTAR and AR_BINDIR relative to the working directory */
    assert_int_equal(mkdir("etc", 0700), 0);
    assert_int_equal(mkdir("etc/shared", 0700), 0);
    assert_int_equal(mkdir("active-response", 0700), 0);
    assert_int_equal(mkdir(AR_BINDIR, 0700), 0);

    /* The command must exist, otherwise ReadExecConfig() discards it */
    fp = fopen(TEST_AR_COMMAND, "w");
    assert_non_null(fp);
    fclose(fp);

    return 0;
}

static int group_teardown(void **state) {
    (void)state;

    remove(DEFAULTAR);
    remove(TEST_AR_COMMAND);
    remove(AR_BINDIR);
    remove("active-response");
    remove("etc/shared");
    remove("etc");

    assert_int_equal(chdir(previous_dir), 0);
    remove(test_dir);

    return 0;
}

/* A regular configuration is loaded in full */
static void test_read_exec_config_below_limit(void **state) {
    (void)state;

    write_ar_conf(10);

    assert_int_equal(ReadExecConfig(), 1);

    assert_entry_loaded(0);
    assert_entry_loaded(9);
    assert_entry_not_loaded(10);
}

/* Exactly MAX_AR commands still fit, and no entry is reported as ignored */
static void test_read_exec_config_at_limit(void **state) {
    (void)state;

    write_ar_conf(MAX_AR);

    assert_int_equal(ReadExecConfig(), 1);

    assert_entry_loaded(0);
    assert_entry_loaded(MAX_AR - 1);
    assert_entry_not_loaded(MAX_AR);
}

/* A line that consumes no slot must not be reported as an exceeding entry */
static void test_read_exec_config_at_limit_trailing_junk(void **state) {
    (void)state;
    char expected_msg[OS_MAXSTR];

    write_ar_conf(MAX_AR);
    append_ar_line("\n");

    snprintf(expected_msg, sizeof(expected_msg), EXEC_INV_CONF, DEFAULTAR);
    expect_string(__wrap__merror, formatted_msg, expected_msg);

    assert_int_equal(ReadExecConfig(), 1);

    assert_entry_loaded(MAX_AR - 1);
    assert_entry_not_loaded(MAX_AR);
}

/* Beyond MAX_AR commands the remaining entries are reported and discarded */
static void test_read_exec_config_above_limit(void **state) {
    (void)state;

    write_ar_conf(MAX_AR + 32);

    expect_max_ar_error();

    assert_int_equal(ReadExecConfig(), 1);

    assert_entry_loaded(0);
    assert_entry_loaded(MAX_AR - 1);
    assert_entry_not_loaded(MAX_AR);
    assert_entry_not_loaded(MAX_AR + 31);
}

/* The table is reloaded on every unresolved command, so the condition is
 * reported once and not again until the configuration is corrected
 */
static void test_read_exec_config_reported_once(void **state) {
    (void)state;
    int i;

    /* Still truncated: no further report */
    for (i = 0; i < 3; i++) {
        assert_int_equal(ReadExecConfig(), 1);
    }

    /* Corrected configuration: nothing to report, and the condition is re-armed */
    write_ar_conf(MAX_AR);
    assert_int_equal(ReadExecConfig(), 1);

    /* Truncated again: reported again */
    write_ar_conf(MAX_AR + 1);
    expect_max_ar_error();
    assert_int_equal(ReadExecConfig(), 1);

    assert_entry_loaded(MAX_AR - 1);
    assert_entry_not_loaded(MAX_AR);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_exec_config_below_limit),
        cmocka_unit_test(test_read_exec_config_at_limit),
        cmocka_unit_test(test_read_exec_config_at_limit_trailing_junk),
        cmocka_unit_test(test_read_exec_config_above_limit),
        cmocka_unit_test(test_read_exec_config_reported_once),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
