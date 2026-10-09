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

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

#include "../headers/shared.h"
#include "../monitord/monitord.h"

#define CDAY  7
#define CMON  9
#define CYEAR 2026

static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/* Rotated suffix state for each manage_log() call */
typedef enum
{
    ROT_END,    /* -NNN does not exist: walk stops */
    ROT_EMPTY,  /* -NNN exists but is empty: walk stops */
    ROT_FULL    /* -NNN exists with content: compressed */
} rot_state_t;

/* wrappers */

void __wrap_OS_SignLog(const char *logfile, const char *logfile_old, const char *ext) {
    check_expected(logfile);
    check_expected(logfile_old);
    check_expected(ext);
}

void __wrap_OS_CompressLog(const char *logfile) {
    check_expected(logfile);
}

/* helpers */

/* expect_string() keeps the pointer, so expected paths must outlive the helper. */
static char path_pool[64][2 * OS_FLSIZE];
static int path_pool_used;

static char *next_path(void) {
    assert_true(path_pool_used < (int)(sizeof(path_pool) / sizeof(path_pool[0])));
    return path_pool[path_pool_used++];
}

static void expect_manage_log(const char *logdir, const char *tag, const char *ext, const rot_state_t *rot) {
    char *base = next_path();
    char *path;

    snprintf(base, sizeof(path_pool[0]), "%s/%d/%s/ossec-%s-%02d", logdir, CYEAR, months[CMON], tag, CDAY);

    expect_string(__wrap_OS_SignLog, logfile, base);
    expect_any(__wrap_OS_SignLog, logfile_old);
    expect_string(__wrap_OS_SignLog, ext, ext);

    if (!mond.compress) {
        return;
    }

    path = next_path();
    snprintf(path, sizeof(path_pool[0]), "%s.%s", base, ext);
    expect_string(__wrap_OS_CompressLog, logfile, path);

    for (int i = 0;; i++) {
        path = next_path();
        snprintf(path, sizeof(path_pool[0]), "%s-%.3d.%s", base, i + 1, ext);

        if (rot[i] == ROT_END) {
            expect_string(__wrap_IsFile, file, path);
            will_return(__wrap_IsFile, -1);
            break;
        }

        expect_string(__wrap_IsFile, file, path);
        will_return(__wrap_IsFile, 0);

        if (rot[i] == ROT_EMPTY) {
            expect_FileSize(path, 0);
            break;
        }

        expect_FileSize(path, 1024);
        expect_string(__wrap_OS_CompressLog, logfile, path);
    }
}

static void expect_manage_files(const rot_state_t *rot) {
    expect_manage_log(EVENTS, "archive", "log", rot);
    expect_manage_log(EVENTS, "archive", "json", rot);
    expect_manage_log(ALERTS, "alerts", "log", rot);
    expect_manage_log(ALERTS, "alerts", "json", rot);
    expect_manage_log(FWLOGS, "firewall", "log", rot);
}

/* setup/teardown */

static int setup_compress(void **state) {
    path_pool_used = 0;
    test_mode = 1;
    mond.compress = 1;
    return 0;
}

static int setup_no_compress(void **state) {
    path_pool_used = 0;
    test_mode = 1;
    mond.compress = 0;
    return 0;
}

static int teardown(void **state) {
    test_mode = 0;
    mond.compress = 0;
    return 0;
}

/* tests */

void test_manage_files_compress_rotated(void **state) {
    const rot_state_t rot[] = {ROT_FULL, ROT_FULL, ROT_END};

    expect_manage_files(rot);

    manage_files(CDAY, CMON, CYEAR);
}

void test_manage_files_compress_base_only(void **state) {
    const rot_state_t rot[] = {ROT_END};

    expect_manage_files(rot);

    manage_files(CDAY, CMON, CYEAR);
}

/* A missing -002 ends the walk even if -003 exists: -003 must never be looked up. */
void test_manage_files_compress_gap(void **state) {
    const rot_state_t rot[] = {ROT_FULL, ROT_END};

    expect_manage_files(rot);

    manage_files(CDAY, CMON, CYEAR);
}

void test_manage_files_compress_empty_rotated(void **state) {
    const rot_state_t rot[] = {ROT_FULL, ROT_EMPTY};

    expect_manage_files(rot);

    manage_files(CDAY, CMON, CYEAR);
}

void test_manage_files_no_compress(void **state) {
    expect_manage_files(NULL);

    manage_files(CDAY, CMON, CYEAR);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_manage_files_compress_rotated, setup_compress, teardown),
        cmocka_unit_test_setup_teardown(test_manage_files_compress_base_only, setup_compress, teardown),
        cmocka_unit_test_setup_teardown(test_manage_files_compress_gap, setup_compress, teardown),
        cmocka_unit_test_setup_teardown(test_manage_files_compress_empty_rotated, setup_compress, teardown),
        cmocka_unit_test_setup_teardown(test_manage_files_no_compress, setup_no_compress, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
