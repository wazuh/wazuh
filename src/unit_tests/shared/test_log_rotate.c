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
#include <errno.h>
#include <time.h>

#include "shared.h"
#include "log_rotate.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"

// 2026-10-14 12:00:00 UTC, so the daily rotation archives 2026-10-13
#define TEST_NOW ((time_t)1791979200)

#define MONTH_DIR "logs/wazuh/2026/Oct"

#ifdef TEST_AGENT
#define PLAIN_LOG "logs/ossec.log"
#define JSON_LOG "logs/ossec.json"
#define ROTATED(ext) MONTH_DIR "/ossec-13." ext
#else
#define PLAIN_LOG "logs/wazuh-manager.log"
#define JSON_LOG "logs/wazuh-manager.json"
#define ROTATED(ext) MONTH_DIR "/wazuh-13." ext
#endif

/* wrappers */

void __wrap_OS_CompressLog(const char * logfile) {
    check_expected(logfile);
}

DIR * __wrap_wopendir(const char * name) {
    check_expected(name);
    errno = ENOENT;
    return NULL;
}

/* setup/teardown */

static int setup_group(void ** state) {
    setenv("TZ", "UTC", 1);
    tzset();
    return 0;
}

/* helpers */

static void expect_rotation_start() {
    will_return(__wrap_time, TEST_NOW);
    expect_string(__wrap__minfo, formatted_msg, "Running daily rotation of log files.");

    expect_string(__wrap_IsDir, file, "logs/wazuh/2026");
    will_return(__wrap_IsDir, 0);
    expect_string(__wrap_IsDir, file, MONTH_DIR);
    will_return(__wrap_IsDir, 0);
}

static void expect_free_slot(const char * path, const char * compressed) {
    expect_string(__wrap_IsFile, file, compressed);
    will_return(__wrap_IsFile, -1);
    expect_string(__wrap_IsFile, file, path);
    will_return(__wrap_IsFile, -1);
}

static void expect_plain_log_rotation() {
    expect_free_slot(ROTATED("log"), ROTATED("log.gz"));
    expect_string(__wrap_IsFile, file, PLAIN_LOG);
    will_return(__wrap_IsFile, 0);
    expect_rename_ex(PLAIN_LOG, ROTATED("log"), 0);
    expect_string(__wrap_OS_CompressLog, logfile, ROTATED("log"));
}

static void expect_rotation_end() {
    expect_string(__wrap__minfo, formatted_msg, "Starting new log after rotation.");

    will_return(__wrap_time, TEST_NOW);
    expect_string(__wrap_wopendir, name, "logs/wazuh");
    expect_string(__wrap__merror, formatted_msg,
                  "Couldn't open directory 'logs/wazuh' to delete old logs: No such file or directory");
}

/* tests */

static void test_w_rotate_log_daily_skips_empty_json(void ** state) {
    expect_rotation_start();
    expect_plain_log_rotation();

    expect_FileSize(JSON_LOG, 0);

    expect_rotation_end();

    w_rotate_log(1, 31, 1, 0, 12);
}

static void test_w_rotate_log_daily_skips_missing_json(void ** state) {
    expect_rotation_start();
    expect_plain_log_rotation();

    expect_FileSize(JSON_LOG, -1);

    expect_rotation_end();

    w_rotate_log(1, 31, 1, 0, 12);
}

static void test_w_rotate_log_daily_rotates_json_with_content(void ** state) {
    expect_rotation_start();
    expect_plain_log_rotation();

    expect_FileSize(JSON_LOG, 128);
    expect_free_slot(ROTATED("json"), ROTATED("json.gz"));
    expect_string(__wrap_IsFile, file, JSON_LOG);
    will_return(__wrap_IsFile, 0);
    expect_rename_ex(JSON_LOG, ROTATED("json"), 0);
    expect_string(__wrap_OS_CompressLog, logfile, ROTATED("json"));

    expect_rotation_end();

    w_rotate_log(1, 31, 1, 0, 12);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_rotate_log_daily_skips_empty_json),
        cmocka_unit_test(test_w_rotate_log_daily_skips_missing_json),
        cmocka_unit_test(test_w_rotate_log_daily_rotates_json_with_content),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
