/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The plain log file written by the real logger: whatever a message holds, it takes one line. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "mconf_hook.h"
#include "../../external/cJSON/cJSON.h"

#define TAG "test-tag"
/* "YYYY/MM/DD hh:mm:ss " */
#define TIMESTAMP_LENGTH 20

static char s_home[] = "/tmp/test_debug_op_XXXXXX";

static cJSON *plain_provider(const char *section) {
    (void) section;
    return cJSON_Parse("{\"log_format\":[\"plain\"]}");
}

/* The logger opens LOGFILE relative to the working directory. */
static int group_setup(void **state) {
    (void) state;

    w_mconf_hook_set(plain_provider);
    nowDaemon();
    return mkdtemp(s_home) == NULL || chdir(s_home) != 0 || mkdir("logs", 0700) != 0;
}

static int group_teardown(void **state) {
    (void) state;

    w_mconf_hook_set(NULL);
    unlink(LOGFILE);
    return rmdir("logs") != 0 || chdir("/") != 0 || rmdir(s_home) != 0;
}

static int test_setup(void **state) {
    (void) state;

    unlink(LOGFILE);
    return 0;
}

/* The whole log file after its timestamp, so the comparison also proves it has no line break but the last one. */
static void assert_logged(const char *expected) {
    struct stat log;
    char *content;
    FILE *fp;

    assert_int_equal(stat(LOGFILE, &log), 0);
    assert_int_equal(log.st_size, TIMESTAMP_LENGTH + strlen(expected));

    content = calloc(log.st_size + 1, 1);
    assert_non_null(content);
    fp = fopen(LOGFILE, "r");
    assert_non_null(fp);
    assert_int_equal(fread(content, 1, log.st_size, fp), log.st_size);
    fclose(fp);

    assert_memory_equal(content + TIMESTAMP_LENGTH, expected, strlen(expected));
    free(content);
}

static void test_plain_log_escapes_control_characters(void **state) {
    (void) state;

    _mtwarn(TAG, __FILE__, __LINE__, __func__, "first %s fourth %c end", "\r\nsecond\tthird\x1b[2K\x7f", 0);

    assert_logged(TAG ": WARNING: first \\r\\nsecond\\tthird\\x1b[2K\\x7f fourth \\x00 end\n");
}

static void test_plain_log_keeps_other_bytes(void **state) {
    (void) state;

    /* U+00E9 and U+2028 */
    _mtinfo(TAG, __FILE__, __LINE__, __func__, "%s", "caf\xc3\xa9 \\n \xe2\x80\xa8 100%");

    assert_logged(TAG ": INFO: caf\xc3\xa9 \\n \xe2\x80\xa8 100%\n");
}

static void test_plain_log_drops_trailing_line_break(void **state) {
    (void) state;

    _mterror(TAG, __FILE__, __LINE__, __func__, "first\nsecond\r\n\n");

    assert_logged(TAG ": ERROR: first\\nsecond\n");
}

static void test_plain_log_keeps_long_message(void **state) {
    (void) state;
    const char prefix[] = TAG ": INFO: ";
    const size_t length = 70000;
    char *expected = calloc(sizeof(prefix) + length + 1, 1);

    assert_non_null(expected);
    memcpy(expected, prefix, sizeof(prefix) - 1);
    memset(expected + sizeof(prefix) - 1, 'x', length);
    _mtinfo(TAG, __FILE__, __LINE__, __func__, "%s", expected + sizeof(prefix) - 1);

    expected[sizeof(prefix) - 1 + length] = '\n';
    assert_logged(expected);
    free(expected);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_plain_log_escapes_control_characters, test_setup),
        cmocka_unit_test_setup(test_plain_log_keeps_other_bytes, test_setup),
        cmocka_unit_test_setup(test_plain_log_drops_trailing_line_break, test_setup),
        cmocka_unit_test_setup(test_plain_log_keeps_long_message, test_setup),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
