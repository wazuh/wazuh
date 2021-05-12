/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include <time.h>

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"

bool w_macos_is_log_predicate_valid(char * predicate);
char ** w_macos_create_log_stream_array(char * predicate, char * level, int type);
wfd_t * w_macos_log_exec(char ** log_cmd_array, u_int32_t flags);
void w_macos_create_log_env(logreader * current);
bool w_macos_is_log_executable(void);
void w_macos_create_log_stream_env(logreader * lf);

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;

}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;

}

static int setup_file(void **state) {
    wfd_t * wfd = calloc(1, sizeof(wfd_t));

    *state = wfd;

    return 0;
}

static int teardown_file(void **state) {
    wfd_t * wfd = *state;

    free(wfd);

    return 0;
}

/* wraps */


/* w_macos_is_log_predicate_valid */
void test_w_macos_is_log_predicate_valid_empty(void ** state) {

    char predicate[] = "";

    bool ret = w_macos_is_log_predicate_valid(predicate);
    assert_false(ret);

}

void test_w_macos_is_log_predicate_valid_existing(void ** state) {

    char predicate[] = "test";

    bool ret = w_macos_is_log_predicate_valid(predicate);
    assert_true(ret);

}

/* w_macos_create_log_stream_array */
void test_w_macos_create_log_stream_array_NULL(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 0;

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_null(ret[4]);

    free_strarray(ret);

}

void test_w_macos_create_log_stream_array_level_default(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 0;

    os_strdup("default", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--level");
    assert_string_equal(ret[5], level);
    assert_null(ret[6]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_info(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 0;

    os_strdup("info", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--level");
    assert_string_equal(ret[5], level);
    assert_null(ret[6]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_debug(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 0;

    os_strdup("debug", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--level");
    assert_string_equal(ret[5], level);
    assert_null(ret[6]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_type_activity(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 1;

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_null(ret[6]);

    free_strarray(ret);

}

void test_w_macos_create_log_stream_array_type_log(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 2;

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_null(ret[6]);

    free_strarray(ret);

}

void test_w_macos_create_log_stream_array_type_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 4;

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "trace");
    assert_null(ret[6]);

    free_strarray(ret);

}

void test_w_macos_create_log_stream_array_type_activity_log(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 3;

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_null(ret[8]);

    free_strarray(ret);

}

void test_w_macos_create_log_stream_array_type_activity_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 5;

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_null(ret[8]);

    free_strarray(ret);

}

void test_w_macos_create_log_stream_array_type_log_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 6;

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_null(ret[8]);

    free_strarray(ret);

}

void test_w_macos_create_log_stream_array_type_activity_log_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 7;

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--type");
    assert_string_equal(ret[9], "trace");
    assert_null(ret[10]);

    free_strarray(ret);

}

void test_w_macos_create_log_stream_array_level_default_type_activity(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 1;

    os_strdup("default", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "default");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_default_type_log(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 2;

    os_strdup("default", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "default");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_default_type_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 4;

    os_strdup("default", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "trace");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "default");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_default_type_activity_log(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 3;

    os_strdup("default", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "default");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_default_type_activity_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 5;

    os_strdup("default", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "default");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_default_type_log_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 6;

    os_strdup("default", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "default");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_default_type_activity_log_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 7;

    os_strdup("default", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--type");
    assert_string_equal(ret[9], "trace");
    assert_string_equal(ret[10], "--level");
    assert_string_equal(ret[11], "default");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_info_type_activity(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 1;

    os_strdup("info", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "info");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_info_type_log(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 2;

    os_strdup("info", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "info");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_info_type_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 4;

    os_strdup("info", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "trace");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "info");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_info_type_activity_log(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 3;

    os_strdup("info", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "info");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_info_type_activity_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 5;

    os_strdup("info", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "info");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_info_type_log_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 6;

    os_strdup("info", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "info");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_info_type_activity_log_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 7;

    os_strdup("info", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--type");
    assert_string_equal(ret[9], "trace");
    assert_string_equal(ret[10], "--level");
    assert_string_equal(ret[11], "info");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_debug_type_activity(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 1;

    os_strdup("debug", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "debug");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_debug_type_log(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 2;

    os_strdup("debug", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "debug");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_debug_type_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 4;

    os_strdup("debug", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "trace");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "debug");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_debug_type_activity_log(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 3;

    os_strdup("debug", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "debug");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_debug_type_activity_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 5;

    os_strdup("debug", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "debug");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_debug_type_log_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 6;

    os_strdup("debug", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "debug");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);

}

void test_w_macos_create_log_stream_array_level_debug_type_activity_log_trace(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 7;

    os_strdup("debug", level);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--type");
    assert_string_equal(ret[9], "trace");
    assert_string_equal(ret[10], "--level");
    assert_string_equal(ret[11], "debug");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);

}


//PREDICADO

void test_w_macos_create_log_stream_array_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 0;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--predicate");
    assert_string_equal(ret[5], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[6]);

    free_strarray(ret);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_default_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 0;

    os_strdup("default", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--level");
    assert_string_equal(ret[5], "default");
    assert_string_equal(ret[6], "--predicate");
    assert_string_equal(ret[7], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_info_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 0;

    os_strdup("info", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--level");
    assert_string_equal(ret[5], "info");
    assert_string_equal(ret[6], "--predicate");
    assert_string_equal(ret[7], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_debug_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 0;

    os_strdup("debug", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--level");
    assert_string_equal(ret[5], "debug");
    assert_string_equal(ret[6], "--predicate");
    assert_string_equal(ret[7], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_type_activity_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 1;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--predicate");
    assert_string_equal(ret[7], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_type_log_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 2;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--predicate");
    assert_string_equal(ret[7], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_type_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 4;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "trace");
    assert_string_equal(ret[6], "--predicate");
    assert_string_equal(ret[7], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[8]);

    free_strarray(ret);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_type_activity_log_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 3;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_type_activity_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 5;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_type_log_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 6;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_type_activity_log_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 7;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--type");
    assert_string_equal(ret[9], "trace");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_default_type_activity_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 1;

    os_strdup("default", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "default");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_default_type_log_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 2;

    os_strdup("default", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "default");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_default_type_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 4;

    os_strdup("default", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "trace");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "default");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_default_type_activity_log_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 3;

    os_strdup("default", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "default");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_default_type_activity_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 5;

    os_strdup("default", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "default");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_default_type_log_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 6;

    os_strdup("default", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "default");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_default_type_activity_log_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 7;

    os_strdup("default", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--type");
    assert_string_equal(ret[9], "trace");
    assert_string_equal(ret[10], "--level");
    assert_string_equal(ret[11], "default");
    assert_string_equal(ret[12], "--predicate");
    assert_string_equal(ret[13], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[14]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_info_type_activity_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 1;

    os_strdup("info", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "info");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_info_type_log_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 2;

    os_strdup("info", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "info");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_info_type_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 4;

    os_strdup("info", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "trace");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "info");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_info_type_activity_log_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 3;

    os_strdup("info", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "info");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_info_type_activity_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 5;

    os_strdup("info", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "info");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_info_type_log_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 6;

    os_strdup("info", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "info");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_info_type_activity_log_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 7;

    os_strdup("info", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--type");
    assert_string_equal(ret[9], "trace");
    assert_string_equal(ret[10], "--level");
    assert_string_equal(ret[11], "info");
    assert_string_equal(ret[12], "--predicate");
    assert_string_equal(ret[13], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[14]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_debug_type_activity_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 1;

    os_strdup("debug", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "debug");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_debug_type_log_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 2;

    os_strdup("debug", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "debug");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_debug_type_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 4;

    os_strdup("debug", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "trace");
    assert_string_equal(ret[6], "--level");
    assert_string_equal(ret[7], "debug");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_debug_type_activity_log_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 3;

    os_strdup("debug", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "debug");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_debug_type_activity_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 5;

    os_strdup("debug", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "debug");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_debug_type_log_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 6;

    os_strdup("debug", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "log");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "trace");
    assert_string_equal(ret[8], "--level");
    assert_string_equal(ret[9], "debug");
    assert_string_equal(ret[10], "--predicate");
    assert_string_equal(ret[11], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[12]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

void test_w_macos_create_log_stream_array_level_debug_type_activity_log_trace_predicate(void ** state) {

    char * predicate = NULL;
    char * level = NULL;
    int type = 7;

    os_strdup("debug", level);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", predicate);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "stream");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--type");
    assert_string_equal(ret[5], "activity");
    assert_string_equal(ret[6], "--type");
    assert_string_equal(ret[7], "log");
    assert_string_equal(ret[8], "--type");
    assert_string_equal(ret[9], "trace");
    assert_string_equal(ret[10], "--level");
    assert_string_equal(ret[11], "debug");
    assert_string_equal(ret[12], "--predicate");
    assert_string_equal(ret[13], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(ret[14]);

    free_strarray(ret);
    os_free(level);
    os_free(predicate);

}

/* w_macos_log_exec */
void test_w_macos_log_exec_wpopenv_error(void ** state) {
    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1975): An error ocurred while calling wpopenv(): Success (0).");

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_null(ret);
    os_free(log_cmd_array);

}

void test_w_macos_log_exec_fileno_error(void ** state) {
    wfd_t * wfd = *state;
    wfd->file = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file);
    will_return(__wrap_fileno, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(1972): The file descriptor couldn't be obtained from the file pointer of the Log Stream pipe: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret, 0);
    os_free(log_cmd_array);

}

void test_w_macos_log_exec_fp_to_fd_error(void ** state) {
    wfd_t * wfd = *state;
    wfd->file = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file);
    will_return(__wrap_fileno, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(1972): The file descriptor couldn't be obtained from the file pointer of the Log Stream pipe: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret, 0);
    os_free(log_cmd_array);

}

void test_w_macos_log_exec_get_flags_error(void ** state) {
    wfd_t * wfd = *state;
    wfd->file = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, -1);

    expect_string(__wrap__merror, formatted_msg,
        "(1973): The flags couldn't be obtained from the file descriptor: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret, 0);
    os_free(log_cmd_array);

}

void test_w_macos_log_exec_set_flags_error(void ** state) {
    wfd_t * wfd = *state;
    wfd->file = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);

    will_return(__wrap_fcntl, -1);

    expect_string(__wrap__merror, formatted_msg,
        "(1974): The flags couldn't be set in the file descriptor: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret, 0);

    os_free(log_cmd_array);

}

void test_w_macos_log_exec_success(void ** state) {
    wfd_t * wfd = *state;
    wfd->file = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);

    will_return(__wrap_fcntl, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret->file,  wfd->file);
    assert_int_equal(ret->append_pool,0);
    assert_int_equal(ret->pid,0);

    os_free(log_cmd_array);

}

/* w_macos_is_log_executable */
void test_w_macos_is_log_executable_success(void ** state) {

    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 0);

    bool ret = w_macos_is_log_executable();

    assert_true(ret);

}

void test_w_macos_is_log_executable_error(void ** state) {

    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 1);

    expect_string(__wrap__merror, formatted_msg, "(1250): Error trying to execute \"/usr/bin/log\": Success (0).");

    bool ret = w_macos_is_log_executable();

    assert_false(ret);

}

/* w_macos_create_log_stream_env */
void test_w_macos_create_log_stream_env_not_executable(void ** state) {

    logreader *current = NULL;
    os_calloc(1, sizeof(logreader), current);
    current->fp = (FILE*)1;
    os_strdup("test", current->file);
    current->diff_max_size = 0;

    os_calloc(1, sizeof(w_macos_log_config_t), current->macos_log);
    current->macos_log->state = LOG_NOT_RUNNING;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", current->query);
    os_strdup("debug", current->query_level);
    current->query_type = 7;

    os_calloc(1, sizeof(wfd_t), current->macos_log->stream_wfd);
    current->macos_log->stream_wfd->file = (FILE*)1;

    // test_w_macos_is_log_executable_error
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 1);

    expect_string(__wrap__merror, formatted_msg, "(1250): Error trying to execute \"/usr/bin/log\": Success (0).");

    w_macos_create_log_stream_env(current);

    os_free(current->file);
    os_free(current->query);
    os_free(current->query_level);
    os_free(current->macos_log->stream_wfd);
    os_free(current->macos_log);
    os_free(current);

}

void test_w_macos_create_log_stream_env_log_wfd_NULL(void ** state) {

    logreader *current = NULL;
    os_calloc(1, sizeof(logreader), current);
    current->fp = (FILE*)1;
    os_strdup("test", current->file);
    current->diff_max_size = 0;

    os_calloc(1, sizeof(w_macos_log_config_t), current->macos_log);
    current->macos_log->state = LOG_NOT_RUNNING;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", current->query);
    os_strdup("debug", current->query_level);
    current->query_type = 7;

    // test_w_macos_is_log_executable_error
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 0);

    // test_w_macos_create_log_stream_array_level_debug_type_activity_log_trace_predicate

    // test_w_macos_log_exec_wpopenv_error
    will_return(__wrap_wpopenv, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1975): An error ocurred while calling wpopenv(): Success (0).");

    w_macos_create_log_stream_env(current);

    os_free(current->file);
    os_free(current->query);
    os_free(current->query_level);
    os_free(current->macos_log->stream_wfd);
    os_free(current->macos_log);
    os_free(current);

}

void test_w_macos_create_log_stream_env_success(void ** state) {

    logreader *current = NULL;
    os_calloc(1, sizeof(logreader), current);
    current->fp = (FILE*)1;
    os_strdup("test", current->file);
    current->diff_max_size = 0;

    os_calloc(1, sizeof(w_macos_log_config_t), current->macos_log);
    current->macos_log->state = LOG_NOT_RUNNING;

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", current->query);
    os_strdup("debug", current->query_level);
    current->query_type = 7;

    // test_w_macos_is_log_executable_success
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 0);

    // test_w_macos_create_log_stream_array_level_debug_type_activity_log_trace_predicate

    // test_w_macos_log_exec_success
    wfd_t * wfd = *state;
    wfd->file = (FILE*) 1234;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);

    will_return(__wrap_fcntl, 0);

    expect_string(__wrap__minfo, formatted_msg, "(1604): Monitoring MacOS logs with: /usr/bin/log stream --style syslog --type activity --type log --type trace --level debug --predicate processImagePath CONTAINS[c] 'com.apple.geod'");

    w_macos_create_log_stream_env(current);

    os_free(current->file);
    os_free(current->query);
    os_free(current->query_level);
    os_free(current->macos_log);
    os_free(current);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_macos_is_log_predicate_valid
        cmocka_unit_test(test_w_macos_is_log_predicate_valid_empty),
        cmocka_unit_test(test_w_macos_is_log_predicate_valid_existing),
        // Test w_macos_create_log_stream_array
        cmocka_unit_test(test_w_macos_create_log_stream_array_NULL),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_activity),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_log),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_activity_log),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_activity_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_log_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_activity_log_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_activity),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_log),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_activity_log),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_activity_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_log_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_activity_log_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_activity),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_log),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_activity_log),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_activity_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_log_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_activity_log_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_activity),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_log),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_activity_log),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_activity_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_log_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_activity_log_trace),
        cmocka_unit_test(test_w_macos_create_log_stream_array_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_activity_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_log_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_activity_log_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_activity_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_log_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_type_activity_log_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_activity_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_log_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_activity_log_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_activity_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_log_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_default_type_activity_log_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_activity_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_log_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_activity_log_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_activity_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_log_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_info_type_activity_log_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_activity_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_log_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_activity_log_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_activity_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_log_trace_predicate),
        cmocka_unit_test(test_w_macos_create_log_stream_array_level_debug_type_activity_log_trace_predicate),
        // Test w_macos_log_exec
        cmocka_unit_test(test_w_macos_log_exec_wpopenv_error),
        cmocka_unit_test_setup_teardown(test_w_macos_log_exec_fileno_error, setup_file, teardown_file),
        cmocka_unit_test_setup_teardown(test_w_macos_log_exec_fp_to_fd_error, setup_file, teardown_file),
        cmocka_unit_test_setup_teardown(test_w_macos_log_exec_get_flags_error, setup_file, teardown_file),
        cmocka_unit_test_setup_teardown(test_w_macos_log_exec_set_flags_error, setup_file, teardown_file),
        cmocka_unit_test_setup_teardown(test_w_macos_log_exec_success, setup_file, teardown_file),
        // Test w_macos_is_log_executable
        cmocka_unit_test(test_w_macos_is_log_executable_success),
        cmocka_unit_test(test_w_macos_is_log_executable_error),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
