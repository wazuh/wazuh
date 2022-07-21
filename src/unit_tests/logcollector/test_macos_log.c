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
#include <time.h>

#include "../../logcollector/logcollector.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/sysinfo_utils_wrappers.h"

bool w_macos_is_log_predicate_valid(char * predicate);
char ** w_macos_create_log_stream_array(char * predicate, char * level, int type);
wfd_t * w_macos_log_exec(char ** log_cmd_array, u_int32_t flags);
void w_macos_create_log_env(logreader * lf, w_sysinfo_helpers_t * global_sysinfo);
bool w_macos_is_log_executable(void);
void w_macos_create_log_stream_env(logreader * lf);
void w_macos_log_show_array_add_level(char ** log_cmd_array, size_t * log_cmd_array_idx, char * level);
char * w_macos_log_show_create_type_predicate(int type);
void w_macos_log_show_array_add_predicate(char ** log_cmd_array,
                                          size_t * log_cmd_array_idx,
                                          char * query,
                                          char * type_predicate);
char ** w_macos_create_log_show_array(char * start_date, char * query, char * level, int type);
void w_macos_set_last_log_timestamp(char * timestamp);
char * w_macos_get_last_log_timestamp();
void w_macos_set_last_log_settings(char * timestamp);
char * w_macos_get_last_log_settings();
void w_macos_create_log_show_env(logreader * lf);
void w_macos_create_log_stream_env(logreader * lf);
void w_macos_add_sierra_support(char ** log_cmd_array, size_t * log_cmd_array_idx);
pid_t w_get_first_child(pid_t parent_pid);

extern w_macos_log_vault_t macos_log_vault;

extern char * macos_codename;

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

static int teardown_settings(void **state) {
    os_free(macos_log_vault.settings);

    return 0;
}

static int setup_timestamp_null(void **state) {
    macos_log_vault.timestamp[0] = '\0';

    return 0;
}

static int teardown_timestamp_null(void **state) {
    strncpy(macos_log_vault.timestamp, "2021-04-27 12:29:25-0700", OS_LOGCOLLECTOR_TIMESTAMP_SHORT_LEN);

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

void test_w_macos_create_log_stream_array_on_sierra(void ** state) {

    int type = 0;
    char * level = NULL;
    char * predicate = NULL;
    char * backup_codename = NULL;

    /* Sets the name "Sierra" to the global variable for the system to be identified as a Sierra Version of macOS */
    if (macos_codename != NULL) {
        /* Just in case, backups the previous codename to be restored */
        w_strdup(macos_codename, backup_codename);
    }

    w_strdup(MACOS_SIERRA_CODENAME_STR, macos_codename);

    char ** ret = w_macos_create_log_stream_array(predicate, level, type);

    assert_string_equal(ret[0], SCRIPT_CMD_STR);
    assert_string_equal(ret[1], SCRIPT_CMD_ARGS);
    assert_string_equal(ret[2], SCRIPT_CMD_SINK);
    assert_string_equal(ret[3], "/usr/bin/log");
    assert_string_equal(ret[4], "stream");
    assert_string_equal(ret[5], "--style");
    assert_string_equal(ret[6], "syslog");
    assert_null(ret[7]);

    free_strarray(ret);

    os_free(macos_codename);
    if (backup_codename != NULL) {
        w_strdup(backup_codename, macos_codename);
        os_free(backup_codename);
    }
}

/* w_macos_log_exec */
void test_w_macos_log_exec_wpopenv_error(void ** state) {

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1974): An error ocurred while calling wpopenv(): Success (0).");

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_null(ret);
    os_free(log_cmd_array);

}

void test_w_macos_log_exec_fileno_error(void ** state) {

    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(1971): The file descriptor couldn't be obtained from the file pointer of the Log Stream pipe: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret, 0);
    os_free(log_cmd_array);

}

void test_w_macos_log_exec_fp_to_fd_error(void ** state) {
    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(1971): The file descriptor couldn't be obtained from the file pointer of the Log Stream pipe: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret, 0);
    os_free(log_cmd_array);

}

void test_w_macos_log_exec_get_flags_error(void ** state) {
    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, -1);

    expect_string(__wrap__merror, formatted_msg,
        "(1972): The flags couldn't be obtained from the file descriptor: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret, 0);
    os_free(log_cmd_array);

}

void test_w_macos_log_exec_set_flags_error(void ** state) {
    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);

    will_return(__wrap_fcntl, -1);

    expect_string(__wrap__merror, formatted_msg,
        "(1973): The flags couldn't be set in the file descriptor: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret, 0);

    os_free(log_cmd_array);

}

void test_w_macos_log_exec_success(void ** state) {
    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    char * log_cmd_array = NULL;
    os_strdup("log stream", log_cmd_array);
    u_int32_t flags = 0;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);

    will_return(__wrap_fcntl, 0);

    wfd_t * ret = w_macos_log_exec(&log_cmd_array, flags);

    assert_ptr_equal(ret->file_out,  wfd->file_out);
    assert_int_equal(ret->pid, 0);

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

void test_w_macos_is_log_executable_sierra_access_fail(void ** state) {

    char * backup_codename = NULL;

    if (macos_codename != NULL) {
        w_strdup(macos_codename, backup_codename);
    }

    w_strdup(MACOS_SIERRA_CODENAME_STR, macos_codename);

    expect_string(__wrap_access, __name, "/usr/bin/script");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 1);

    expect_string(__wrap__merror, formatted_msg, "(1250): Error trying to execute \"/usr/bin/script\": Success (0).");

    bool ret = w_macos_is_log_executable();

    assert_false(ret);

    os_free(macos_codename);
    if (backup_codename != NULL) {
        w_strdup(backup_codename, macos_codename);
        os_free(backup_codename);
    }
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

    os_calloc(1, sizeof(wfd_t), current->macos_log->processes.stream.wfd);
    current->macos_log->processes.stream.wfd->file_out = (FILE*)1;

    // test_w_macos_is_log_executable_error
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 1);

    expect_string(__wrap__merror, formatted_msg, "(1250): Error trying to execute \"/usr/bin/log\": Success (0).");

    w_macos_create_log_stream_env(current);

    os_free(current->file);
    os_free(current->query);
    os_free(current->query_level);
    os_free(current->macos_log->processes.stream.wfd);
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

    expect_string(__wrap__merror, formatted_msg, "(1974): An error ocurred while calling wpopenv(): Success (0).");

    w_macos_create_log_stream_env(current);

    os_free(current->file);
    os_free(current->query);
    os_free(current->query_level);
    os_free(current->macos_log->processes.stream.wfd);
    os_free(current->macos_log);
    os_free(current);

}

void test_w_macos_create_log_stream_env_complete(void ** state) {

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
    wfd->file_out = (FILE*) 1234;

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);

    will_return(__wrap_fcntl, 0);

    expect_string(__wrap__minfo, formatted_msg, "(1604): Monitoring macOS logs with: /usr/bin/log stream --style syslog --type activity --type log --type trace --level debug --predicate processImagePath CONTAINS[c] 'com.apple.geod'");

    w_macos_create_log_stream_env(current);

    os_free(current->file);
    os_free(current->query);
    os_free(current->query_level);
    os_free(current->macos_log);
    os_free(current);

}

/* w_macos_log_show_array_add_level */

void test_w_macos_log_show_array_add_level_NULL(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    char * type_predicate = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * level = NULL;

    w_macos_log_show_array_add_level(log_cmd_array, &log_cmd_array_idx, level);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_null(log_cmd_array[6]);

    free_strarray(log_cmd_array);

}

void test_w_macos_log_show_array_add_level_default(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    char * type_predicate = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * level = MACOS_LOG_LEVEL_DEFAULT_STR;

    w_macos_log_show_array_add_level(log_cmd_array, &log_cmd_array_idx, level);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_null(log_cmd_array[6]);

    free_strarray(log_cmd_array);

}

void test_w_macos_log_show_array_add_level_info(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    char * type_predicate = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * level = SHOW_INFO_OPT_STR;

    w_macos_log_show_array_add_level(log_cmd_array, &log_cmd_array_idx, level);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_string_equal(log_cmd_array[6], "--info");
    assert_null(log_cmd_array[7]);

    free_strarray(log_cmd_array);

}

void test_w_macos_log_show_array_add_level_debug(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    char * type_predicate = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * level = MACOS_LOG_LEVEL_DEBUG_STR;

    w_macos_log_show_array_add_level(log_cmd_array, &log_cmd_array_idx, level);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_string_equal(log_cmd_array[6], "--info");
    assert_string_equal(log_cmd_array[7], "--debug");
    assert_null(log_cmd_array[8]);

    free_strarray(log_cmd_array);

}

/* w_macos_log_show_create_type_predicate */

void test_w_macos_log_show_create_type_predicate_NULL(void ** state) {

    char * type_predicate = NULL;

    int type = 0;

    type_predicate = w_macos_log_show_create_type_predicate(type);

    assert_null(type_predicate);

}

void test_w_macos_log_show_create_type_predicate_activity(void ** state) {

    char * type_predicate = NULL;

    int type = 1;

    type_predicate = w_macos_log_show_create_type_predicate(type);

    assert_string_equal(type_predicate, "eventType == activityCreateEvent " \
                                        "OR eventType == activityTransitionEvent " \
                                        "OR eventType == userActionEvent");

    os_free(type_predicate);

}

void test_w_macos_log_show_create_type_predicate_log(void ** state) {

    char * type_predicate = NULL;

    int type = 2;

    type_predicate = w_macos_log_show_create_type_predicate(type);

    assert_string_equal(type_predicate, "eventType == logEvent");

    os_free(type_predicate);

}

void test_w_macos_log_show_create_type_predicate_trace(void ** state) {

    char * type_predicate = NULL;

    int type = 4;

    type_predicate = w_macos_log_show_create_type_predicate(type);

    assert_string_equal(type_predicate, "eventType == traceEvent");

    os_free(type_predicate);

}

void test_w_macos_log_show_create_type_predicate_activity_log(void ** state) {

    char * type_predicate = NULL;

    int type = 3;

    type_predicate = w_macos_log_show_create_type_predicate(type);

    assert_string_equal(type_predicate, "eventType == activityCreateEvent " \
                                        "OR eventType == activityTransitionEvent " \
                                        "OR eventType == userActionEvent " \
                                        "OR eventType == logEvent");

    os_free(type_predicate);

}

void test_w_macos_log_show_create_type_predicate_activity_trace(void ** state) {

    char * type_predicate = NULL;

    int type = 5;

    type_predicate = w_macos_log_show_create_type_predicate(type);

    assert_string_equal(type_predicate, "eventType == activityCreateEvent " \
                                        "OR eventType == activityTransitionEvent " \
                                        "OR eventType == userActionEvent " \
                                        "OR eventType == traceEvent");

    os_free(type_predicate);

}

void test_w_macos_log_show_create_type_predicate_log_trace(void ** state) {

    char * type_predicate = NULL;

    int type = 6;

    type_predicate = w_macos_log_show_create_type_predicate(type);

    assert_string_equal(type_predicate, "eventType == logEvent OR eventType == traceEvent");

    os_free(type_predicate);

}

void test_w_macos_log_show_create_type_predicate_activity_log_trace(void ** state) {

    char * type_predicate = NULL;

    int type = 7;

    type_predicate = w_macos_log_show_create_type_predicate(type);

    assert_string_equal(type_predicate, "eventType == activityCreateEvent " \
                                        "OR eventType == activityTransitionEvent " \
                                        "OR eventType == userActionEvent " \
                                        "OR eventType == logEvent " \
                                        "OR eventType == traceEvent");

    os_free(type_predicate);

}

/* w_macos_log_show_array_add_predicate */

void test_w_macos_log_show_array_add_predicate_query_and_predicate_null(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * query = NULL;

    char * type_predicate = NULL;

    w_macos_log_show_array_add_predicate(log_cmd_array, &log_cmd_array_idx, query, type_predicate);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_null(log_cmd_array[6]);

    free_strarray(log_cmd_array);

}

void test_w_macos_log_show_array_add_predicate_query_null_and_valid_predicate(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * query = NULL;

    char * type_predicate = NULL;
    os_strdup("eventType == logEvent", type_predicate);

    w_macos_log_show_array_add_predicate(log_cmd_array, &log_cmd_array_idx, query, type_predicate);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_string_equal(log_cmd_array[6], "--predicate");
    assert_string_equal(log_cmd_array[7], "eventType == logEvent");
    assert_null(log_cmd_array[8]);

    free_strarray(log_cmd_array);
    os_free(query);
    os_free(type_predicate);

}

void test_w_macos_log_show_array_add_predicate_invalid_query_and_predicate_null(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * query = NULL;
    os_strdup("", query);

    char * type_predicate = NULL;

    w_macos_log_show_array_add_predicate(log_cmd_array, &log_cmd_array_idx, query, type_predicate);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_null(log_cmd_array[6]);

    free_strarray(log_cmd_array);
    os_free(query);
    os_free(type_predicate);

}

void test_w_macos_log_show_array_add_predicate_invalid_query_valid_type_and_predicate_null(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * query = NULL;
    os_strdup("", query);

    char * type_predicate = NULL;
    w_strdup("message CONTAINS \"test\"", type_predicate);

    w_macos_log_show_array_add_predicate(log_cmd_array, &log_cmd_array_idx, query, type_predicate);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_string_equal(log_cmd_array[6], "--predicate");
    assert_string_equal(log_cmd_array[7], "message CONTAINS \"test\"");
    assert_null(log_cmd_array[8]);

    free_strarray(log_cmd_array);
    os_free(query);
    os_free(type_predicate);

}

void test_w_macos_log_show_array_add_predicate_valid_query_and_predicate_null(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * query = NULL;
    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", query);

    char * type_predicate = NULL;

    w_macos_log_show_array_add_predicate(log_cmd_array, &log_cmd_array_idx, query, type_predicate);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_string_equal(log_cmd_array[6], "--predicate");
    assert_string_equal(log_cmd_array[7], "processImagePath CONTAINS[c] 'com.apple.geod'");
    assert_null(log_cmd_array[8]);

    free_strarray(log_cmd_array);
    os_free(query);
    os_free(type_predicate);

}

void test_w_macos_log_show_array_add_predicate_valid_query_and_predicate(void ** state) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup("2021-04-27 12:29:25-0700", log_cmd_array[log_cmd_array_idx++]);

    char * query = NULL;
    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", query);

    char * type_predicate = NULL;
    os_strdup("eventType == logEvent", type_predicate);

    w_macos_log_show_array_add_predicate(log_cmd_array, &log_cmd_array_idx, query, type_predicate);

    assert_string_equal(log_cmd_array[0], "/usr/bin/log");
    assert_string_equal(log_cmd_array[1], "show");
    assert_string_equal(log_cmd_array[2], "--style");
    assert_string_equal(log_cmd_array[3], "syslog");
    assert_string_equal(log_cmd_array[4], "--start");
    assert_string_equal(log_cmd_array[5], "2021-04-27 12:29:25-0700");
    assert_string_equal(log_cmd_array[6], "--predicate");
    assert_string_equal(log_cmd_array[7], "( processImagePath CONTAINS[c] 'com.apple.geod' ) AND ( eventType == logEvent )");
    assert_null(log_cmd_array[8]);

    free_strarray(log_cmd_array);
    os_free(query);
    os_free(type_predicate);

}

/* w_macos_create_log_show_array */

void test_w_macos_create_log_show_array_complete(void ** state) {

    char start_date[25] = "2021-04-27 12:29:25-0700";

    char * query = NULL;
    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", query);

    char * level = MACOS_LOG_LEVEL_DEBUG_STR;

    int type = 7;

    char ** ret = w_macos_create_log_show_array(start_date, query, level, type);

    assert_string_equal(ret[0], "/usr/bin/log");
    assert_string_equal(ret[1], "show");
    assert_string_equal(ret[2], "--style");
    assert_string_equal(ret[3], "syslog");
    assert_string_equal(ret[4], "--start");
    assert_string_equal(ret[5], "2021-04-27 12:29:25-0700");
    assert_string_equal(ret[6], "--info");
    assert_string_equal(ret[7], "--debug");
    assert_string_equal(ret[8], "--predicate");
    assert_string_equal(ret[9], "( processImagePath CONTAINS[c] 'com.apple.geod' ) " \
                                "AND ( eventType == activityCreateEvent " \
                                "OR eventType == activityTransitionEvent " \
                                "OR eventType == userActionEvent " \
                                "OR eventType == logEvent OR eventType == traceEvent )");
    assert_null(ret[10]);

    free_strarray(ret);
    os_free(query);

}

void test_w_macos_create_log_show_array_complete_on_sierra(void ** state) {

    char start_date[25] = "2021-04-27 12:29:25-0700";

    char * query = NULL;
    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", query);

    char * level = MACOS_LOG_LEVEL_DEBUG_STR;

    int type = 7;

    char * backup_codename = NULL;

    if (macos_codename != NULL) {
        w_strdup(macos_codename, backup_codename);
    }

    w_strdup(MACOS_SIERRA_CODENAME_STR, macos_codename);

    char ** ret = w_macos_create_log_show_array(start_date, query, level, type);

    assert_string_equal(ret[0], SCRIPT_CMD_STR);
    assert_string_equal(ret[1], SCRIPT_CMD_ARGS);
    assert_string_equal(ret[2], SCRIPT_CMD_SINK);
    assert_string_equal(ret[3], "/usr/bin/log");
    assert_string_equal(ret[4], "show");
    assert_string_equal(ret[5], "--style");
    assert_string_equal(ret[6], "syslog");
    assert_string_equal(ret[7], "--start");
    assert_string_equal(ret[8], "2021-04-27 12:29:25-0700");
    assert_string_equal(ret[9], "--info");
    assert_string_equal(ret[10], "--debug");
    assert_string_equal(ret[11], "--predicate");
    assert_string_equal(ret[12], "( processImagePath CONTAINS[c] 'com.apple.geod' ) " \
                                "AND ( eventType == activityCreateEvent " \
                                "OR eventType == activityTransitionEvent " \
                                "OR eventType == userActionEvent " \
                                "OR eventType == logEvent OR eventType == traceEvent )");
    assert_null(ret[13]);

    free_strarray(ret);
    os_free(query);

    os_free(macos_codename);
    if (backup_codename != NULL) {
        w_strdup(backup_codename, macos_codename);
        os_free(backup_codename);
    }
}

/* w_macos_set_last_log_timestamp */

void test_w_macos_set_last_log_timestamp_complete(void ** state) {

    char * timestamp = NULL;
    os_strdup("2021-04-27 12:29:25-0700", timestamp);

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    w_macos_set_last_log_timestamp(timestamp);

    os_free(timestamp);

}

/* w_macos_get_last_log_timestamp */

void test_w_macos_get_last_log_timestamp_complete(void ** state) {

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    char * ret = w_macos_get_last_log_timestamp();

    assert_string_equal(ret, "2021-04-27 12:29:25-0700");

    os_free(ret);

}

/* w_macos_set_log_settings */

void test_w_macos_set_log_settings_complete(void ** state) {

    char * settings = NULL;
    os_strdup("test", settings);

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    w_macos_set_log_settings(settings);

    os_free(settings);

}

/* w_macos_get_log_settings */

void test_w_macos_get_log_settings_complete(void ** state) {

    os_strdup("test", macos_log_vault.settings);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    char * ret = w_macos_get_log_settings();

    assert_string_equal(ret, "test");

    os_free(ret);

}

/* w_macos_create_log_show_env */

void test_w_macos_create_log_show_env_timestamp_NULL(void ** state) {

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    // test_w_macos_get_last_log_timestamp_complete */

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    w_macos_create_log_show_env(lf);

    os_free(lf->macos_log);
    os_free(lf);

}

void test_w_macos_create_log_show_env_show_wfd_NULL(void ** state) {

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);
    lf->query_type = 0;

    // test_w_macos_get_last_log_timestamp_complete

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    // test_w_macos_log_exec_wpopenv_error
    will_return(__wrap_wpopenv, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1974): An error ocurred while calling wpopenv(): Success (0).");

    expect_string(__wrap__merror, formatted_msg, "(1605): Error while trying to execute `log show` as follows: " \
                                                 "/usr/bin/log show --style syslog --start 2021-04-27 12:29:25-0700 " \
                                                 "--info --debug --predicate processImagePath CONTAINS[c] 'com.apple.geod'.");

    w_macos_create_log_show_env(lf);

    os_free(lf->macos_log->processes.show.wfd);
    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);

}

void test_w_macos_create_log_show_env_success(void ** state) {

    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);
    lf->query_type = 0;

    // test_w_macos_get_last_log_timestamp_complete

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    // test_w_macos_log_exec_success
    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);

    will_return(__wrap_fcntl, 0);

    expect_string(__wrap__minfo, formatted_msg, "(1603): Monitoring macOS old logs with: " \
                                                 "/usr/bin/log show --style syslog --start 2021-04-27 12:29:25-0700 " \
                                                 "--info --debug --predicate processImagePath CONTAINS[c] 'com.apple.geod'.");

    w_macos_create_log_show_env(lf);

    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);

}

/* w_macos_create_log_stream_env */
void test_w_macos_create_log_stream_env_show_wfd_NULL(void ** state) {

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);
    lf->query_type = 0;

    // test_w_macos_log_exec_wpopenv_error
    will_return(__wrap_wpopenv, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1974): An error ocurred while calling wpopenv(): Success (0).");

    expect_string(__wrap__merror, formatted_msg, "(1606): Error while trying to execute `log stream` as follows: " \
                                                 "/usr/bin/log stream --style syslog --level debug " \
                                                 "--predicate processImagePath CONTAINS[c] 'com.apple.geod'.");

    w_macos_create_log_stream_env(lf);

    os_free(lf->macos_log->processes.show.wfd);
    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);

}

void test_w_macos_create_log_stream_env_success(void ** state) {

    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);
    lf->query_type = 0;

    // test_w_macos_log_exec_success
    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);

    will_return(__wrap_fcntl, 0);

    expect_string(__wrap__minfo, formatted_msg, "(1604): Monitoring macOS logs with: " \
                                                 "/usr/bin/log stream --style syslog --level debug " \
                                                 "--predicate processImagePath CONTAINS[c] 'com.apple.geod'.");

    w_macos_create_log_stream_env(lf);

    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);

}

void test_w_macos_create_log_env_codename_null_only_future (void ** state) {

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);
    lf->query_type = 0;
    lf->future = 1; // No past events

    will_return(__wrap_w_get_os_codename, NULL);

    // test_w_macos_is_log_executable_success
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 0);

    will_return(__wrap_wpopenv, NULL);

    expect_any(__wrap__merror, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    w_macos_create_log_env(lf, NULL);

    os_free(lf->macos_log->current_settings);
    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);
}

void test_w_macos_create_log_env_codename_not_null_only_future (void ** state) {

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);
    lf->query_type = 0;
    lf->future = 1; // No past events

    will_return(__wrap_w_get_os_codename, "macTEST");

    // test_w_macos_is_log_executable_success
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Creating environment for macOS macTEST.");

    will_return(__wrap_wpopenv, NULL);

    expect_any(__wrap__merror, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    w_macos_create_log_env(lf, NULL);

    os_free(lf->macos_log->current_settings);
    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);
}

void test_w_macos_create_log_env_codename_null_previous_settings_null (void ** state) {

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);
    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);

    lf->query_type = 0;
    lf->future = 0; // Look for past events
    macos_log_vault.settings = NULL;

    will_return(__wrap_w_get_os_codename, NULL);

    // test_w_macos_is_log_executable_success
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 0);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_wpopenv, NULL);

    expect_any(__wrap__merror, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    w_macos_create_log_env(lf, NULL);

    os_free(lf->macos_log->current_settings);
    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);
}

void test_w_macos_create_log_env_codename_null_current_and_previous_settings_missmatch (void ** state) {

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);
    lf->query_type = 0;
    lf->future = 0; // Look for past events

    /* Forces the missmatch */
    w_strdup("some random setting", macos_log_vault.settings);

    will_return(__wrap_w_get_os_codename, NULL);

    // test_w_macos_is_log_executable_success
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 0);

    /* For reading the */
    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Current predicate differs from the stored one. Discarding old events.");

    will_return(__wrap_wpopenv, NULL);

    expect_any(__wrap__merror, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    w_macos_create_log_env(lf, NULL);

    os_free(macos_log_vault.settings);
    os_free(lf->macos_log->current_settings);
    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);
}

void test_w_macos_create_log_env_codename_null_settings_match (void ** state) {

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    os_calloc(1, sizeof(w_macos_log_config_t), lf->macos_log);

    os_strdup("processImagePath CONTAINS[c] 'com.apple.geod'", lf->query);
    os_strdup(MACOS_LOG_LEVEL_DEBUG_STR, lf->query_level);
    lf->query_type = 0;
    lf->future = 0; // Look for past events
    w_strdup("/usr/bin/log stream --style syslog --level debug --predicate processImagePath CONTAINS[c] 'com.apple.geod'", macos_log_vault.settings);

    bzero(macos_log_vault.timestamp, OS_LOGCOLLECTOR_TIMESTAMP_SHORT_LEN + 1); // Prevents log show execution

    will_return(__wrap_w_get_os_codename, NULL);

    // test_w_macos_is_log_executable_success
    expect_string(__wrap_access, __name, "/usr/bin/log");
    expect_value(__wrap_access, __type, 1);
    will_return(__wrap_access, 0);

    // w_macos_get_log_settings locks
    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    // w_macos_get_last_log_timestamp locks
    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_wpopenv, NULL);

    expect_any(__wrap__merror, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    w_macos_create_log_env(lf, NULL);

    os_free(macos_log_vault.settings);
    os_free(lf->macos_log->current_settings);
    os_free(lf->query_level);
    os_free(lf->query);
    os_free(lf->macos_log);
    os_free(lf);
}

void test_w_macos_add_sierra_support(void ** state) {

    size_t index = 0;
    char ** log_cmd_array_idx = NULL;
    os_calloc(4, sizeof(char *), log_cmd_array_idx);

    w_macos_add_sierra_support(log_cmd_array_idx, &index);

    assert_int_equal(index, 3);
    assert_string_equal(log_cmd_array_idx[0], SCRIPT_CMD_STR);
    assert_string_equal(log_cmd_array_idx[1], SCRIPT_CMD_ARGS);
    assert_string_equal(log_cmd_array_idx[2], SCRIPT_CMD_SINK);

    free_strarray(log_cmd_array_idx);
}

void test_w_get_first_child_NULL(void ** state) {

    will_return(__wrap_w_get_process_childs, NULL);

    assert_int_equal(w_get_first_child(0), 0);
}

void test_w_get_first_child_non_null_non_zero(void ** state) {

    pid_t * pid_array = NULL;

    os_calloc(4, sizeof(pid_t), pid_array);

    pid_array[0] = 7;
    pid_array[1] = 9;
    pid_array[2] = 11;
    pid_array[3] = 0;

    will_return(__wrap_w_get_process_childs, pid_array);

    assert_int_equal(w_get_first_child(0), 7);
}

void test_w_get_first_child_non_null_zero(void ** state) {

    pid_t * pid_array = NULL;

    os_calloc(4, sizeof(pid_t), pid_array);

    pid_array[0] = 0;
    pid_array[1] = 9;
    pid_array[2] = 11;
    pid_array[3] = 20;

    will_return(__wrap_w_get_process_childs, pid_array);

    assert_int_equal(w_get_first_child(0), 0);
}

// Test w_macos_set_is_valid_data
void test_w_macos_set_is_valid_data_ok(void ** state) {

    bool bak_is_valid_data = macos_log_vault.is_valid_data;
    macos_log_vault.is_valid_data = false;

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);
    w_macos_set_is_valid_data(true);

    assert_true(macos_log_vault.is_valid_data);
    macos_log_vault.is_valid_data = bak_is_valid_data;

}

// Test w_macos_get_is_valid_data
void test_w_macos_get_is_valid_data_ok(void ** state) {

    bool bak_is_valid_data = macos_log_vault.is_valid_data;
    macos_log_vault.is_valid_data = false;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    assert_false(w_macos_get_is_valid_data());
    macos_log_vault.is_valid_data = bak_is_valid_data;
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
        cmocka_unit_test(test_w_macos_create_log_stream_array_on_sierra),
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
        cmocka_unit_test(test_w_macos_is_log_executable_sierra_access_fail),
        // Test w_macos_log_show_array_add_level
        cmocka_unit_test(test_w_macos_log_show_array_add_level_NULL),
        cmocka_unit_test(test_w_macos_log_show_array_add_level_default),
        cmocka_unit_test(test_w_macos_log_show_array_add_level_info),
        cmocka_unit_test(test_w_macos_log_show_array_add_level_debug),
        // Test w_macos_log_show_create_type_predicate
        cmocka_unit_test(test_w_macos_log_show_create_type_predicate_NULL),
        cmocka_unit_test(test_w_macos_log_show_create_type_predicate_activity),
        cmocka_unit_test(test_w_macos_log_show_create_type_predicate_log),
        cmocka_unit_test(test_w_macos_log_show_create_type_predicate_trace),
        cmocka_unit_test(test_w_macos_log_show_create_type_predicate_activity_log),
        cmocka_unit_test(test_w_macos_log_show_create_type_predicate_activity_trace),
        cmocka_unit_test(test_w_macos_log_show_create_type_predicate_log_trace),
        cmocka_unit_test(test_w_macos_log_show_create_type_predicate_activity_log_trace),
        // Test w_macos_log_show_array_add_predicate
        cmocka_unit_test(test_w_macos_log_show_array_add_predicate_query_and_predicate_null),
        cmocka_unit_test(test_w_macos_log_show_array_add_predicate_query_null_and_valid_predicate),
        cmocka_unit_test(test_w_macos_log_show_array_add_predicate_invalid_query_and_predicate_null),
        cmocka_unit_test(test_w_macos_log_show_array_add_predicate_invalid_query_valid_type_and_predicate_null),
        cmocka_unit_test(test_w_macos_log_show_array_add_predicate_valid_query_and_predicate_null),
        cmocka_unit_test(test_w_macos_log_show_array_add_predicate_valid_query_and_predicate),
        // Test w_macos_create_log_show_array
        cmocka_unit_test(test_w_macos_create_log_show_array_complete),
        cmocka_unit_test(test_w_macos_create_log_show_array_complete_on_sierra),
        // Test w_macos_set_last_log_timestamp
        cmocka_unit_test(test_w_macos_set_last_log_timestamp_complete),
        // Test w_macos_get_last_log_timestamp
        cmocka_unit_test(test_w_macos_get_last_log_timestamp_complete),
        // Test w_macos_set_log_settings
        cmocka_unit_test_teardown(test_w_macos_set_log_settings_complete, teardown_settings),
        // Test w_macos_get_log_settings
        cmocka_unit_test_teardown(test_w_macos_get_log_settings_complete, teardown_settings),
        // Test w_macos_create_log_show_env
        cmocka_unit_test_setup_teardown(test_w_macos_create_log_show_env_timestamp_NULL, setup_timestamp_null, teardown_timestamp_null),
        cmocka_unit_test(test_w_macos_create_log_show_env_show_wfd_NULL),
        cmocka_unit_test_setup_teardown(test_w_macos_create_log_show_env_success, setup_file, teardown_file),
        // Test w_macos_create_log_stream_env
        cmocka_unit_test(test_w_macos_create_log_stream_env_show_wfd_NULL),
        cmocka_unit_test_setup_teardown(test_w_macos_create_log_stream_env_success, setup_file, teardown_file),
        // Test w_macos_create_log_env
        cmocka_unit_test(test_w_macos_create_log_env_codename_null_only_future),
        cmocka_unit_test(test_w_macos_create_log_env_codename_not_null_only_future),
        cmocka_unit_test(test_w_macos_create_log_env_codename_null_previous_settings_null),
        cmocka_unit_test(test_w_macos_create_log_env_codename_null_current_and_previous_settings_missmatch),
        cmocka_unit_test(test_w_macos_create_log_env_codename_null_settings_match),
        // Test w_macos_add_sierra_support
        cmocka_unit_test(test_w_macos_add_sierra_support),
        // Test w_get_first_child
        cmocka_unit_test(test_w_get_first_child_NULL),
        cmocka_unit_test(test_w_get_first_child_non_null_non_zero),
        cmocka_unit_test(test_w_get_first_child_non_null_zero),
        // Test w_macos_set_is_valid_data
        cmocka_unit_test(test_w_macos_set_is_valid_data_ok),
        // Test w_macos_get_is_valid_data
        cmocka_unit_test(test_w_macos_get_is_valid_data_ok),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
