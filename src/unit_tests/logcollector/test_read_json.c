/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "logcollector.h"
#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

/* Globals */
extern int maximum_lines;

/* Setup & Teardown */

static int group_setup(void **state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void **state) {
    test_mode = 0;
    return 0;
}

/* Wraps */

int __wrap_can_read() {
    return mock_type(int);
}

extern int __real_feof(FILE * stream);
int __wrap_feof(FILE * stream) {
    if (test_mode) {
        return mock_type(int);
    }
    return __real_feof(stream);
}

bool __wrap_w_get_hash_context(logreader *lf, EVP_MD_CTX **context, int64_t position) {
    bool valid = mock_type(bool);
    if (valid) {
        EVP_DigestInit(*context, EVP_sha1());
    }
    return valid;
}

/* Checks the stored hash covers exactly the given bytes */
int __wrap_w_update_file_status(const char *path, int64_t pos, EVP_MD_CTX *context) {
    const char *hashed = mock_ptr_type(const char *);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned char expected_md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    check_expected(pos);
    EVP_DigestFinal_ex(context, md, &md_len);
    EVP_Digest(hashed, strlen(hashed), expected_md, NULL, EVP_sha1(), NULL);
    assert_memory_equal(md, expected_md, md_len);
    EVP_MD_CTX_free(context);
    return 0;
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *log_target, char queue_mq) {
    check_expected(str);
    return 0;
}

bool __wrap_check_ignore_and_restrict(const char *ignore_regex, const char *restrict_regex, const char *str) {
    return mock_type(bool);
}

/* Helpers */

static void expect_line(const char *line, int64_t end) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, end);
}

static void expect_sent(const char *str, int64_t end) {
    will_return(__wrap_check_ignore_and_restrict, false);
    expect_string(__wrap_w_msg_hash_queues_push, str, str);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, end);
}

/*
 * Input: {"n":1}, a line longer than the read buffer, {"n":3}, {"n":4}.
 * The long line is dropped whole, reported with its own length, and every other line is sent.
 */
static void run_long_line(bool long_line_ignored) {
    logreader lf = { .file = "test" };
    int rc;
    const int64_t chunk_len = OS_MAXSTR - OS_LOG_HEADER - 1;
    const int64_t long_end = 8 + chunk_len + 5;
    char *chunk = malloc(chunk_len + 1);
    char expected_msg[OS_SIZE_256];

    maximum_lines = 0;
    sample_log_length = 6;

    memset(chunk, 'x', chunk_len);
    memcpy(chunk, "{\"n\":2", 6);
    chunk[chunk_len] = '\0';
    snprintf(expected_msg, sizeof(expected_msg), "Large message size from file 'test' (length = %ld): '{\"n\":2'...", (long)(chunk_len + 5));

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, false);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    expect_line("{\"n\":1}\n", 8);
    expect_sent("{\"n\":1}", 8);

    expect_line(chunk, 8 + chunk_len);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "xx\"}\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, long_end);

    will_return(__wrap_feof, 0);

    expect_string(__wrap__merror, formatted_msg, expected_msg);

    will_return(__wrap_check_ignore_and_restrict, long_line_ignored);

    expect_line("{\"n\":3}\n", long_end + 8);
    expect_sent("{\"n\":3}", long_end + 8);

    expect_line("{\"n\":4}\n", long_end + 16);
    expect_sent("{\"n\":4}", long_end + 16);

    will_return(__wrap_can_read, 0);

    read_json(&lf, &rc, 0);

    free(chunk);
}

/*
 * Input: {"n":1}, then a line longer than the read buffer whose end is not written yet.
 * Nothing is sent or reported for it, and the next read starts again at that line.
 */
static void run_long_line_incomplete(bool hash) {
    logreader lf = { .file = "test" };
    int rc;
    const int64_t chunk_len = OS_MAXSTR - OS_LOG_HEADER - 1;
    char *chunk = malloc(chunk_len + 1);

    maximum_lines = 0;

    memset(chunk, 'x', chunk_len);
    chunk[chunk_len] = '\0';

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, hash);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    expect_line("{\"n\":1}\n", 8);
    expect_sent("{\"n\":1}", 8);

    expect_line(chunk, 8 + chunk_len);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "partial");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 8 + chunk_len + 7);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_feof, 1);

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 8);
    will_return(__wrap_w_fseek, 0);

    if (hash) {
        expect_value(__wrap_w_update_file_status, pos, 8);
        will_return(__wrap_w_update_file_status, "{\"n\":1}\n");
    }

    read_json(&lf, &rc, 0);

    free(chunk);
}

void test_long_line_incomplete_waits(void **state) {
    run_long_line_incomplete(false);
}

void test_long_line_incomplete_hash_rolled_back(void **state) {
    run_long_line_incomplete(true);
}

/* Tests */

void test_long_line_not_json_next_lines_sent(void **state) {
    run_long_line(false);
}

void test_long_line_ignored_next_lines_sent(void **state) {
    run_long_line(true);
}

/* Reads one complete line with the given labels and checks the message that is sent */
static void run_labels(wlabel_t *labels, const char *line, const char *expected) {
    logreader lf = { .file = "test", .labels = labels };
    int rc;
    const int64_t end = strlen(line);

    maximum_lines = 0;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, false);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    expect_line(line, end);
    expect_sent(expected, end);

    will_return(__wrap_can_read, 0);

    read_json(&lf, &rc, 0);
}

/*
 * Input: a line with members named like the configured labels, in any case.
 * The configured labels replace them, and the other members are kept.
 */
void test_labels_take_precedence(void **state) {
    wlabel_t labels[] = {
        { .key = "env", .value = "production" },
        { .key = "tags.team", .value = "blue" },
        { .key = NULL }
    };

    run_labels(labels,
               "{\"ENV\":\"test\",\"msg\":\"hello\",\"tags\":{\"team\":\"red\",\"id\":1}}\n",
               "{\"msg\":\"hello\",\"tags\":{\"id\":1,\"team\":\"blue\"},\"env\":\"production\"}");
}

/*
 * Input: a line with a member whose name holds the dotted label key.
 * It is removed, so it cannot shadow the nested label once analysisd flattens the event.
 */
void test_labels_dotted_member_name(void **state) {
    wlabel_t labels[] = {
        { .key = "tags.team", .value = "blue" },
        { .key = NULL }
    };

    run_labels(labels,
               "{\"tags.team\":\"red\",\"msg\":\"hello\"}\n",
               "{\"msg\":\"hello\",\"tags\":{\"team\":\"blue\"}}");
}

/*
 * Input: a line with an "app" object, and the labels "app" and "app.env", which collide with each other.
 * The line's member is replaced, and the first label wins over the second, as when the line has no such member.
 */
void test_labels_colliding_first_wins(void **state) {
    wlabel_t labels[] = {
        { .key = "app", .value = "x" },
        { .key = "app.env", .value = "prod" },
        { .key = NULL }
    };

    run_labels(labels,
               "{\"app\":{\"env\":\"line\",\"v\":1},\"msg\":\"m\"}\n",
               "{\"msg\":\"m\",\"app\":\"x\"}");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_long_line_not_json_next_lines_sent),
        cmocka_unit_test(test_long_line_ignored_next_lines_sent),
        cmocka_unit_test(test_long_line_incomplete_waits),
        cmocka_unit_test(test_long_line_incomplete_hash_rolled_back),
        cmocka_unit_test(test_labels_take_precedence),
        cmocka_unit_test(test_labels_dotted_member_name),
        cmocka_unit_test(test_labels_colliding_first_wins),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
