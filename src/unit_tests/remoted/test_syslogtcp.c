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

#include "../../remoted/remoted.h"
#include "../../headers/shared.h"
#include "../../os_net/os_net.h"
#include "../wrappers/wazuh/shared/mq_op_wrappers.h"

/* Symbols under test (made non-static by WAZUH_UNIT_TESTING). */
size_t w_get_pri_header_len(const char * syslog_msg);
void send_buffer(sockbuffer_t *socket_buffer, char *srcip);

/* The send_buffer helper reads logr.m_queue as an opaque fd to pass to
 * SendMSG, which is wrapped in these tests — the actual value is unused. */
remoted logr;

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* --------------------------------------------------------------------
 *   w_get_pri_header_len (existing tests, unchanged)
 * -------------------------------------------------------------------- */

void test_w_get_pri_header_len_null(void ** state) {
    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len(NULL);
    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_no_pri(void ** state) {
    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len("test log");
    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_w_pri(void ** state) {
    const ssize_t expected_retval = 4;
    ssize_t retval = w_get_pri_header_len("<18>test log");
    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_not_end(void ** state) {
    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len("<18 test log");
    assert_int_equal(retval, expected_retval);
}

/* --------------------------------------------------------------------
 *   send_buffer — framing parser
 * -------------------------------------------------------------------- */

/* Populate a sockbuffer_t from a literal C string. */
static void fill_buffer(sockbuffer_t *buf, const char *bytes, size_t len) {
    memcpy(buf->data, bytes, len);
    buf->data_len = len;
    buf->data[len] = '\0';
}

/* ---- Newline-delimited framing (RFC 6587 §3.4.2) ---- */

void test_send_buffer_empty(void ** state) {
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    storage[0] = '\0';

    send_buffer(&buf, "10.0.0.1");
    assert_int_equal(buf.data_len, 0);
}

void test_send_buffer_single_newline_message(void ** state) {
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    const char *input = "<13>Apr 10 12:00:00 host test message\n";
    fill_buffer(&buf, input, strlen(input));

    /* PRI header "<13>" is 4 bytes, so the forwarded message skips it. */
    expect_SendMSG_call("Apr 10 12:00:00 host test message", "10.0.0.1", SYSLOG_MQ, 0);

    send_buffer(&buf, "10.0.0.1");
    assert_int_equal(buf.data_len, 0);
}

void test_send_buffer_multiple_newline_messages(void ** state) {
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    const char *input = "<13>first message\n<14>second message\n<15>third\n";
    fill_buffer(&buf, input, strlen(input));

    expect_SendMSG_call("first message", "10.0.0.1", SYSLOG_MQ, 0);
    expect_SendMSG_call("second message", "10.0.0.1", SYSLOG_MQ, 0);
    expect_SendMSG_call("third", "10.0.0.1", SYSLOG_MQ, 0);

    send_buffer(&buf, "10.0.0.1");
    assert_int_equal(buf.data_len, 0);
}

void test_send_buffer_partial_newline_message(void ** state) {
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    const char *input = "<13>complete\n<14>incomplete no newline";
    fill_buffer(&buf, input, strlen(input));

    expect_SendMSG_call("complete", "10.0.0.1", SYSLOG_MQ, 0);

    send_buffer(&buf, "10.0.0.1");

    /* The incomplete trailing record should be preserved for the next read. */
    assert_int_equal(buf.data_len, strlen("<14>incomplete no newline"));
    assert_memory_equal(buf.data, "<14>incomplete no newline", buf.data_len);
}

/* ---- Octet-counting framing (RFC 5425 / RFC 6587 §3.4.1) ---- */

void test_send_buffer_single_octet_counted(void ** state) {
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    /* "25 <13>hello from fortigate" — 25 bytes after the space. */
    const char *input = "25 <13>hello from fortigate";
    fill_buffer(&buf, input, strlen(input));

    expect_SendMSG_call("hello from fortigate", "10.0.0.1", SYSLOG_MQ, 0);

    send_buffer(&buf, "10.0.0.1");
    assert_int_equal(buf.data_len, 0);
}

void test_send_buffer_multiple_octet_counted(void ** state) {
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    /* Two back-to-back octet-counted messages, no newlines. */
    const char *input = "10 <13>first!11 <14>second!";
    fill_buffer(&buf, input, strlen(input));

    expect_SendMSG_call("first!", "10.0.0.1", SYSLOG_MQ, 0);
    expect_SendMSG_call("second!", "10.0.0.1", SYSLOG_MQ, 0);

    send_buffer(&buf, "10.0.0.1");
    assert_int_equal(buf.data_len, 0);
}

void test_send_buffer_partial_octet_counted(void ** state) {
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    /* Header says 25 bytes but only 12 have arrived so far. */
    const char *input = "25 <13>hello";
    fill_buffer(&buf, input, strlen(input));

    /* No SendMSG expected — the record is incomplete. */
    send_buffer(&buf, "10.0.0.1");

    assert_int_equal(buf.data_len, strlen(input));
    assert_memory_equal(buf.data, input, buf.data_len);
}

void test_send_buffer_mixed_framings(void ** state) {
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    /* Octet-counted record followed by a newline-delimited one. */
    const char *input = "10 <13>first!<14>second\n";
    fill_buffer(&buf, input, strlen(input));

    expect_SendMSG_call("first!", "10.0.0.1", SYSLOG_MQ, 0);
    expect_SendMSG_call("second", "10.0.0.1", SYSLOG_MQ, 0);

    send_buffer(&buf, "10.0.0.1");
    assert_int_equal(buf.data_len, 0);
}

void test_send_buffer_newline_starts_with_lt(void ** state) {
    /* A conforming RFC 3164/5424 message begins with '<', so the parser must
     * NOT treat it as octet-counted framing even though the remaining bytes
     * could look like a number later on. */
    char storage[OS_MAXSTR + 2];
    sockbuffer_t buf = { .data = storage, .data_len = 0 };
    const char *input = "<13>123 looks like a count\n";
    fill_buffer(&buf, input, strlen(input));

    expect_SendMSG_call("123 looks like a count", "10.0.0.1", SYSLOG_MQ, 0);

    send_buffer(&buf, "10.0.0.1");
    assert_int_equal(buf.data_len, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* w_get_pri_header_len (existing) */
        cmocka_unit_test(test_w_get_pri_header_len_null),
        cmocka_unit_test(test_w_get_pri_header_len_no_pri),
        cmocka_unit_test(test_w_get_pri_header_len_w_pri),
        cmocka_unit_test(test_w_get_pri_header_len_not_end),

        /* send_buffer — newline framing */
        cmocka_unit_test(test_send_buffer_empty),
        cmocka_unit_test(test_send_buffer_single_newline_message),
        cmocka_unit_test(test_send_buffer_multiple_newline_messages),
        cmocka_unit_test(test_send_buffer_partial_newline_message),

        /* send_buffer — octet-counted framing */
        cmocka_unit_test(test_send_buffer_single_octet_counted),
        cmocka_unit_test(test_send_buffer_multiple_octet_counted),
        cmocka_unit_test(test_send_buffer_partial_octet_counted),

        /* send_buffer — framing auto-detect */
        cmocka_unit_test(test_send_buffer_mixed_framings),
        cmocka_unit_test(test_send_buffer_newline_starts_with_lt),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
