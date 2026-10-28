/* Copyright (C) 2026, Wazuh Inc.
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

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/libc/string_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Globals */
extern int maximum_lines;

/* Bytes the stored hash must cover. NULL skips the check */
static const char *stored_bytes = NULL;

/* Setup & Teardown */

static int group_setup(void **state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void **state) {
    test_mode = 0;
    return 0;
}

static int test_teardown(void **state) {
    maximum_lines = 0;
    stored_bytes = NULL;
    return 0;
}

/* Hash checks */

static void sha1_hex(EVP_MD_CTX *context, char *hex) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    EVP_MD_CTX *copy = EVP_MD_CTX_new();

    EVP_MD_CTX_copy(copy, context);
    EVP_DigestFinal_ex(copy, digest, NULL);
    EVP_MD_CTX_free(copy);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    }
}

static void assert_stored_hash(EVP_MD_CTX *context) {
    char stored[2 * SHA_DIGEST_LENGTH + 1];
    char expected[2 * SHA_DIGEST_LENGTH + 1];
    EVP_MD_CTX *bytes = EVP_MD_CTX_new();

    EVP_DigestInit(bytes, EVP_sha1());
    EVP_DigestUpdate(bytes, stored_bytes, strlen(stored_bytes));
    sha1_hex(bytes, expected);
    EVP_MD_CTX_free(bytes);

    sha1_hex(context, stored);
    assert_string_equal(stored, expected);
}

/* Wraps */

int __wrap_can_read() {
    return mock_type(int);
}

/* The context hashes for real, so the tests can check the hash stored with the offset */
bool __wrap_w_get_hash_context(logreader *lf, EVP_MD_CTX **context, int64_t position) {
    EVP_DigestInit(*context, EVP_sha1());
    return mock_type(bool);
}

int __wrap_w_update_file_status(const char *path, int64_t pos, EVP_MD_CTX *context) {
    check_expected(pos);
    if (stored_bytes != NULL) {
        assert_stored_hash(context);
    }
    bool free_context = mock_type(bool);
    if (free_context) {
        EVP_MD_CTX_free(context);
    }
    return mock_type(int);
}

void __wrap_OS_SHA1_Stream_Bytes(EVP_MD_CTX *c, const char * buf, size_t len) {
    function_called();
    check_expected(len);
    EVP_DigestUpdate(c, buf, len);
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *log_target, char queue_mq) {
    check_expected(str);
    check_expected(size);
    return mock_type(int);
}

int __wrap_check_ignore_and_restrict(const char *ignore_regex, const char *restrict_regex, const char *str) {
    check_expected(str);
    return mock_type(int);
}

/* Helpers */

/* Builds "<prefix><filler repeated>\n" of total length len plus the newline. */
static char * build_line(const char *prefix, char filler, size_t len) {
    size_t prefix_len = strlen(prefix);
    char *line;

    assert_true(len >= prefix_len);

    line = calloc(len + 2, sizeof(char));
    assert_non_null(line);

    memcpy(line, prefix, prefix_len);
    memset(line + prefix_len, filler, len - prefix_len);
    line[len] = '\n';

    return line;
}

/* Builds a date line whose first space sits at index space_idx. */
static char * build_date_line(size_t space_idx, const char *tail) {
    size_t tail_len = strlen(tail);
    char *line;

    assert_true(space_idx >= 6);

    line = calloc(space_idx + tail_len + 3, sizeof(char));
    assert_non_null(line);

    memcpy(line, "01/13-", 6);
    memset(line + 6, 'Z', space_idx - 6);
    line[space_idx] = ' ';
    memcpy(line + space_idx + 1, tail, tail_len);
    line[space_idx + 1 + tail_len] = '\n';

    return line;
}

/* File position reported by w_ftell after each line read */
static int64_t mock_position = 0;

/* Expect a line of line_len bytes, which may contain NUL bytes, to be read and hashed */
static void expect_line_bytes(char *line, size_t line_len) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);
    mock_position += (int64_t) line_len;
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, mock_position);
    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, line_len);
}

static void expect_line(char *line) {
    expect_line_bytes(line, strlen(line));
}

/* A NULL msg skips the content check, for records too large to spell out. */
static void expect_queued(const char *msg, size_t size) {
    if (msg) {
        expect_string(__wrap_check_ignore_and_restrict, str, msg);
    } else {
        expect_any(__wrap_check_ignore_and_restrict, str);
    }
    will_return(__wrap_check_ignore_and_restrict, false);

    if (msg) {
        expect_string(__wrap_w_msg_hash_queues_push, str, msg);
    } else {
        expect_any(__wrap_w_msg_hash_queues_push, str);
    }
    expect_value(__wrap_w_msg_hash_queues_push, size, size);
    will_return(__wrap_w_msg_hash_queues_push, 0);
}

static void expect_prologue(void) {
    mock_position = 0;
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_w_get_hash_context, true);
}

static void expect_epilogue(void) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    expect_value(__wrap_w_update_file_status, pos, 0);
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    expect_any(__wrap__mdebug2, formatted_msg);
}

/* Expect a line to be read from a file whose hash state could not be obtained */
static void expect_line_unhashed(char *line) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);
    mock_position += (int64_t) strlen(line);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, mock_position);
}

static void expect_end_of_file(void) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);
}

/* Expect the reader to go back to pos, so the next read starts there */
static void expect_rewind(int64_t pos) {
    expect_string(__wrap__mdebug2, formatted_msg, "Message not complete from 'test.log'. Trying again.");
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, pos);
    will_return(__wrap_w_fseek, 0);
}

/* Expect the offset pos to be stored, with the hash of the bytes before it */
static void expect_stored_state(int64_t pos, const char *bytes) {
    stored_bytes = bytes;
    expect_value(__wrap_w_update_file_status, pos, pos);
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);
}

/* Tests */

/**
 * Test: well-formed three-line record.
 * The whole record is queued as one message, its parts separated by a space.
 */
void test_read_snortfull_complete_record(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:0] Test alert [**]\n";
    char line2[] = "[Classification: Attempted Information Leak] [Priority: 2]\n";
    char line3[] = "01/13-15:30:00.000000 10.0.0.1:1234 -> 10.0.0.2:80\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1000001:0] Test alert [**] [Classification: Attempted Information Leak] [Priority: 2] "
                      "10.0.0.1:1234 -> 10.0.0.2:80";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: preprocessor record whose first line already fills f_msg.
 * The free space left after the first line is smaller than the preprocessor
 * label, so both appends must be bounded to what is left.
 */
void test_read_snortfull_preprocessor_full_buffer(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char *line1 = build_line("[**] [", 'A', OS_MAX_LOG_SIZE - 10);
    char *line2 = build_line("01/13-15:30:00.000000 ", 'C', 2022);

    expect_prologue();

    expect_line(line1);
    expect_line(line2);

    expect_queued(NULL, OS_MAX_LOG_SIZE);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line1);
    free(line2);
}

/**
 * Test: three-line record whose first two lines fill f_msg.
 * The third append must be bounded to zero bytes.
 */
void test_read_snortfull_third_line_full_buffer(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char *line1 = build_line("[**] [", 'A', 60024);
    char *line2 = build_line("[Classification: ", 'B', 40017);
    char *line3 = build_line("01/13-15:30:00.000000 ", 'C', 2022);

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    expect_queued(NULL, OS_MAX_LOG_SIZE);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line1);
    free(line2);
    free(line3);
}

/**
 * Test: preprocessor record shorter than its own date line.
 * The queued message is the composed record, sized with its terminator.
 */
void test_read_snortfull_preprocessor_message_length(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [\n";
    char *line2 = build_date_line(50, "abcde");

    expect_prologue();

    expect_line(line1);
    expect_line(line2);

    const char *msg = "[**] [ [Classification: Preprocessor] [Priority: 3] abcde";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line2);
}

/**
 * Test: record as written by Snort, with a trailing space after the priority.
 * No extra separator is added, so the address follows a single space.
 */
void test_read_snortfull_snort_trailing_space(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1054:7] WEB-MISC weblogic/tomcat .jsp view source attempt [**]\n";
    char line2[] = "[Classification: Web Application Attack] [Priority: 1] \n";
    char line3[] = "10/06-08:25:55.575491 10.4.12.26:43832 -> 10.4.10.231:8080\n";
    char line4[] = "TCP TTL:64 TOS:0x0 ID:2148 IpLen:20 DgmLen:139 DF\n";
    char line5[] = "\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1054:7] WEB-MISC weblogic/tomcat .jsp view source attempt [**] "
                      "[Classification: Web Application Attack] [Priority: 1] 10.4.12.26:43832 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_line(line4);
    expect_line(line5);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: record without classification.
 * The real priority line is kept.
 */
void test_read_snortfull_priority_only(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000003:1] no classtype test [**]\n";
    char line2[] = "[Priority: 0] \n";
    char line3[] = "10/06-08:25:55.601399 10.4.12.26:43844 -> 10.4.10.231:8080\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1000003:1] no classtype test [**] [Priority: 0] 10.4.12.26:43844 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: date line with the year (Snort show_year).
 */
void test_read_snortfull_date_with_year(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1054:7] WEB-MISC test [**]\n";
    char line2[] = "[Classification: Web Application Attack] [Priority: 1] \n";
    char line3[] = "10/06/26-08:25:55.575491 10.4.12.26:43832 -> 10.4.10.231:8080\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1054:7] WEB-MISC test [**] [Classification: Web Application Attack] [Priority: 1] "
                      "10.4.12.26:43832 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: record with the AppID line written by Snort with OpenAppID.
 */
void test_read_snortfull_appid(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1054:7] WEB-MISC test [**]\n";
    char line2[] = "[Classification: Web Application Attack] [Priority: 1] \n";
    char line3[] = "[AppID: HTTP] \n";
    char line4[] = "10/06-08:25:55.575491 10.4.12.26:43832 -> 10.4.10.231:8080\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);
    expect_line(line4);

    const char *msg = "[**] [1:1054:7] WEB-MISC test [**] [Classification: Web Application Attack] [Priority: 1] "
                      "[AppID: HTTP] 10.4.12.26:43832 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: record with CRLF line endings.
 * The carriage returns are not queued.
 */
void test_read_snortfull_crlf(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1054:7] WEB-MISC test [**]\r\n";
    char line2[] = "[Classification: Web Application Attack] [Priority: 1] \r\n";
    char line3[] = "10/06-08:25:55.575491 10.4.12.26:43832 -> 10.4.10.231:8080\r\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1054:7] WEB-MISC test [**] [Classification: Web Application Attack] [Priority: 1] "
                      "10.4.12.26:43832 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: record matched by <ignore>.
 * The filter is checked against the whole record and nothing is queued.
 */
void test_read_snortfull_ignored_record(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:1] ICMP PING test [**]\n";
    char line2[] = "[Classification: Misc activity] [Priority: 3] \n";
    char line3[] = "10/06-08:25:55.608163 10.4.12.26 -> 10.4.10.231\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    expect_string(__wrap_check_ignore_and_restrict, str,
                  "[**] [1:1000001:1] ICMP PING test [**] [Classification: Misc activity] [Priority: 3] "
                  "10.4.12.26 -> 10.4.10.231");
    will_return(__wrap_check_ignore_and_restrict, true);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: several oversized records in a row.
 * Verifies the buffer state is reset between records and every append stays
 * within bounds when the sequence is repeated.
 */
void test_read_snortfull_consecutive_full_records(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;
    int i;

    char *line1 = build_line("[**] [", 'A', 60024);
    char *line2 = build_line("[Classification: ", 'B', 40017);
    char *line3 = build_line("01/13-15:30:00.000000 ", 'C', 2022);

    expect_prologue();

    for (i = 0; i < 3; i++) {
        expect_line(line1);
        expect_line(line2);
        expect_line(line3);

        expect_queued(NULL, OS_MAX_LOG_SIZE);
    }

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line1);
    free(line2);
    free(line3);
}

/**
 * Test: a line that breaks the record format.
 * The reader stops with an error, but the state covering the bad line is stored, so the next read and a
 * restart resume after it instead of hashing from a stale state.
 */
void test_read_snortfull_bad_line_keeps_state(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:0] Test alert [**]\n";
    char line2[] = "[Classification: no line end";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);

    expect_string(__wrap__merror, formatted_msg, "Bad formated snort full file.");

    expect_value(__wrap_w_update_file_status, pos, (int64_t) (strlen(line1) + strlen(line2)));
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, -1);
}

/**
 * Test: the file ends right after an alert's header, the writer has not flushed the rest yet.
 * Nothing is queued and the reader goes back to the header, offset and hash included, so the next read
 * assembles the alert from its first line.
 */
void test_read_snortfull_eof_after_header(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:0] Test alert [**]\n";

    expect_prologue();

    expect_line(line1);
    expect_end_of_file();

    expect_rewind(0);
    expect_stored_state(0, "");
    expect_any(__wrap__mdebug2, formatted_msg);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: a complete alert, then the header and classification of the next one at the end of the file.
 * The first alert is queued; the reader goes back to the second alert's header, and the stored hash
 * covers the first alert only.
 */
void test_read_snortfull_eof_after_classification(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:1] First alert [**]\n";
    char line2[] = "[Classification: Misc activity] [Priority: 3] \n";
    char line3[] = "10/06-08:25:55.608163 10.0.0.1 -> 10.0.0.2\n";
    char line4[] = "ICMP TTL:64 TOS:0x0 ID:1 IpLen:20 DgmLen:84\n";
    char line5[] = "\n";
    char line6[] = "[**] [1:1000002:1] Second alert [**]\n";
    char line7[] = "[Classification: Misc activity] [Priority: 3] \n";
    char first_alert[256];

    snprintf(first_alert, sizeof(first_alert), "%s%s%s%s%s", line1, line2, line3, line4, line5);

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1000001:1] First alert [**] [Classification: Misc activity] [Priority: 3] "
                      "10.0.0.1 -> 10.0.0.2";
    expect_queued(msg, strlen(msg) + 1);

    expect_line(line4);
    expect_line(line5);
    expect_line(line6);
    expect_line(line7);
    expect_end_of_file();

    expect_rewind((int64_t) strlen(first_alert));
    expect_stored_state((int64_t) strlen(first_alert), first_alert);
    expect_any(__wrap__mdebug2, formatted_msg);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: reading is paused in the middle of an alert.
 * The reader goes back to the alert's header.
 */
void test_read_snortfull_paused_mid_alert(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:0] Test alert [**]\n";
    char line2[] = "[Classification: Attempted Information Leak] [Priority: 2]\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    will_return(__wrap_can_read, 0);

    expect_rewind(0);
    expect_stored_state(0, "");
    expect_any(__wrap__mdebug2, formatted_msg);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: the file ends in the middle of an alert, and its hash state could not be obtained.
 * The reader still goes back to the alert's header; no state is stored.
 */
void test_read_snortfull_eof_mid_alert_unhashed(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:0] Test alert [**]\n";
    char line2[] = "[Classification: Attempted Information Leak] [Priority: 2]\n";
    char line3[] = "01/13-15:30:00.000000 10.0.0.1:1234 -> 10.0.0.2:80\n";
    char line4[] = "[**] [1:1000002:0] Unfinished alert [**]\n";

    mock_position = 0;
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_w_get_hash_context, false);

    expect_line_unhashed(line1);
    expect_line_unhashed(line2);
    expect_line_unhashed(line3);

    const char *msg = "[**] [1:1000001:0] Test alert [**] [Classification: Attempted Information Leak] [Priority: 2] "
                      "10.0.0.1:1234 -> 10.0.0.2:80";
    expect_queued(msg, strlen(msg) + 1);

    expect_line_unhashed(line4);
    expect_end_of_file();

    expect_rewind((int64_t) (strlen(line1) + strlen(line2) + strlen(line3)));
    expect_any(__wrap__mdebug2, formatted_msg);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_snortfull_complete_record),
        cmocka_unit_test(test_read_snortfull_preprocessor_full_buffer),
        cmocka_unit_test(test_read_snortfull_third_line_full_buffer),
        cmocka_unit_test(test_read_snortfull_preprocessor_message_length),
        cmocka_unit_test(test_read_snortfull_consecutive_full_records),
        cmocka_unit_test(test_read_snortfull_bad_line_keeps_state),
        cmocka_unit_test(test_read_snortfull_snort_trailing_space),
        cmocka_unit_test(test_read_snortfull_priority_only),
        cmocka_unit_test(test_read_snortfull_ignored_record),
        cmocka_unit_test(test_read_snortfull_date_with_year),
        cmocka_unit_test(test_read_snortfull_crlf),
        cmocka_unit_test(test_read_snortfull_appid),
        cmocka_unit_test_teardown(test_read_snortfull_eof_after_header, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_eof_after_classification, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_paused_mid_alert, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_eof_mid_alert_unhashed, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
