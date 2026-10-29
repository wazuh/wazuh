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

/* What logcollector keeps between two reads of a file: the offset and the hash context the reader stored */
static int64_t kept_offset = 0;
static EVP_MD_CTX *kept_context = NULL;

/* What the writer has appended to the file so far, and copies of its lines for the mocked fgets */
static char written[2048];
static char line_pool[64][256];
static size_t lines_in_pool = 0;

/* How many calls to EVP_MD_CTX_copy work before one fails, to test the reader without memory. Negative: none fails */
static int copies_before_failure = -1;

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
    EVP_MD_CTX_free(kept_context);
    kept_context = NULL;
    kept_offset = 0;
    written[0] = '\0';
    lines_in_pool = 0;
    copies_before_failure = -1;
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

extern int __real_feof(FILE *stream);
int __wrap_feof(FILE *stream) {
    if (test_mode) {
        return mock_type(int);
    }
    return __real_feof(stream);
}

extern int __real_EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);
int __wrap_EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in) {
    if (copies_before_failure == 0) {
        copies_before_failure = -1;
        return 0;
    }
    if (copies_before_failure > 0) {
        copies_before_failure--;
    }
    return __real_EVP_MD_CTX_copy(out, in);
}

/* The context hashes for real, so the tests can check the hash stored with the offset.
 * It starts from the hash kept by the previous read, as the real one does. */
bool __wrap_w_get_hash_context(logreader *lf, EVP_MD_CTX **context, int64_t position) {
    EVP_DigestInit(*context, EVP_sha1());
    if (kept_context != NULL) {
        EVP_MD_CTX_copy(*context, kept_context);
    }
    return mock_type(bool);
}

/* Takes over the context, as the real one does, when the test asks to keep it for the next read */
static void keep_state(int64_t pos, EVP_MD_CTX *context) {
    EVP_MD_CTX_free(kept_context);
    kept_context = context;
    kept_offset = pos;
}

int __wrap_w_update_file_status(const char *path, int64_t pos, EVP_MD_CTX *context) {
    check_expected(pos);
    if (stored_bytes != NULL) {
        assert_stored_hash(context);
    }
    bool free_context = mock_type(bool);
    if (free_context) {
        EVP_MD_CTX_free(context);
    } else {
        keep_state(pos, context);
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

/* Expect a read that starts at offset, where the previous one left the file */
static void expect_prologue_at(int64_t offset) {
    mock_position = offset;
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, offset);
    will_return(__wrap_w_get_hash_context, true);
}

static void expect_prologue(void) {
    expect_prologue_at(0);
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

/* Expect a line to be read and not used: the reader stops before it, so the next read starts there */
static void expect_line_left_unread(char *line) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);
}

/* Expect the last line of the file, still being written, to be read without its line end */
static void expect_unfinished_line(char *line) {
    expect_line_left_unread(line);
    will_return(__wrap_feof, 1);
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

/* The same, but the state stays for the next read, as it does in logcollector. The bytes are the written ones */
static void expect_kept_state(int64_t pos) {
    static char covered[sizeof(written)];

    snprintf(covered, sizeof(covered), "%.*s", (int) pos, written);
    stored_bytes = covered;
    expect_value(__wrap_w_update_file_status, pos, pos);
    will_return(__wrap_w_update_file_status, false);
    will_return(__wrap_w_update_file_status, 0);
}

/* Reads in a row */

static void write_to_file(const char *bytes) {
    assert_true(strlen(written) + strlen(bytes) < sizeof(written));
    strcat(written, bytes);
}

/* A copy of a line of the file that stays valid until the read ends */
static char *copy_line(const char *text, size_t len) {
    assert_true(lines_in_pool < sizeof(line_pool) / sizeof(line_pool[0]));
    assert_true(len < sizeof(line_pool[0]));

    char *line = line_pool[lines_in_pool++];
    memcpy(line, text, len);
    line[len] = '\0';
    return line;
}

/* Expect the lines of text to be read. Returns true if the last one is unfinished: nothing is read after it */
static bool expect_lines(const char *text) {
    bool unfinished = false;

    while (*text != '\0' && !unfinished) {
        const char *end = strchr(text, '\n');
        size_t len = end ? (size_t) (end - text) + 1 : strlen(text);
        char *line = copy_line(text, len);

        unfinished = (end == NULL);
        if (unfinished) {
            expect_unfinished_line(line);
        } else {
            expect_line(line);
        }
        text += len;
    }
    return unfinished;
}

/* Expect a read that goes from offset to the end of what has been written, the last line maybe unfinished */
static void expect_read_from(int64_t offset) {
    expect_prologue_at(offset);

    if (!expect_lines(written + offset)) {
        expect_end_of_file();
    }
}

static void expect_queued_message(const char *msg) {
    expect_queued(msg, strlen(msg) + 1);
}

/* Expect the read to end inside an alert: the reader goes back to its header and keeps that state */
static void expect_read_back_to(int64_t offset) {
    expect_rewind(offset);
    expect_kept_state(offset);
    expect_any(__wrap__mdebug2, formatted_msg);
}

/* Expect the read to end at the end of what has been written, with no alert open */
static void expect_read_to_end(void) {
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, mock_position);
    expect_kept_state(mock_position);
    expect_any(__wrap__mdebug2, formatted_msg);
}

/* What Snort writes for alert id, and the message the reader sends for it */
#define HEADER(id)         "[**] [1:" id ":1] Alert " id " [**]\n"
#define CLASSIFICATION     "[Classification: Misc activity] [Priority: 3] \n"
#define DATE_AND_PACKET    "10/06-08:25:55.608163 10.0.0.1 -> 10.0.0.2\n" \
                           "ICMP TTL:64 TOS:0x0 ID:1 IpLen:20 DgmLen:84\n\n"
#define ALERT(id)          HEADER(id) CLASSIFICATION DATE_AND_PACKET
#define MESSAGE(id)        "[**] [1:" id ":1] Alert " id " [**] [Classification: Misc activity] [Priority: 3] " \
                           "10.0.0.1 -> 10.0.0.2"

#define DISCARD_WARNING    "Incomplete snort full alert discarded from 'test.log': a new alert starts before its " \
                           "date line."

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
 * Test: a line that breaks the record format, without a line end before the end of the file.
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
    will_return(__wrap_feof, 0);
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

/**
 * Test: the line limit, 100 (the lowest logcollector accepts), is reached on the header of the 34th alert.
 * The limit does not cut the alert: the reader goes on to its date line, queues it and stops there.
 */
void test_read_snortfull_line_limit_on_header(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char header[] = "[**] [1:1000001:1] Test alert [**]\n";
    char classification[] = "[Classification: Misc activity] [Priority: 3] \n";
    char date[] = "10/06-08:25:55.608163 10.0.0.1 -> 10.0.0.2\n";
    const char *msg = "[**] [1:1000001:1] Test alert [**] [Classification: Misc activity] [Priority: 3] "
                      "10.0.0.1 -> 10.0.0.2";
    char read_bytes[34 * 160] = {0};

    maximum_lines = 100;

    expect_prologue();

    /* 33 three-line alerts take lines 1 to 99, the 34th starts on line 100 */
    for (int i = 0; i < 34; i++) {
        expect_line(header);
        expect_line(classification);
        expect_line(date);
        expect_queued(msg, strlen(msg) + 1);
        strcat(read_bytes, header);
        strcat(read_bytes, classification);
        strcat(read_bytes, date);
    }

    /* No alert open: the limit stops the read after line 102 */
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(read_bytes));

    expect_stored_state((int64_t) strlen(read_bytes), read_bytes);
    expect_any(__wrap__mdebug2, formatted_msg);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: the line limit, 100, is reached on the header of the 34th alert, which has an AppID line.
 * An alert has at most four lines up to its date line, so the read goes three lines past the limit and no more.
 */
void test_read_snortfull_line_limit_on_header_with_appid(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char header[] = "[**] [1:1000001:1] Test alert [**]\n";
    char classification[] = "[Classification: Misc activity] [Priority: 3] \n";
    char appid[] = "[AppID: HTTP] \n";
    char date[] = "10/06-08:25:55.608163 10.0.0.1 -> 10.0.0.2\n";
    const char *msg = "[**] [1:1000001:1] Test alert [**] [Classification: Misc activity] [Priority: 3] "
                      "10.0.0.1 -> 10.0.0.2";
    const char *appid_msg = "[**] [1:1000001:1] Test alert [**] [Classification: Misc activity] [Priority: 3] "
                            "[AppID: HTTP] 10.0.0.1 -> 10.0.0.2";
    char read_bytes[34 * 160] = {0};

    maximum_lines = 100;

    expect_prologue();

    /* 33 three-line alerts take lines 1 to 99 */
    for (int i = 0; i < 33; i++) {
        expect_line(header);
        expect_line(classification);
        expect_line(date);
        expect_queued(msg, strlen(msg) + 1);
        strcat(read_bytes, header);
        strcat(read_bytes, classification);
        strcat(read_bytes, date);
    }

    /* The 34th starts on line 100 and ends on line 103 */
    expect_line(header);
    expect_line(classification);
    expect_line(appid);
    expect_line(date);
    expect_queued(appid_msg, strlen(appid_msg) + 1);
    strcat(read_bytes, header);
    strcat(read_bytes, classification);
    strcat(read_bytes, appid);
    strcat(read_bytes, date);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(read_bytes));

    expect_stored_state((int64_t) strlen(read_bytes), read_bytes);
    expect_string(__wrap__mdebug2, formatted_msg, "Read 103 lines from test.log");

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: the writer flushed an alert in the middle of its classification line.
 * The unfinished line is not a format error: the reader goes back to the alert's header.
 */
void test_read_snortfull_unfinished_line_in_alert(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:0] Test alert [**]\n";
    char line2[] = "[Classification: Attempted Inf";

    expect_prologue();

    expect_line(line1);
    expect_unfinished_line(line2);

    expect_rewind(0);
    expect_stored_state(0, "");
    expect_any(__wrap__mdebug2, formatted_msg);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: a complete alert, then the first bytes of the next header at the end of the file.
 * The first alert is queued and the reader goes back to the start of the unfinished line.
 */
void test_read_snortfull_unfinished_line_after_alert(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:0] Test alert [**]\n";
    char line2[] = "[Classification: Attempted Information Leak] [Priority: 2]\n";
    char line3[] = "01/13-15:30:00.000000 10.0.0.1:1234 -> 10.0.0.2:80\n";
    char line4[] = "[**] [1:10";
    char alert[256];

    snprintf(alert, sizeof(alert), "%s%s%s", line1, line2, line3);

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1000001:0] Test alert [**] [Classification: Attempted Information Leak] [Priority: 2] "
                      "10.0.0.1:1234 -> 10.0.0.2:80";
    expect_queued(msg, strlen(msg) + 1);

    expect_unfinished_line(line4);

    expect_rewind((int64_t) strlen(alert));
    expect_stored_state((int64_t) strlen(alert), alert);
    expect_any(__wrap__mdebug2, formatted_msg);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: the writer flushes the first bytes of the next header and finishes the alert in a second write.
 * The first read sends the alert before it and goes back to the cut header. The second read starts there, with
 * the hash the first one kept: it sends the finished alert once and does not replay the one sent before.
 */
void test_read_snortfull_header_cut_by_writer_is_sent_once(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(ALERT("1001") "[**] [1:10");
    expect_read_from(0);
    expect_queued_message(MESSAGE("1001"));
    expect_read_back_to((int64_t) strlen(ALERT("1001")));

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    assert_int_equal(kept_offset, (int64_t) strlen(ALERT("1001")));

    write_to_file("02:1] Alert 1002 [**]\n" CLASSIFICATION DATE_AND_PACKET);
    expect_read_from(kept_offset);
    expect_queued_message(MESSAGE("1002"));
    expect_read_to_end();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: the writer is slow, and flushes the header and classification of an alert a read before its date line.
 * A read that finds nothing new goes back to the same header with the same hash: the alert is not hashed twice
 * or sent early. Once the writer finishes it, the next read sends it once, and the alert after it too.
 */
void test_read_snortfull_open_alert_waits_for_slow_writer(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(ALERT("1001") HEADER("1002") CLASSIFICATION);
    expect_read_from(0);
    expect_queued_message(MESSAGE("1001"));
    expect_read_back_to((int64_t) strlen(ALERT("1001")));

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    assert_int_equal(kept_offset, (int64_t) strlen(ALERT("1001")));

    expect_read_from(kept_offset);
    expect_read_back_to((int64_t) strlen(ALERT("1001")));

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    assert_int_equal(kept_offset, (int64_t) strlen(ALERT("1001")));

    write_to_file(DATE_AND_PACKET ALERT("1003"));
    expect_read_from(kept_offset);
    expect_queued_message(MESSAGE("1002"));
    expect_queued_message(MESSAGE("1003"));
    expect_read_to_end();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: the writer flushes in the middle of the classification line of the first alert of the file.
 * The first read sends nothing and goes back to the start of the file; the second sends the alert once.
 */
void test_read_snortfull_line_cut_in_alert_is_sent_once(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(HEADER("1001") "[Classification: Misc act");
    expect_read_from(0);
    expect_read_back_to(0);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    assert_int_equal(kept_offset, 0);

    write_to_file("ivity] [Priority: 3] \n" DATE_AND_PACKET);
    expect_read_from(kept_offset);
    expect_queued_message(MESSAGE("1001"));
    expect_read_to_end();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: a line that is not part of an alert comes right after its header.
 * It is a format error. The reader stops, and stores the state after the bad line, which was hashed.
 */
void test_read_snortfull_unknown_line_after_header(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(HEADER("1001") "not a snort line\n");
    expect_prologue_at(0);
    expect_lines(written);
    expect_string(__wrap__merror, formatted_msg, "Bad formated snort full file.");
    expect_stored_state((int64_t) strlen(written), written);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, -1);
}

/**
 * Test: a line that is neither an AppID line nor the date line comes after the classification.
 * It is a format error, and the alert is not sent.
 */
void test_read_snortfull_unknown_line_after_classification(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(HEADER("1001") CLASSIFICATION "not a snort line\n");
    expect_prologue_at(0);
    expect_lines(written);
    expect_string(__wrap__merror, formatted_msg, "Bad formated snort full file.");
    expect_stored_state((int64_t) strlen(written), written);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, -1);
}

#define HASH_SAVE_ERROR "Could not save the hash state of 'test.log' at the start of an alert. Trying again later."

/**
 * Test: the hash context cannot be copied at the header of the second alert (no memory).
 * The reader could not go back to that header later, so it does not start the alert: it stops before the
 * header, stores the offset and the hash up to there, and reports the error. The next read starts at that
 * header and sends the alert once, without reading the first alert again.
 */
void test_read_snortfull_hash_copy_fails_at_header(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(ALERT("1001") ALERT("1002"));
    copies_before_failure = 1;
    expect_prologue_at(0);
    expect_lines(ALERT("1001"));
    expect_queued_message(MESSAGE("1001"));
    expect_line_left_unread(copy_line(HEADER("1002"), strlen(HEADER("1002"))));
    expect_string(__wrap__merror, formatted_msg, HASH_SAVE_ERROR);
    expect_read_back_to((int64_t) strlen(ALERT("1001")));

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, -1);
    assert_int_equal(kept_offset, (int64_t) strlen(ALERT("1001")));

    expect_read_from(kept_offset);
    expect_queued_message(MESSAGE("1002"));
    expect_read_to_end();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: Snort stops after the first lines of an alert and writes whole alerts after it restarts.
 * A header ends the alert still open, whether its header or its classification was the last line read: the
 * open alert is discarded with a warning, and the one that starts at the header is sent.
 */
void test_read_snortfull_header_ends_open_alert(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(HEADER("1001") ALERT("1002") HEADER("1003") CLASSIFICATION ALERT("1004"));
    expect_read_from(0);
    expect_string(__wrap__mwarn, formatted_msg, DISCARD_WARNING);
    expect_queued_message(MESSAGE("1002"));
    expect_string(__wrap__mwarn, formatted_msg, DISCARD_WARNING);
    expect_queued_message(MESSAGE("1004"));
    expect_read_to_end();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    assert_int_equal(kept_offset, (int64_t) strlen(written));
}

/**
 * Test: a read ends inside an alert that the writer never finishes, and the next alert is written after it.
 * The first read goes back to the open alert's header. The second reads it again, discards it at the next
 * header and sends the next alert, so the alert after the unfinished one is not lost.
 */
void test_read_snortfull_unfinished_alert_then_whole_alert(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(ALERT("1001") HEADER("1002") CLASSIFICATION);
    expect_read_from(0);
    expect_queued_message(MESSAGE("1001"));
    expect_read_back_to((int64_t) strlen(ALERT("1001")));

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    assert_int_equal(kept_offset, (int64_t) strlen(ALERT("1001")));

    write_to_file(ALERT("1003"));
    expect_read_from(kept_offset);
    expect_string(__wrap__mwarn, formatted_msg, DISCARD_WARNING);
    expect_queued_message(MESSAGE("1003"));
    expect_read_to_end();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    assert_int_equal(kept_offset, (int64_t) strlen(written));
}

/**
 * Test: a second AppID line in an alert.
 * Snort writes one at most, so it is a format error. That keeps an alert to four lines up to its date line, the
 * most the line limit can be passed by and the most a read that ends inside it reads again.
 */
void test_read_snortfull_second_appid_line(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    write_to_file(HEADER("1001") CLASSIFICATION "[AppID: HTTP] \n" "[AppID: HTTP] \n");
    expect_prologue_at(0);
    expect_lines(written);
    expect_string(__wrap__merror, formatted_msg, "Bad formated snort full file.");
    expect_stored_state((int64_t) strlen(written), written);

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, -1);
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
        cmocka_unit_test_teardown(test_read_snortfull_line_limit_on_header, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_line_limit_on_header_with_appid, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_unfinished_line_in_alert, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_unfinished_line_after_alert, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_header_cut_by_writer_is_sent_once, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_open_alert_waits_for_slow_writer, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_line_cut_in_alert_is_sent_once, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_hash_copy_fails_at_header, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_unknown_line_after_header, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_unknown_line_after_classification, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_header_ends_open_alert, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_unfinished_alert_then_whole_alert, test_teardown),
        cmocka_unit_test_teardown(test_read_snortfull_second_appid_line, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
