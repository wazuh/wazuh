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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"
#include "../../os_crypto/sha1/sha1_op.h"
#include "../wrappers/common.h"

/* The UCS-2 readers read real files here: the property under test is that the
 * stored hash covers exactly the bytes up to the stored offset, so a restart
 * finds the file unchanged and resumes instead of reading it again from 0. */

#define TEST_FILE "test_read_ucs2.log"
#define MAX_LINE_WCHARS (OS_MAXSTR - OS_LOG_HEADER - 1)

extern int maximum_lines;

void *read_ucs2_le(logreader *lf, int *rc, int drop_it);
void *read_ucs2_be(logreader *lf, int *rc, int drop_it);

static int64_t saved_offset;
static char saved_hash[2 * SHA_DIGEST_LENGTH + 1];
static int messages_sent;

/* Wraps */

/* The real one reads ossec.conf on Windows; the long-line case reports one error */
void __wrap__merror(__attribute__((unused)) const char * file, __attribute__((unused)) int line,
                    __attribute__((unused)) const char * func, __attribute__((unused)) const char *msg, ...) {
}

int __wrap_can_read() {
    return 1;
}

bool __wrap_w_get_hash_context(__attribute__((unused)) logreader * lf, EVP_MD_CTX ** context,
                               __attribute__((unused)) int64_t position) {
    EVP_DigestInit(*context, EVP_sha1());
    return true;
}

int __wrap_w_update_file_status(__attribute__((unused)) const char * path, int64_t pos, EVP_MD_CTX * context) {
    unsigned char digest[SHA_DIGEST_LENGTH];

    EVP_DigestFinal_ex(context, digest, NULL);
    EVP_MD_CTX_free(context);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(saved_hash + 2 * i, 3, "%02x", digest[i]);
    }

    saved_offset = pos;
    return 0;
}

int __wrap_w_msg_hash_queues_push(__attribute__((unused)) const char *str, __attribute__((unused)) char *file,
                                  __attribute__((unused)) unsigned long size,
                                  __attribute__((unused)) logtarget * targets,
                                  __attribute__((unused)) char queue_mq) {
    messages_sent++;
    return 0;
}

/* Helpers */

typedef struct {
    unsigned char * data;
    size_t len;
} test_buf_t;

static void append_bytes(test_buf_t * buf, const void * bytes, size_t len) {
    os_realloc(buf->data, buf->len + len, buf->data);
    memcpy(buf->data + buf->len, bytes, len);
    buf->len += len;
}

/* Append ASCII text encoded as UTF-16, little or big endian */
static void append_utf16(test_buf_t * buf, const char * text, bool big_endian) {
    for (const char * c = text; *c != '\0'; c++) {
        unsigned char pair[2] = { (unsigned char) *c, 0 };

        if (big_endian) {
            pair[0] = 0;
            pair[1] = (unsigned char) *c;
        }
        append_bytes(buf, pair, 2);
    }
}

static void append_bom(test_buf_t * buf, bool big_endian) {
    unsigned char le[] = { 0xFF, 0xFE };
    unsigned char be[] = { 0xFE, 0xFF };

    append_bytes(buf, big_endian ? be : le, 2);
}

/* Append a line of n copies of 'a' plus CRLF */
static void append_long_line(test_buf_t * buf, size_t n, bool big_endian) {
    char * text = NULL;

    os_calloc(n + 3, sizeof(char), text);
    memset(text, 'a', n);
    strcat(text, "\r\n");
    append_utf16(buf, text, big_endian);
    os_free(text);
}

static void sha1_hex(const unsigned char * data, size_t len, char * hex) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();

    EVP_DigestInit(ctx, EVP_sha1());
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_free(ctx);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    }
}

/* Write the buffer, run the reader once, and check the stored offset and hash */
static void run_reader(test_buf_t * buf, bool big_endian, int64_t expected_offset, int expected_messages) {
    char expected_hash[2 * SHA_DIGEST_LENGTH + 1];
    FILE * fp = fopen(TEST_FILE, "wb");

    assert_non_null(fp);
    assert_int_equal(fwrite(buf->data, 1, buf->len, fp), buf->len);
    fclose(fp);

    logreader lf = { .file = TEST_FILE, .ucs2 = big_endian ? UCS2_BE : UCS2_LE };
    lf.fp = fopen(TEST_FILE, "rb");
    assert_non_null(lf.fp);

    int rc = 0;
    saved_offset = -1;
    saved_hash[0] = '\0';
    messages_sent = 0;

    if (big_endian) {
        read_ucs2_be(&lf, &rc, 0);
    } else {
        read_ucs2_le(&lf, &rc, 0);
    }

    fclose(lf.fp);
    remove(TEST_FILE);

    assert_int_equal(saved_offset, expected_offset);
    sha1_hex(buf->data, (size_t) saved_offset, expected_hash);
    assert_string_equal(saved_hash, expected_hash);
    assert_int_equal(messages_sent, expected_messages);

    os_free(buf->data);
}

/* Setup & Teardown */

static int group_setup(__attribute__((unused)) void ** state) {
    test_mode = 1;
    maximum_lines = 0;
    return 0;
}

static int group_teardown(__attribute__((unused)) void ** state) {
    test_mode = 0;
    return 0;
}

/* Tests */

static void lines_hash_matches_file(bool big_endian) {
    test_buf_t buf = { 0 };

    append_bom(&buf, big_endian);
    append_utf16(&buf, "t6854 line one\r\nt6854 line two\r\nt6854 line three\r\n", big_endian);

    run_reader(&buf, big_endian, (int64_t) buf.len, 3);
}

/* A line holding U+0000 is hashed whole: the line end is found by length, not by the first NUL */
static void nul_char_line_hash_matches_file(bool big_endian) {
    test_buf_t buf = { 0 };
    unsigned char nul[] = { 0, 0 };

    append_bom(&buf, big_endian);
    append_utf16(&buf, "t6854 before", big_endian);
    append_bytes(&buf, nul, 2);
    append_utf16(&buf, "after\r\nt6854 next line\r\n", big_endian);

    run_reader(&buf, big_endian, (int64_t) buf.len, 2);
}

/* A last line without its line feed is not sent and not hashed: it is read again once complete */
static void partial_last_line_rolls_back(bool big_endian) {
    test_buf_t buf = { 0 };

    append_bom(&buf, big_endian);
    append_utf16(&buf, "t6854 line one\r\n", big_endian);
    int64_t complete = (int64_t) buf.len;
    append_utf16(&buf, "t6854 half a li", big_endian);

    run_reader(&buf, big_endian, complete, 1);
}

/* A line longer than the buffer is sent truncated, the rest of it is skipped, and every byte is hashed */
static void long_line_is_hashed_whole(bool big_endian) {
    test_buf_t buf = { 0 };

    append_bom(&buf, big_endian);
    append_long_line(&buf, MAX_LINE_WCHARS + 5000, big_endian);
    append_utf16(&buf, "t6854 after the long line\r\n", big_endian);

    run_reader(&buf, big_endian, (int64_t) buf.len, 2);
}

void test_read_ucs2_le_lines(void ** state) { lines_hash_matches_file(false); }
void test_read_ucs2_be_lines(void ** state) { lines_hash_matches_file(true); }
void test_read_ucs2_le_partial_last_line(void ** state) { partial_last_line_rolls_back(false); }
void test_read_ucs2_be_partial_last_line(void ** state) { partial_last_line_rolls_back(true); }
void test_read_ucs2_le_long_line(void ** state) { long_line_is_hashed_whole(false); }
void test_read_ucs2_le_nul_char(void ** state) { nul_char_line_hash_matches_file(false); }
void test_read_ucs2_be_nul_char(void ** state) { nul_char_line_hash_matches_file(true); }
void test_read_ucs2_be_long_line(void ** state) { long_line_is_hashed_whole(true); }

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_ucs2_le_lines),
        cmocka_unit_test(test_read_ucs2_be_lines),
        cmocka_unit_test(test_read_ucs2_le_partial_last_line),
        cmocka_unit_test(test_read_ucs2_be_partial_last_line),
        cmocka_unit_test(test_read_ucs2_le_long_line),
        cmocka_unit_test(test_read_ucs2_be_long_line),
        cmocka_unit_test(test_read_ucs2_le_nul_char),
        cmocka_unit_test(test_read_ucs2_be_nul_char),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
