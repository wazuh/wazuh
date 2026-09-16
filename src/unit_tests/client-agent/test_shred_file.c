/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * AUTHD_PASS is a relative path, so these run the real shredder against real files under an etc/
 * directory created relative to the working directory -- same style as test_reenroll_secret.c and
 * test_client_conf_ssl_resolution.c. Nothing about the filesystem is mocked: whether the file is
 * opened without truncating is the entire point, and a mocked fopen() would prove nothing.
 *
 * What a test can observe is the length. That is not incidental: opening with "w" instead of
 * "r+b" truncates on open, so ftell() reports 0, the size == 0 branch returns early, and the file
 * is left at zero bytes. Asserting the original length survives is therefore a direct regression
 * test on the open mode -- the one thing here that has ever actually been wrong. What no test in
 * userspace can observe is that the zeros landed on the file's original blocks; that follows from
 * the mode (OPEN_EXISTING / no O_TRUNC) rather than from anything assertable, and is argued in
 * shred_file.h instead.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "shred_file.h"
#include "agentd.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define SECRET_LINE "hunter2-pass"
#define SCRATCH_FILE "etc/shred_scratch"

/* ---- fixtures ---- */

static int group_setup(void **state) {
    (void) state;
    mkdir("etc", 0755);
    return 0;
}

static int setup_test(void **state) {
    (void) state;
    unlink(AUTHD_PASS);
    unlink(SCRATCH_FILE);
    return 0;
}

static int teardown_test(void **state) {
    (void) state;
    unlink(AUTHD_PASS);
    unlink(SCRATCH_FILE);
    return 0;
}

/* ---- helpers ---- */

static void write_file(const char *path, const char *contents, size_t length) {
    FILE *fp = fopen(path, "wb");
    assert_non_null(fp);
    if (length > 0) {
        assert_int_equal(fwrite(contents, 1, length, fp), length);
    }
    fclose(fp);
}

static const char *read_all(const char *path) {
    static char buffer[256];
    FILE *fp = fopen(path, "rb");
    size_t n;

    assert_non_null(fp);
    n = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);
    buffer[n] = '\0';
    return buffer;
}

static off_t size_of(const char *path) {
    struct stat info;
    assert_int_equal(stat(path, &info), 0);
    return info.st_size;
}

/* Asserts the file is exactly @p length bytes and every one of them is zero. */
static void assert_all_zero(const char *path, size_t length) {
    FILE *fp = fopen(path, "rb");
    unsigned char *buffer;
    size_t i;

    assert_int_equal((size_t) size_of(path), length);
    assert_non_null(fp);

    os_malloc(length + 1, buffer);
    assert_int_equal(fread(buffer, 1, length, fp), length);
    fclose(fp);

    for (i = 0; i < length; i++) {
        if (buffer[i] != 0x00) {
            os_free(buffer);
            fail_msg("byte %zu of '%s' was not overwritten", i, path);
        }
    }

    os_free(buffer);
}

/* ---- w_shred_file_in_place() ---- */

/* The length assertion inside assert_all_zero() is the regression test on the open mode: with a
 * truncating mode this file would come back at zero bytes instead of twelve. */
static void test_overwrite_zeroes_every_byte_and_keeps_the_length(void **state) {
    (void) state;

    write_file(SCRATCH_FILE, SECRET_LINE, strlen(SECRET_LINE));
    assert_int_equal(w_shred_file_in_place(SCRATCH_FILE), 0);
    assert_all_zero(SCRATCH_FILE, strlen(SECRET_LINE));
}

/* The overwrite loop writes a fixed-size buffer repeatedly, so a file larger than one chunk is the
 * case where an off-by-one leaves a tail of the secret behind. */
static void test_overwrite_spans_more_than_one_chunk(void **state) {
    (void) state;
    const size_t length = 10000;
    char *filler;

    os_malloc(length, filler);
    memset(filler, 'A', length);
    write_file(SCRATCH_FILE, filler, length);
    os_free(filler);

    assert_int_equal(w_shred_file_in_place(SCRATCH_FILE), 0);
    assert_all_zero(SCRATCH_FILE, length);
}

/* Nothing to overwrite is not a failure: the caller still has to unlink, and reporting this as an
 * error would send it down a fallback path for a file that holds no secret. */
static void test_overwrite_of_an_empty_file_succeeds(void **state) {
    (void) state;

    write_file(SCRATCH_FILE, "", 0);
    assert_int_equal(w_shred_file_in_place(SCRATCH_FILE), 0);
    assert_int_equal(size_of(SCRATCH_FILE), 0);
}

/* Unlinking belongs to the caller -- w_reenroll_secret_clear() logs its own line after it, and the
 * enrollment-password path reports its own failure -- so the file must survive this call. */
static void test_overwrite_leaves_the_file_in_place(void **state) {
    (void) state;

    write_file(SCRATCH_FILE, SECRET_LINE, strlen(SECRET_LINE));
    assert_int_equal(w_shred_file_in_place(SCRATCH_FILE), 0);
    assert_int_equal(w_is_file(SCRATCH_FILE), 1);
}

static void test_overwrite_reports_a_file_that_is_not_there(void **state) {
    (void) state;
    char expected[OS_SIZE_256];

    snprintf(expected, sizeof(expected), FOPEN_ERROR, SCRATCH_FILE, ENOENT, strerror(ENOENT));
    expect_string(__wrap__merror, formatted_msg, expected);

    assert_int_equal(w_shred_file_in_place(SCRATCH_FILE), 1);
}

/* ---- the vetted, no-follow open ---- */

/* The shredder runs over credential paths, and one caller (the MSI's --shred-enrollment-password)
 * runs privileged, so a link swapped in at the target must be refused rather than written through.
 * Without the vetted open, this test would zero `decoy` instead of failing. */
static void test_overwrite_refuses_a_symlink(void **state) {
    (void) state;
    const char *decoy = "etc/shred_decoy";
    char expected[OS_SIZE_256];

    write_file(decoy, SECRET_LINE, strlen(SECRET_LINE));
    assert_int_equal(symlink("shred_decoy", SCRATCH_FILE), 0);

    snprintf(expected, sizeof(expected), FOPEN_ERROR, SCRATCH_FILE, ELOOP, strerror(ELOOP));
    expect_string(__wrap__merror, formatted_msg, expected);

    assert_int_equal(w_shred_file_in_place(SCRATCH_FILE), 1);

    /* The decoy is what a following open would have destroyed. */
    assert_string_equal(read_all(decoy), SECRET_LINE);
    unlink(decoy);
}

/* A hard link is a regular file, so no file-type test can tell it apart -- the link count is what
 * rejects it. Worth its own case: it is the one a truncating open would already have destroyed
 * before anything could be checked. */
static void test_overwrite_refuses_a_hard_link(void **state) {
    (void) state;
    const char *decoy = "etc/shred_decoy";

    write_file(decoy, SECRET_LINE, strlen(SECRET_LINE));
    assert_int_equal(link(decoy, SCRATCH_FILE), 0);

    expect_any(__wrap__merror, formatted_msg);
    assert_int_equal(w_shred_file_in_place(SCRATCH_FILE), 1);

    assert_string_equal(read_all(decoy), SECRET_LINE);
    unlink(decoy);
}

/* ---- w_agent_shred_enrollment_password() ---- */

static void test_shred_removes_the_enrollment_password(void **state) {
    (void) state;

    write_file(AUTHD_PASS, SECRET_LINE, strlen(SECRET_LINE));
    assert_int_equal(w_agent_shred_enrollment_password(), 0);
    assert_int_equal(w_is_file(AUTHD_PASS), 0);
}

/* A fresh 5.0 install never wrote one, and an upgrade that already ran has removed it, so the
 * installer calls this against nothing far more often than against a password. Reporting that as
 * a failure would push the MSI onto its fallback on every ordinary upgrade. */
static void test_shred_without_a_password_is_a_silent_no_op(void **state) {
    (void) state;

    assert_int_equal(w_agent_shred_enrollment_password(), 0);
    assert_int_equal(w_is_file(AUTHD_PASS), 0);
}

/* An empty authd.pass carries no secret but is still the file whose presence the manager-side
 * policy is about, so it goes the same way as a populated one. */
static void test_shred_removes_an_empty_password_file(void **state) {
    (void) state;

    write_file(AUTHD_PASS, "", 0);
    assert_int_equal(w_agent_shred_enrollment_password(), 0);
    assert_int_equal(w_is_file(AUTHD_PASS), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_overwrite_zeroes_every_byte_and_keeps_the_length, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_overwrite_spans_more_than_one_chunk, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_overwrite_of_an_empty_file_succeeds, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_overwrite_leaves_the_file_in_place, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_overwrite_reports_a_file_that_is_not_there, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_overwrite_refuses_a_symlink, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_overwrite_refuses_a_hard_link, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_shred_removes_the_enrollment_password, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_shred_without_a_password_is_a_silent_no_op, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_shred_removes_an_empty_password_file, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
