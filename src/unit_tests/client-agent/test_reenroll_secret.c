/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * AGENT_REENROLL_SECRET is a relative path, so these tests run the real store against real files
 * under an etc/ directory created relative to the working directory -- same style as
 * test_token_bootstrap.c and test_client_conf_ssl_resolution.c. Nothing about the filesystem is
 * mocked: the atomicity and the mode are the point, and a mocked rename would prove neither.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "shared.h"
#include "reenroll_secret.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define VALID_SECRET "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define OTHER_SECRET "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

/* ---- fixtures ---- */

static int group_setup(void **state) {
    (void) state;
    mkdir("etc", 0755);
    unlink(AGENT_REENROLL_SECRET);
    return 0;
}

static int setup_test(void **state) {
    (void) state;
    unlink(AGENT_REENROLL_SECRET);
    return 0;
}

/* A successful store writes one mdebug1 of its own, and TempFile() writes an FSTAT_ERROR one
 * whenever the file it is about to replace does not exist yet -- so the count varies with what the
 * test did before. Declared uninteresting instead of counted, in the test body rather than in the
 * fixture: cmocka validates a setup function's own queue when setup returns, and an "always" entry
 * left there is reported as an unchecked leftover. */
#define ignore_debug_lines() expect_any_always(__wrap__mdebug1, formatted_msg)

static int teardown_test(void **state) {
    (void) state;
    unlink(AGENT_REENROLL_SECRET);
    return 0;
}

static void write_store(const char *contents) {
    FILE *fp = fopen(AGENT_REENROLL_SECRET, "w");
    assert_non_null(fp);
    fputs(contents, fp);
    fclose(fp);
}

static char *read_store(void) {
    static char buffer[256];
    FILE *fp = fopen(AGENT_REENROLL_SECRET, "r");
    assert_non_null(fp);
    memset(buffer, 0, sizeof(buffer));
    assert_non_null(fgets(buffer, sizeof(buffer), fp));
    fclose(fp);
    return buffer;
}

/* ---- store / load round trip ---- */

static void test_store_then_load_round_trip(void **state) {
    (void) state;
    ignore_debug_lines();
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    assert_int_equal(w_reenroll_secret_store("001", VALID_SECRET), 0);

    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 1);
    assert_string_equal(id, "001");
    assert_string_equal(secret, VALID_SECRET);
}

/* The id is stored WITH the secret, on one line, because the bearer's `kid` is the agent's own id:
 * an agent that has lost client.keys must still know which id to present. */
static void test_stored_line_carries_the_id_and_the_secret(void **state) {
    (void) state;
    ignore_debug_lines();

    assert_int_equal(w_reenroll_secret_store("042", VALID_SECRET), 0);

    assert_string_equal(read_store(), "042 " VALID_SECRET "\n");
}

/* Rotation is the normal case -- the manager mints a new secret on every enrollment -- so a store
 * must replace, not append or refuse. */
static void test_storing_again_replaces_the_previous_secret(void **state) {
    (void) state;
    ignore_debug_lines();
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    assert_int_equal(w_reenroll_secret_store("001", VALID_SECRET), 0);
    assert_int_equal(w_reenroll_secret_store("001", OTHER_SECRET), 0);

    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 1);
    assert_string_equal(secret, OTHER_SECRET);
    assert_string_equal(read_store(), "001 " OTHER_SECRET "\n");
}

#ifndef WIN32
/* 0640 and no wider: the credential is client.keys's equal, so it gets client.keys's mode. It must
 * stay readable AND writable by the owner because every rotation rewrites it from the daemon. */
static void test_stored_file_has_client_keys_mode(void **state) {
    (void) state;
    ignore_debug_lines();
    struct stat info;

    assert_int_equal(w_reenroll_secret_store("001", VALID_SECRET), 0);

    assert_int_equal(stat(AGENT_REENROLL_SECRET, &info), 0);
    assert_int_equal(info.st_mode & 0777, 0640);
}
#endif

/* ---- refusals at the store boundary ---- */

static void test_store_refuses_an_invalid_id(void **state) {
    (void) state;

    expect_string(__wrap__merror, formatted_msg,
                  "Re-enrollment secret not stored: the manager answered with an invalid agent id.");
    assert_int_equal(w_reenroll_secret_store("not-an-id", VALID_SECRET), -1);

    /* Nothing written: a store that cannot be verified is worse than none. */
    assert_int_equal(IsFile(AGENT_REENROLL_SECRET), -1);
}

static void test_store_refuses_a_malformed_secret(void **state) {
    (void) state;

    expect_string(__wrap__merror, formatted_msg,
                  "Re-enrollment secret not stored: the manager answered with a malformed secret.");
    assert_int_equal(w_reenroll_secret_store("001", "tooshort"), -1);
    assert_int_equal(IsFile(AGENT_REENROLL_SECRET), -1);
}

/* Uppercase hex is not what OS_NewReenrollSecret() produces, and the manager compares the derived
 * key, not the text -- so accepting it here would store a secret that derives a different key and
 * fails every re-enrollment. */
static void test_store_refuses_uppercase_hex(void **state) {
    (void) state;

    expect_string(__wrap__merror, formatted_msg,
                  "Re-enrollment secret not stored: the manager answered with a malformed secret.");
    assert_int_equal(w_reenroll_secret_store("001", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
                     -1);
}

static void test_store_refuses_null_arguments(void **state) {
    (void) state;
    assert_int_equal(w_reenroll_secret_store(NULL, VALID_SECRET), -1);
    assert_int_equal(w_reenroll_secret_store("001", NULL), -1);
}

/* ---- load: absent and malformed are both "absent" ---- */

static void test_load_missing_store_is_absent_not_an_error(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    /* No log expectation at all: this is the normal state of a legacy install, and an agent that
     * logged an error every enrollment attempt for it would be crying wolf. */
    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 0);
    assert_string_equal(id, "");
    assert_string_equal(secret, "");
}

static void test_load_empty_store_is_absent(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    write_store("");
    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 0);
}

static void test_load_secret_without_an_id_is_malformed(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    write_store(VALID_SECRET "\n");
    expect_string(__wrap__merror, formatted_msg,
                  "Re-enrollment secret store '" AGENT_REENROLL_SECRET "' is malformed; ignoring it.");
    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 0);
    assert_string_equal(secret, "");
}

static void test_load_extra_field_is_malformed(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    write_store("001 " VALID_SECRET " extra\n");
    expect_string(__wrap__merror, formatted_msg,
                  "Re-enrollment secret store '" AGENT_REENROLL_SECRET "' is malformed; ignoring it.");
    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 0);
}

/* An over-long secret must be refused, never silently cut to the first 64 characters -- which
 * would validate here and then derive a different key than the manager holds. The line is
 * well-formed (one id, one space, one value), so the value itself is what gets named. */
static void test_load_over_long_secret_is_refused_not_truncated(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    write_store("001 " VALID_SECRET "ff\n");
    expect_string(__wrap__merror, formatted_msg,
                  "Re-enrollment secret store '" AGENT_REENROLL_SECRET
                  "' holds an invalid id or secret; ignoring it.");
    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 0);
    assert_string_equal(secret, "");
}

static void test_load_invalid_values_are_ignored(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    write_store("001 zzzz\n");
    expect_string(__wrap__merror, formatted_msg,
                  "Re-enrollment secret store '" AGENT_REENROLL_SECRET
                  "' holds an invalid id or secret; ignoring it.");
    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 0);
}

/* A trailing CRLF is what a file edited on Windows carries; it must not make a good secret
 * unreadable. */
static void test_load_tolerates_crlf(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    write_store("001 " VALID_SECRET "\r\n");
    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 1);
    assert_string_equal(secret, VALID_SECRET);
}

static void test_load_refuses_null_arguments(void **state) {
    (void) state;
    char secret[W_REENROLL_SECRET_SIZE];
    assert_int_equal(w_reenroll_secret_load(NULL, W_REENROLL_ID_SIZE, secret, sizeof(secret)), 0);
}

/* ---- clear ---- */

static void test_clear_overwrites_then_unlinks(void **state) {
    (void) state;
    ignore_debug_lines();
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    assert_int_equal(w_reenroll_secret_store("001", VALID_SECRET), 0);

    expect_string(__wrap__minfo, formatted_msg,
                  "The re-enrollment secret was rejected by the manager and has been removed.");
    w_reenroll_secret_clear();

    assert_int_equal(IsFile(AGENT_REENROLL_SECRET), -1);
    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 0);
}

/* Clearing what is not there is not a failure: the caller reaches this after a rejection, and
 * whether a store existed is not something it should have to check first. */
static void test_clear_without_a_store_is_silent(void **state) {
    (void) state;
    w_reenroll_secret_clear();
    assert_int_equal(IsFile(AGENT_REENROLL_SECRET), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_store_then_load_round_trip, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_stored_line_carries_the_id_and_the_secret, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_storing_again_replaces_the_previous_secret, setup_test, teardown_test),
#ifndef WIN32
        cmocka_unit_test_setup_teardown(test_stored_file_has_client_keys_mode, setup_test, teardown_test),
#endif
        cmocka_unit_test_setup_teardown(test_store_refuses_an_invalid_id, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_store_refuses_a_malformed_secret, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_store_refuses_uppercase_hex, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_store_refuses_null_arguments, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_load_missing_store_is_absent_not_an_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_load_empty_store_is_absent, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_load_secret_without_an_id_is_malformed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_load_extra_field_is_malformed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_load_over_long_secret_is_refused_not_truncated, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_load_invalid_values_are_ignored, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_load_tolerates_crlf, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_load_refuses_null_arguments, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_clear_overwrites_then_unlinks, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_clear_without_a_store_is_silent, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
