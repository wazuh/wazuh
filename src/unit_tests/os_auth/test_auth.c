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
#include <string.h>

#include "os_err.h"
#include "shared.h"
#include "auth.h"
#include "sec.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_auth/os_auth_wrappers.h"
#include "../wrappers/wazuh/shared/randombytes_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

#define TEST_UNAME "Linux |ubuntu-focal |5.4.0-92-generic |#103-Ubuntu SMP Fri Nov 26 16:13:00 UTC 2021 " \
                   "|x86_64 [Ubuntu|ubuntu: 20.04.2 LTS (Focal Fossa)] - Wazuh v4.3.4"

/* The deterministic RNG above yields this password. */
#define TEST_GENERATED_PASS "6e0d9a4188ac9de8fa695bd96e276090"

/* The fake (non-NULL) FILE* handed back by the wfopen mock. */
#define FAKE_FP ((FILE *)1)

/* Drives the wrapped RNG so w_generate_random_pass() yields a deterministic value. */
static void setup_deterministic_pass(void) {
    will_return(__wrap_os_random, 146557);
    will_return(__wrap_os_random, 314159);
    will_return(__wrap_GetRandomNoise, strdup("Wazuh"));
    will_return(__wrap_GetRandomNoise, strdup("The Open Source Security Platform"));
    will_return(__wrap_time, 1655254875);
    will_return_always(__wrap_getuname, TEST_UNAME);
}

/* Toggle file-mock mode around each authd.pass test. */
static int test_setup(void **state) {
    test_mode = 1;
    return 0;
}

static int test_teardown(void **state) {
    test_mode = 0;
    return 0;
}

/* Queue a successful open("r") -> fgets -> close of authd.pass returning `content`. */
static void expect_pass_file_read(const char *content) {
    expect_string(__wrap_wfopen, path, "etc/authd.pass");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, FAKE_FP);

    expect_value(__wrap_fgets, __stream, FAKE_FP);
    will_return(__wrap_fgets, content);

    expect_value(__wrap_fclose, _File, FAKE_FP);
    will_return(__wrap_fclose, 0);
}

/* Queue an open("r") that fails: authd.pass does not exist. */
static void expect_pass_file_open_fail(void) {
    expect_string(__wrap_wfopen, path, "etc/authd.pass");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);
}

/* tests */

static void test_w_generate_random_pass_success(void **state) {
    char* result = NULL;

    will_return(__wrap_os_random, 146557);
    will_return(__wrap_os_random, 314159);
    will_return(__wrap_GetRandomNoise, strdup("Wazuh"));
    will_return(__wrap_GetRandomNoise, strdup("The Open Source Security Platform"));
    will_return(__wrap_time, 1655254875);
    will_return_always(__wrap_getuname, TEST_UNAME);

    result = w_generate_random_pass();

    assert_string_equal(result, TEST_GENERATED_PASS);
    os_free(result);
}

static void test_w_authd_load_password_from_file(void **state) {
    bool generated = true;

    expect_pass_file_read("MyS3cret\n");

    char *result = w_authd_load_password("etc/authd.pass", &generated);

    assert_non_null(result);
    assert_string_equal(result, "MyS3cret");
    assert_false(generated);
    os_free(result);
}

/* A CRLF-authored file (Windows) must trim the trailing \r as well as \n. */
static void test_w_authd_load_password_strips_crlf(void **state) {
    bool generated = true;

    expect_pass_file_read("MyS3cret\r\n");

    char *result = w_authd_load_password("etc/authd.pass", &generated);

    assert_non_null(result);
    assert_string_equal(result, "MyS3cret");
    assert_false(generated);
    os_free(result);
}

/* A first line longer than the read buffer is fatal: never use a truncated password. */
static void test_w_authd_load_password_too_long_is_fatal(void **state) {
    bool generated = false;
    static char longline[5000];

    memset(longline, 'a', sizeof(longline) - 1);
    longline[sizeof(longline) - 1] = '\0';

    expect_pass_file_read(longline);
    expect_string(__wrap__merror_exit, formatted_msg, "Authentication password in 'etc/authd.pass' is too long.");

    expect_assert_failure(w_authd_load_password("etc/authd.pass", &generated));
}

static void test_w_authd_load_password_empty_file_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_read("");   /* empty file content */
    expect_string(__wrap__merror_exit, formatted_msg, "Invalid password provided in 'etc/authd.pass'.");

    expect_assert_failure(w_authd_load_password("etc/authd.pass", &generated));
}

static void test_w_authd_load_password_generate_and_persist(void **state) {
    bool generated = false;

    expect_pass_file_open_fail();   /* file does not exist */

    setup_deterministic_pass();

    /* Open for writing the new password */
    expect_string(__wrap_wfopen, path, "etc/authd.pass");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, FAKE_FP);

    expect_value(__wrap_fprintf, __stream, FAKE_FP);
    expect_string(__wrap_fprintf, formatted_msg, TEST_GENERATED_PASS "\n");
    will_return(__wrap_fprintf, 33);

    expect_value(__wrap_fclose, _File, FAKE_FP);
    will_return(__wrap_fclose, 0);

    char *result = w_authd_load_password("etc/authd.pass", &generated);

    assert_non_null(result);
    assert_string_equal(result, TEST_GENERATED_PASS);
    assert_true(generated);
    os_free(result);
}

static void test_w_authd_load_password_persist_failure_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_open_fail();   /* file does not exist */

    setup_deterministic_pass();

    /* Open for writing fails */
    expect_string(__wrap_wfopen, path, "etc/authd.pass");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, NULL);

    expect_any(__wrap__merror_exit, formatted_msg);

    expect_assert_failure(w_authd_load_password("etc/authd.pass", &generated));
}

/* An existing file whose first line is too short must fail closed (never return NULL,
 * which would silently disable password enrollment). */
static void test_w_authd_load_password_short_line_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_read("x\n");   /* first line too short (strlen 2, not > 2) */
    expect_string(__wrap__merror_exit, formatted_msg, "Invalid password provided in 'etc/authd.pass'.");

    expect_assert_failure(w_authd_load_password("etc/authd.pass", &generated));
}

/* An all-whitespace line passes the length check but must still fail closed: it would
 * otherwise become a valid shared enrollment secret. */
static void test_w_authd_load_password_spaces_only_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_read("      \n");   /* only spaces after CR/LF trim */
    expect_string(__wrap__merror_exit, formatted_msg, "Invalid password provided in 'etc/authd.pass'.");

    expect_assert_failure(w_authd_load_password("etc/authd.pass", &generated));
}

/* An existing, non-empty file that cannot be read (fgets fails) must fail closed too. */
static void test_w_authd_load_password_unreadable_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_read(NULL);   /* read error -> no usable password */
    expect_string(__wrap__merror_exit, formatted_msg, "Invalid password provided in 'etc/authd.pass'.");

    expect_assert_failure(w_authd_load_password("etc/authd.pass", &generated));
}

/* w_authd_read_password (read-only loader used by cluster workers) */

static void test_w_authd_read_password_from_file(void **state) {
    expect_pass_file_read("SyncedPass\n");

    char *result = w_authd_read_password("etc/authd.pass");

    assert_non_null(result);
    assert_string_equal(result, "SyncedPass");
    os_free(result);
}

/* Missing file (e.g. not synchronized yet) must return NULL without generating or aborting. */
static void test_w_authd_read_password_missing_returns_null(void **state) {
    expect_pass_file_open_fail();

    assert_null(w_authd_read_password("etc/authd.pass"));
}

/* An existing file whose first line is too short yields NULL (the caller rejects, never bypasses). */
static void test_w_authd_read_password_short_returns_null(void **state) {
    expect_pass_file_read("x\n");
    expect_string(__wrap__mwarn, formatted_msg, "Authentication password in 'etc/authd.pass' is invalid or empty; ignoring.");

    assert_null(w_authd_read_password("etc/authd.pass"));
}

/* On the worker an all-whitespace file must be ignored (NULL + warn), not synced as a secret. */
static void test_w_authd_read_password_spaces_only_returns_null(void **state) {
    expect_pass_file_read("      \n");
    expect_string(__wrap__mwarn, formatted_msg, "Authentication password in 'etc/authd.pass' is invalid or empty; ignoring.");

    assert_null(w_authd_read_password("etc/authd.pass"));
}

/* CRLF-authored file: the worker reader must trim \r too, matching the master. */
static void test_w_authd_read_password_strips_crlf(void **state) {
    expect_pass_file_read("SyncedPass\r\n");

    char *result = w_authd_read_password("etc/authd.pass");

    assert_non_null(result);
    assert_string_equal(result, "SyncedPass");
    os_free(result);
}

/* An over-long first line yields NULL on the worker (reject), never a truncated password. */
static void test_w_authd_read_password_too_long_returns_null(void **state) {
    static char longline[5000];

    memset(longline, 'a', sizeof(longline) - 1);
    longline[sizeof(longline) - 1] = '\0';

    expect_pass_file_read(longline);
    expect_string(__wrap__mwarn, formatted_msg, "Authentication password in 'etc/authd.pass' is too long; ignoring.");

    assert_null(w_authd_read_password("etc/authd.pass"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_generate_random_pass_success),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_from_file, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_strips_crlf, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_too_long_is_fatal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_empty_file_is_fatal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_generate_and_persist, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_persist_failure_is_fatal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_short_line_is_fatal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_spaces_only_is_fatal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_unreadable_is_fatal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_read_password_from_file, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_read_password_strips_crlf, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_read_password_too_long_returns_null, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_read_password_missing_returns_null, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_read_password_short_returns_null, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_read_password_spaces_only_returns_null, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
