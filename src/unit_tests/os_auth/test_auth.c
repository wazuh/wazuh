/*
 * Copyright (C) Wazuh Inc.
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
#include "../wrappers/externals/openssl/rand_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/externals/pcre2/pcre2_wrappers.h"

/* The fake (non-NULL) FILE* handed back by the wfopen mock. */
#define FAKE_FP ((FILE *)1)

/* The generated password is CSPRNG output, so there is no literal to compare against: what the
 * tests pin is its shape (AUTHD_PASS_HEX_CHARS lowercase hex) and that the value written to
 * AUTHD_PASS is the very value returned to the caller. */
static int is_lower_hex_pass(const char *s) {
    size_t i;

    if (!s || strlen(s) != AUTHD_PASS_HEX_CHARS) {
        return 0;
    }
    for (i = 0; i < AUTHD_PASS_HEX_CHARS; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* The password line handed to fprintf by the last generate+persist test, captured by
 * check_persisted_pass_line() so the test can compare it with what the function returned. */
static char persisted_pass[AUTHD_PASS_HEX_CHARS + 1];

/* fprintf's formatted_msg check: "<64 lowercase hex>\n", captured into persisted_pass. */
static int check_persisted_pass_line(const LargestIntegralType value,
                                     const LargestIntegralType check_data) {
    (void)check_data;
    const char *line = (const char *)value;

    assert_non_null(line);
    assert_int_equal(strlen(line), AUTHD_PASS_HEX_CHARS + 1);
    assert_int_equal(line[AUTHD_PASS_HEX_CHARS], '\n');

    memcpy(persisted_pass, line, AUTHD_PASS_HEX_CHARS);
    persisted_pass[AUTHD_PASS_HEX_CHARS] = '\0';
    assert_true(is_lower_hex_pass(persisted_pass));
    return 1;
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
    expect_string(__wrap_wfopen, path, AUTHD_PASS);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, FAKE_FP);

    expect_value(__wrap_fgets, __stream, FAKE_FP);
    will_return(__wrap_fgets, content);

    expect_value(__wrap_fclose, _File, FAKE_FP);
    will_return(__wrap_fclose, 0);
}

/* Queue an open("r") that fails: authd.pass does not exist. */
static void expect_pass_file_open_fail(void) {
    expect_string(__wrap_wfopen, path, AUTHD_PASS);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);
}

/* tests */

static void test_w_generate_random_pass_success(void **state) {
    will_return(__wrap_RAND_bytes, 1); /* pass through to the real CSPRNG */

    char *result = w_generate_random_pass();

    assert_non_null(result);
    assert_true(is_lower_hex_pass(result));
    os_free(result);
}

/* Two passwords in a row must differ: the value comes from the CSPRNG, not from a
 * timestamp/hostname mix that repeats within the same second on the same host. */
static void test_w_generate_random_pass_values_differ(void **state) {
    will_return(__wrap_RAND_bytes, 1);
    will_return(__wrap_RAND_bytes, 1);

    char *first = w_generate_random_pass();
    char *second = w_generate_random_pass();

    assert_non_null(first);
    assert_non_null(second);
    assert_string_not_equal(first, second);
    os_free(first);
    os_free(second);
}

/* Fail closed: no weaker fallback generator when the CSPRNG fails. */
static void test_w_generate_random_pass_csprng_failure(void **state) {
    will_return(__wrap_RAND_bytes, 0); /* do not pass through... */
    will_return(__wrap_RAND_bytes, 0); /* ...and report failure */
    expect_string(__wrap__merror, formatted_msg,
                  "Unable to generate an enrollment password: the CSPRNG (RAND_bytes) failed.");

    assert_null(w_generate_random_pass());
}

static void test_w_authd_load_password_from_file(void **state) {
    bool generated = true;

    expect_pass_file_read("MyS3cret\n");

    char *result = w_authd_load_password(AUTHD_PASS, &generated);

    assert_non_null(result);
    assert_string_equal(result, "MyS3cret");
    assert_false(generated);
    os_free(result);
}

/* A CRLF-authored file (Windows) must trim the trailing \r as well as \n. */
static void test_w_authd_load_password_strips_crlf(void **state) {
    bool generated = true;

    expect_pass_file_read("MyS3cret\r\n");

    char *result = w_authd_load_password(AUTHD_PASS, &generated);

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
    expect_string(__wrap__merror_exit, formatted_msg, "Authentication password in '" AUTHD_PASS "' is too long.");

    expect_assert_failure(w_authd_load_password(AUTHD_PASS, &generated));
}

static void test_w_authd_load_password_empty_file_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_read("");   /* empty file content */
    expect_string(__wrap__merror_exit, formatted_msg, "Invalid password provided in '" AUTHD_PASS "'.");

    expect_assert_failure(w_authd_load_password(AUTHD_PASS, &generated));
}

static void test_w_authd_load_password_generate_and_persist(void **state) {
    bool generated = false;

    expect_pass_file_open_fail();   /* file does not exist */

    will_return(__wrap_RAND_bytes, 1); /* pass through to the real CSPRNG */

    /* Open for writing the new password */
    expect_string(__wrap_wfopen, path, AUTHD_PASS);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, FAKE_FP);

    expect_value(__wrap_fprintf, __stream, FAKE_FP);
    expect_check(__wrap_fprintf, formatted_msg, check_persisted_pass_line, 0);
    will_return(__wrap_fprintf, AUTHD_PASS_HEX_CHARS + 1);

    expect_value(__wrap_fclose, _File, FAKE_FP);
    will_return(__wrap_fclose, 0);

    persisted_pass[0] = '\0';

    char *result = w_authd_load_password(AUTHD_PASS, &generated);

    assert_non_null(result);
    assert_true(is_lower_hex_pass(result));
    /* What was written is what the caller got: the file and the in-memory password cannot diverge. */
    assert_string_equal(result, persisted_pass);
    assert_true(generated);
    os_free(result);
}

/* A CSPRNG failure must leave AUTHD_PASS alone: no wfopen("w") is expected here, so any
 * attempt to create the file fails the test before merror_exit() is even reached. */
static void test_w_authd_load_password_csprng_failure_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_open_fail();   /* file does not exist */

    will_return(__wrap_RAND_bytes, 0);
    will_return(__wrap_RAND_bytes, 0);
    expect_string(__wrap__merror, formatted_msg,
                  "Unable to generate an enrollment password: the CSPRNG (RAND_bytes) failed.");
    expect_string(__wrap__merror_exit, formatted_msg, "Unable to generate random password. Exiting.");

    expect_assert_failure(w_authd_load_password(AUTHD_PASS, &generated));
}

static void test_w_authd_load_password_persist_failure_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_open_fail();   /* file does not exist */

    will_return(__wrap_RAND_bytes, 1); /* pass through to the real CSPRNG */

    /* Open for writing fails */
    expect_string(__wrap_wfopen, path, AUTHD_PASS);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, NULL);

    expect_any(__wrap__merror_exit, formatted_msg);

    expect_assert_failure(w_authd_load_password(AUTHD_PASS, &generated));
}

/* An existing file whose first line is too short must fail closed (never return NULL,
 * which would silently disable password enrollment). */
static void test_w_authd_load_password_short_line_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_read("x\n");   /* first line too short (strlen 2, not > 2) */
    expect_string(__wrap__merror_exit, formatted_msg, "Invalid password provided in '" AUTHD_PASS "'.");

    expect_assert_failure(w_authd_load_password(AUTHD_PASS, &generated));
}

/* An all-whitespace line passes the length check but must still fail closed: it would
 * otherwise become a valid shared enrollment secret. */
static void test_w_authd_load_password_spaces_only_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_read("      \n");   /* only spaces after CR/LF trim */
    expect_string(__wrap__merror_exit, formatted_msg, "Invalid password provided in '" AUTHD_PASS "'.");

    expect_assert_failure(w_authd_load_password(AUTHD_PASS, &generated));
}

/* An existing, non-empty file that cannot be read (fgets fails) must fail closed too. */
static void test_w_authd_load_password_unreadable_is_fatal(void **state) {
    bool generated = false;

    expect_pass_file_read(NULL);   /* read error -> no usable password */
    expect_string(__wrap__merror_exit, formatted_msg, "Invalid password provided in '" AUTHD_PASS "'.");

    expect_assert_failure(w_authd_load_password(AUTHD_PASS, &generated));
}

/* w_authd_read_password (read-only loader used by cluster workers) */

static void test_w_authd_read_password_from_file(void **state) {
    expect_pass_file_read("SyncedPass\n");

    char *result = w_authd_read_password(AUTHD_PASS);

    assert_non_null(result);
    assert_string_equal(result, "SyncedPass");
    os_free(result);
}

/* Missing file (e.g. not synchronized yet) must return NULL without generating or aborting. */
static void test_w_authd_read_password_missing_returns_null(void **state) {
    expect_pass_file_open_fail();

    assert_null(w_authd_read_password(AUTHD_PASS));
}

/* An existing file whose first line is too short yields NULL (the caller rejects, never bypasses). */
static void test_w_authd_read_password_short_returns_null(void **state) {
    expect_pass_file_read("x\n");
    expect_string(__wrap__mwarn, formatted_msg, "Authentication password in '" AUTHD_PASS "' is invalid or empty; ignoring.");

    assert_null(w_authd_read_password(AUTHD_PASS));
}

/* On the worker an all-whitespace file must be ignored (NULL + warn), not synced as a secret. */
static void test_w_authd_read_password_spaces_only_returns_null(void **state) {
    expect_pass_file_read("      \n");
    expect_string(__wrap__mwarn, formatted_msg, "Authentication password in '" AUTHD_PASS "' is invalid or empty; ignoring.");

    assert_null(w_authd_read_password(AUTHD_PASS));
}

/* CRLF-authored file: the worker reader must trim \r too, matching the master. */
static void test_w_authd_read_password_strips_crlf(void **state) {
    expect_pass_file_read("SyncedPass\r\n");

    char *result = w_authd_read_password(AUTHD_PASS);

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
    expect_string(__wrap__mwarn, formatted_msg, "Authentication password in '" AUTHD_PASS "' is too long; ignoring.");

    assert_null(w_authd_read_password(AUTHD_PASS));
}

/* The insertion queue is what the writer turns into the global.db row: the address must be queued
 * as it was registered, a network keeping its mask, as client.keys does. */
extern struct keynode *queue_insert;
extern struct keynode * volatile *insert_tail;

static void free_queued_inserts(void) {
    struct keynode *cur = queue_insert;

    while (cur) {
        struct keynode *next = cur->next;
        os_free(cur->id);
        os_free(cur->name);
        os_free(cur->ip);
        os_free(cur->group);
        os_free(cur->raw_key);
        os_free(cur->reenroll_secret);
        os_free(cur);
        cur = next;
    }
    queue_insert = NULL;
    insert_tail = &queue_insert;
}

/* Queues an entry registered with `registered`, built the way OS_AddKey() builds it (the mask kept
 * apart from the address text), through add_insert() or add_rotate(). */
static void queue_registered(const char *registered, int rotate) {
    keyentry entry;
    char *slash;

    memset(&entry, 0, sizeof(entry));

    os_calloc(1, sizeof(os_ip), entry.ip);
    /* Parse with the real PCRE2: this binary wraps it with mocks by default. */
    w_test_pcre2_wrappers(false);
    assert_int_not_equal(OS_IsValidIP(registered, entry.ip), 0);
    w_test_pcre2_wrappers(true);
    if ((slash = strchr(entry.ip->ip, '/')) != NULL) {
        *slash = '\0';
    }
    entry.id = (char *)"001";
    entry.name = (char *)"agent1";
    entry.raw_key = (char *)"key";

    free_queued_inserts();
    if (rotate) {
        add_rotate(&entry, NULL, "secret", 0);
    } else {
        add_insert(&entry, NULL, NULL, 0);
    }
    w_free_os_ip(entry.ip);

    assert_non_null(queue_insert);
}

static void test_add_insert_keeps_the_mask_of_an_ipv4_network(void **state) {
    queue_registered("10.9.0.0/24", 0);
    assert_string_equal(queue_insert->ip, "10.9.0.0/24");
    free_queued_inserts();
}

static void test_add_rotate_keeps_the_mask_of_an_ipv4_network(void **state) {
    queue_registered("10.9.0.0/24", 1);
    assert_string_equal(queue_insert->ip, "10.9.0.0/24");
    assert_true(queue_insert->rotate);
    free_queued_inserts();
}

static void test_add_insert_queues_a_host_address_unchanged(void **state) {
    queue_registered("192.168.1.10", 0);
    assert_string_equal(queue_insert->ip, "192.168.1.10");
    free_queued_inserts();
}

static void test_add_insert_queues_any_unchanged(void **state) {
    queue_registered("any", 0);
    assert_string_equal(queue_insert->ip, "any");
    free_queued_inserts();
}

static void test_add_insert_keeps_the_mask_of_an_ipv6_network(void **state) {
    queue_registered("fd00:1::/64", 0);
    const size_t len = strlen(queue_insert->ip);
    assert_true(len > 3);
    assert_string_equal(queue_insert->ip + len - 3, "/64");
    free_queued_inserts();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_generate_random_pass_success),
        cmocka_unit_test(test_w_generate_random_pass_values_differ),
        cmocka_unit_test(test_w_generate_random_pass_csprng_failure),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_from_file, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_strips_crlf, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_too_long_is_fatal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_empty_file_is_fatal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_generate_and_persist, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_authd_load_password_csprng_failure_is_fatal, test_setup, test_teardown),
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
        cmocka_unit_test(test_add_insert_keeps_the_mask_of_an_ipv4_network),
        cmocka_unit_test(test_add_rotate_keeps_the_mask_of_an_ipv4_network),
        cmocka_unit_test(test_add_insert_queues_a_host_address_unchanged),
        cmocka_unit_test(test_add_insert_queues_any_unchanged),
        cmocka_unit_test(test_add_insert_keeps_the_mask_of_an_ipv6_network),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
