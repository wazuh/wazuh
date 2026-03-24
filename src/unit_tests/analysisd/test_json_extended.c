/*
 * Copyright (C) 2026, Wazuh Inc.
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

#include "../../analysisd/format/json_extended.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Setup/Teardown */

static int setup_group(void **state) {
    (void) state;
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    return 0;
}

/* Helper function to allocate result buffers */
static void allocate_results(char* results[MAX_MATCHES]) {
    for (int i = 0; i < MAX_MATCHES; i++) {
        results[i] = calloc(MAX_STRING_LESS, sizeof(char));
        assert_non_null(results[i]);
    }
}

/* Helper function to free result buffers */
static void free_results(char* results[MAX_MATCHES]) {
    for (int i = 0; i < MAX_MATCHES; i++) {
        free(results[i]);
    }
}

/* Tests for match_regex - Buffer Overflow Fix Validation */

/**
 * Test 1: Normal case - match within buffer limits
 */
void test_match_regex_normal_short_match(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    const char* input = "Test {CIS: 1.2.3} end";
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    count = match_regex(r, input, results);

    assert_int_equal(count, 1);
    assert_string_equal(results[0], "CIS: 1.2.3");

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 2: Boundary case - match exactly at 29 bytes (safe)
 */
void test_match_regex_boundary_29_bytes(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    // Create a 29-byte match (MAX_STRING_LESS - 1)
    const char* input = "Test {KEY: 123456789012345678901234} end";  // "KEY: 123456789012345678901234" = 29 bytes
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    count = match_regex(r, input, results);

    assert_int_equal(count, 1);
    assert_int_equal(strlen(results[0]), 29);

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 3: SECURITY TEST - Oversized match gets truncated (buffer overflow prevention)
 * This test validates the fix for the heap buffer overflow vulnerability
 */
void test_match_regex_oversized_match_truncated(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    // Create a match > MAX_STRING_LESS bytes (would overflow without fix)
    char input[500];
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    // Create an 82-byte match (40 'A's + ": " + 40 'a's = 82 bytes) to test truncation
    snprintf(input, sizeof(input),
             "Test {AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: "
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa} end");

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    // Expect debug message about truncation
    expect_string(__wrap__mdebug1, formatted_msg, "Match length (82) exceeds buffer size, truncating to 29.");

    count = match_regex(r, input, results);

    // Should still return a result, but truncated
    assert_int_equal(count, 1);
    // Result must not overflow buffer (max 29 bytes + null terminator)
    assert_int_equal(strlen(results[0]), 29);
    // Buffer must be null-terminated
    assert_int_equal(results[0][29], '\0');

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 4: SECURITY TEST - Maximum payload (402 bytes like PoC)
 */
void test_match_regex_exploit_payload_402_bytes(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    char input[500];
    char key[210];
    char value[210];
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    // Replicate exact PoC payload: 200-byte key + 200-byte value
    memset(key, 'A', 200);
    key[200] = '\0';
    memset(value, 'a', 200);
    value[200] = '\0';

    snprintf(input, sizeof(input), "System Audit: {%s: %s}.", key, value);

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    expect_string(__wrap__mdebug1, formatted_msg, "Match length (402) exceeds buffer size, truncating to 29.");

    count = match_regex(r, input, results);

    assert_int_equal(count, 1);
    // Must be truncated to 29 bytes
    assert_int_equal(strlen(results[0]), 29);
    // First 29 bytes should be 'A's (the key)
    for (int i = 0; i < 29; i++) {
        assert_int_equal(results[0][i], 'A');
    }
    assert_int_equal(results[0][29], '\0');

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 5: Multiple matches within limits
 */
void test_match_regex_multiple_matches(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    const char* input = "Test {CIS: 1.2.3} and {PCI: 2.4} and {GDPR: IV}";
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    count = match_regex(r, input, results);

    assert_int_equal(count, 3);
    assert_string_equal(results[0], "CIS: 1.2.3");
    assert_string_equal(results[1], "PCI: 2.4");
    assert_string_equal(results[2], "GDPR: IV");

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 6: SECURITY TEST - Max matches boundary (MAX_MATCHES = 10)
 */
void test_match_regex_max_matches_limit(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    // Create input with 15 matches (more than MAX_MATCHES)
    const char* input = "{A: 1} {B: 2} {C: 3} {D: 4} {E: 5} "
                        "{F: 6} {G: 7} {H: 8} {I: 9} {J: 10} "
                        "{K: 11} {L: 12} {M: 13} {N: 14} {O: 15}";
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    expect_string(__wrap__mdebug1, formatted_msg, "Maximum results reached (10), stopping.");

    count = match_regex(r, input, results);

    // Should stop at MAX_MATCHES
    assert_int_equal(count, MAX_MATCHES);
    assert_string_equal(results[0], "A: 1");
    assert_string_equal(results[9], "J: 10");

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 7: No matches found
 */
void test_match_regex_no_matches(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    const char* input = "No compliance tags here";
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    count = match_regex(r, input, results);

    assert_int_equal(count, 0);

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 8: SECURITY TEST - Null termination is guaranteed
 */
void test_match_regex_null_termination(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    char input[200];
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    // Create a match that will be truncated
    memset(input, 0, sizeof(input));
    snprintf(input, sizeof(input), "{KEY: %s}", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    allocate_results(results);
    // Fill buffer with non-zero to test null termination
    memset(results[0], 'X', MAX_STRING_LESS);

    r = compile_regex(pattern);
    assert_non_null(r);

    expect_string(__wrap__mdebug1, formatted_msg, "Match length (47) exceeds buffer size, truncating to 29.");

    count = match_regex(r, input, results);

    assert_int_equal(count, 1);
    // Defensive null termination must be present at position 29
    assert_int_equal(results[0][29], '\0');
    // String length must be valid (not reading past buffer)
    assert_true(strlen(results[0]) <= 29);

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 9: Mixed normal and oversized matches
 */
void test_match_regex_mixed_sizes(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    const char* input = "{SHORT: 1} {VERYLONGKEYYYYYYYYYYYYYYYYYYYYYYYYYY: "
                        "VERYLONGVALUEEEEEEEEEEEEEEEEEEEEE} {NORMAL: ok}";
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    expect_string(__wrap__mdebug1, formatted_msg, "Match length (71) exceeds buffer size, truncating to 29.");

    count = match_regex(r, input, results);

    assert_int_equal(count, 3);
    assert_string_equal(results[0], "SHORT: 1");
    assert_int_equal(strlen(results[1]), 29);  // Truncated
    assert_string_equal(results[2], "NORMAL: ok");

    free_results(results);
    regfree(r);
    free(r);
}

/**
 * Test 10: Empty match
 */
void test_match_regex_empty_match(void **state) {
    (void) state;

    const char* pattern = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    const char* input = "Test {} end";
    char* results[MAX_MATCHES];
    regex_t* r;
    int count;

    allocate_results(results);
    r = compile_regex(pattern);
    assert_non_null(r);

    count = match_regex(r, input, results);

    // Empty braces won't match the pattern (requires key: value)
    assert_int_equal(count, 0);

    free_results(results);
    regfree(r);
    free(r);
}

/* Main test suite */
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_match_regex_normal_short_match),
        cmocka_unit_test(test_match_regex_boundary_29_bytes),
        cmocka_unit_test(test_match_regex_oversized_match_truncated),
        cmocka_unit_test(test_match_regex_exploit_payload_402_bytes),
        cmocka_unit_test(test_match_regex_multiple_matches),
        cmocka_unit_test(test_match_regex_max_matches_limit),
        cmocka_unit_test(test_match_regex_no_matches),
        cmocka_unit_test(test_match_regex_null_termination),
        cmocka_unit_test(test_match_regex_mixed_sizes),
        cmocka_unit_test(test_match_regex_empty_match),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
