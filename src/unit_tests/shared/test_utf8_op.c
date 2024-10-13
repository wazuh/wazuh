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

#include "../../headers/shared.h"
#include "../wrappers/common.h"

// Tests

void test_utf8_random_replace(void **state)
{
    size_t i;
    const size_t LENGTH = 4096;
    char buffer[LENGTH];

    randombytes(buffer, LENGTH - 1);

    /* Avoid zeroes */

    for (i = 0; i < LENGTH - 1; i++) {
        buffer[i] = buffer[i] ? buffer[i] : '0';
    }

    buffer[LENGTH - 1] = '\0';

    char * copy = w_utf8_filter(buffer, true);
    int r = w_utf8_valid(copy);
    free(copy);
}

void test_utf8_random_not_replace(void **state)
{
    size_t i;
    const size_t LENGTH = 4096;
    char buffer[LENGTH];

    randombytes(buffer, LENGTH - 1);

    /* Avoid zeroes */

    for (i = 0; i < LENGTH - 1; i++) {
        buffer[i] = buffer[i] ? buffer[i] : '0';
    }

    buffer[LENGTH - 1] = '\0';

    char * copy = w_utf8_filter(buffer, false);
    int r = w_utf8_valid(copy);
    free(copy);
}

void test_utf8_edge_cases(void **state)
{
    const char * edge_cases[] = {
        "\xF4\x8F\xBF\xBF", // U+10FFFF (highest valid UTF-8 character)
        "\xF4\x90\x80\x80", // Beyond U+10FFFF (invalid)
        NULL
    };

    // Check edge cases
    assert_valid_utf8(edge_cases[0], false, true); // Should be valid
    assert_valid_utf8(edge_cases[1], false, false); // Should be invalid
}

void test_empty_string(void **state) {
    const char *empty = "";
    assert_valid_utf8(empty, false, true); // Should be valid
}

void test_incomplete_utf8_sequences(void **state) {
    const char * incomplete_sequences[] = {
        "\xC2",             // Missing second byte for 2-byte sequence
        "\xE2\x98",         // Missing third byte for 3-byte sequence
        "\xF0\x9F\x98",     // Missing fourth byte for 4-byte sequence
        NULL
    };

    for (int i = 0; incomplete_sequences[i] != NULL; ++i) {
        assert_valid_utf8(incomplete_sequences[i], false, false); // Should be invalid
    }
}

void test_overlong_encodings(void **state) {
    const char * overlong_sequences[] = {
        "\xC0\x80",         // Overlong encoding for null character (U+0000)
        "\xE0\x80\x80",     // Overlong encoding for null character (U+0000)
        "\xF0\x80\x80\x80", // Overlong encoding for null character (U+0000)
        NULL
    };

    for (int i = 0; overlong_sequences[i] != NULL; ++i) {
        assert_valid_utf8(overlong_sequences[i], false, false); // Should be invalid
    }
}

void test_surrogate_pair_boundary(void **state) {
    const char *boundary_cases[] = {
        "\xED\x9F\xBF",     // U+D7FF (valid, just before surrogate range)
        "\xED\xA0\x80",     // U+D800 (invalid, start of surrogate range)
        NULL
    };

    assert_valid_utf8(boundary_cases[0], false, true);  // Should be valid
    assert_valid_utf8(boundary_cases[1], false, false); // Should be invalid
}

void test_maximal_overhead_cases(void **state) {
    const char *maximal_cases[] = {
        "\x7F",             // U+007F (1 byte)
        "\xDF\xBF",         // U+07FF (2 bytes)
        "\xEF\xBF\xBF",     // U+FFFF (3 bytes)
        "\xF4\x8F\xBF\xBF", // U+10FFFF (4 bytes)
        NULL
    };

    for (int i = 0; maximal_cases[i] != NULL; ++i) {
        assert_valid_utf8(maximal_cases[i], false, true); // Should be valid
    }
}

void test_continuation_without_leading(void **state) {
    const char *invalid_continuations[] = {
        "\x80",             // Continuation byte with no leading byte
        "\xA0",             // Invalid continuation byte
        "\xBF",             // Invalid continuation byte
        NULL
    };

    for (int i = 0; invalid_continuations[i] != NULL; ++i) {
        assert_valid_utf8(invalid_continuations[i], false, false); // Should be invalid
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_valid_utf8_sequences),
        cmocka_unit_test(test_invalid_utf8_sequences),
        cmocka_unit_test(test_utf8_random_replace),
        cmocka_unit_test(test_utf8_random_not_replace),
        cmocka_unit_test(test_utf8_edge_cases),
        cmocka_unit_test(test_empty_string),
        cmocka_unit_test(test_incomplete_utf8_sequences),
        cmocka_unit_test(test_overlong_encodings),
        cmocka_unit_test(test_surrogate_pair_boundary),
        cmocka_unit_test(test_maximal_overhead_cases),
        cmocka_unit_test(test_continuation_without_leading)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
