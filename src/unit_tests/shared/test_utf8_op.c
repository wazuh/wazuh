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

// Utility function for verifying the result
void assert_valid_utf8(const char *input, bool replacement, bool expect_valid) {
    char *filtered;
    int result;

    if (replacement) {
        filtered = w_utf8_filter(input, true);
        result = w_utf8_valid(filtered);
        assert_int_equal(result, 1); // After replacement, should be valid
        free(filtered);
    } else {
        result = w_utf8_valid(input);
        if (expect_valid) {
            assert_int_equal(result, 1);
        } else {
            assert_int_equal(result, 0);
        }
    }
}

// Test valid UTF-8 sequences
void test_valid_utf8_sequences(void **state)
{
    const char * valid_sequences[] = {
        "Hello, World!",      // ASCII characters (1-byte each)
        "\xC3\x9C",           // Ü (U+00DC, 2-byte UTF-8)
        "\xC3\xBC",           // ü (U+00FC, 2-byte UTF-8)
        "\xE2\x98\x83",       // ☃ (U+2603, 3-byte UTF-8)
        "\xF0\x9F\x98\x81",   // 😁 (U+1F601, 4-byte UTF-8)
        "Σὲ γνωρίζω",         // Greek text (multi-byte sequences)
        "中文字符",            // Chinese characters (3-byte UTF-8)
        NULL                  // Null-terminated array
    };

    for (int i = 0; valid_sequences[i] != NULL; ++i) {
        assert_valid_utf8(valid_sequences[i], false, true);
        assert_valid_utf8(valid_sequences[i], true, true);
    }
}

// Test invalid UTF-8 sequences
void test_invalid_utf8_sequences(void **state)
{
    const char * invalid_sequences[] = {
        "\xC0\xAF",           // Overlong encoding of '/'
        "\xE0\x80\xAF",       // Overlong encoding (null character U+002F)
        "\xED\xA0\x80",       // UTF-16 surrogate half (invalid in UTF-8)
        "\xF8\x88\x80\x80\x80", // 5-byte sequence (invalid, as UTF-8 only supports up to 4 bytes)
        "\xFF",               // Invalid single byte (not valid in UTF-8)
        "\x80",               // Continuation byte without a start
        "\xC3\x28",           // Invalid 2-byte sequence (invalid second byte)
        NULL                  // Null-terminated array
    };

    for (int i = 0; invalid_sequences[i] != NULL; ++i) {
        assert_valid_utf8(invalid_sequences[i], false, false);
        assert_valid_utf8(invalid_sequences[i], true, true); // Replaced, thus valid output
    }
}

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

    char *copy = w_utf8_filter((char *)buffer, true);
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

    int r = w_utf8_valid((char *)buffer);

    /* The result could be either valid or invalid */
    (void)r; // Use (void) to avoid unused variable warning in case you don't assert
}

void test_utf8_edge_cases(void **state)
{
    const char * edge_cases[] = {
        "\xF4\x8F\xBF\xBF", // U+10FFFF (highest valid UTF-8 character)
        "\xF4\x90\x80\x80", // Beyond U+10FFFF (invalid)
        NULL
    };

    // Check edge cases
    assert_valid_utf8(edge_cases[0], false, true);  // Should be valid
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

void test_surrogate_pair_extended_boundary(void **state) {
    const char *boundary_cases[] = {
        "\xED\x9F\xBF",     // U+D7FF (valid)
        "\xED\xBF\xBF",     // U+DFFF (invalid, end of surrogate range)
        NULL
    };

    assert_valid_utf8(boundary_cases[0], false, true);  // Should be valid
    assert_valid_utf8(boundary_cases[1], false, false); // Should be invalid
}

void test_multilingual_plane_cases(void **state) {
    const char *multilingual_plane_cases[] = {
        "\xF0\x90\x80\x80", // U+10000 (valid, start of SMP)
        "\xF0\x9F\xBF\xBF", // U+1FFFF (valid, end of SMP)
        NULL
    };

    for (int i = 0; multilingual_plane_cases[i] != NULL; ++i) {
        assert_valid_utf8(multilingual_plane_cases[i], false, true); // Should be valid
    }
}

void test_mixed_valid_invalid_utf8(void **state) {
    const char *mixed_cases[] = {
        "Valid\xC0\xAFInvalid", // Mixed: Valid ASCII followed by overlong encoding
        "A\xE0\x80\xAFB",       // Mixed: Valid ASCII, invalid overlong encoding, valid ASCII
        NULL
    };

    for (int i = 0; mixed_cases[i] != NULL; ++i) {
        assert_valid_utf8(mixed_cases[i], false, false); // Should be invalid
    }
}

void test_boundary_cases(void **state){
    const char *boundary_cases[] = {
        "\xED\x80\x80",     // U+D000 (valid, not U+D800)
        "\xED\xA0\x80",     // U+D800 (invalid, start of surrogate range)
        NULL
    };

    assert_valid_utf8(boundary_cases[0], false, true);  // Should be valid
    assert_valid_utf8(boundary_cases[1], false, false); // Should be invalid
}

// New test functions added based on recommendations

void test_surrogate_range_after(void **state) {
    const char *test_case = "\xEE\x80\x80"; // U+E000 (valid, just after surrogate range)
    assert_valid_utf8(test_case, false, true); // Should be valid
}

void test_invalid_start_bytes(void **state) {
    const char *invalid_starts[] = {
        "\xF5\x80\x80\x80", // Invalid start byte beyond 0xF4
        "\xFE",             // Invalid start byte
        NULL
    };

    for (int i = 0; invalid_starts[i] != NULL; ++i) {
        assert_valid_utf8(invalid_starts[i], false, false); // Should be invalid
    }
}

void test_invalid_second_byte_sequences(void **state) {
    const char *invalid_sequences[] = {
        "\xE0\x9F\xBF",     // Invalid second byte for 0xE0 start byte
        "\xF0\x8F\xBF\xBF", // Invalid second byte for 0xF0 start byte
        NULL
    };

    for (int i = 0; invalid_sequences[i] != NULL; ++i) {
        assert_valid_utf8(invalid_sequences[i], false, false); // Should be invalid
    }
}

void test_incomplete_three_byte_sequence(void **state) {
    const char *incomplete_sequence = "\xE2\x82"; // Missing third byte
    assert_valid_utf8(incomplete_sequence, false, false); // Should be invalid
}

void test_mixed_valid_invalid_with_surrogates(void **state) {
    const char *mixed_case = "Test\xED\xA0\x80End"; // Contains invalid surrogate code point
    assert_valid_utf8(mixed_case, false, false); // Should be invalid
}

void test_specific_byte_sequence_boundaries(void **state) {
    const char *test_cases[] = {
        "\xC2\x80",         // Minimum 2-byte sequence (U+0080, valid)
        "\xE0\xA0\x80",     // Minimum 3-byte sequence (U+0800, valid)
        "\xC2\x80\x80",     // Invalid: extra continuation byte
        "\xE0\xA0\x80\x80", // Invalid: extra continuation byte
        NULL
    };

    int expected[] = {1, 1, 0, 0};

    for (int i = 0; test_cases[i] != NULL; ++i) {
        assert_valid_utf8(test_cases[i], false, expected[i]);
    }
}

void test_non_characters(void **state) {
    const char *non_characters[] = {
        "\xEF\xB7\x90", // U+FDD0 (valid but non-character)
        "\xEF\xBF\xBE", // U+FFFE (valid but non-character)
        NULL
    };

    for (int i = 0; non_characters[i] != NULL; ++i) {
        assert_valid_utf8(non_characters[i], false, true); // Should be valid
    }
}

void test_special_unicode_characters(void **state) {
    const char *special_chars[] = {
        "\xE2\x80\x8B", // U+200B Zero-width space
        "\xCC\x81",     // U+0301 Combining acute accent
        NULL
    };

    for (int i = 0; special_chars[i] != NULL; ++i) {
        assert_valid_utf8(special_chars[i], false, true); // Should be valid
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
        cmocka_unit_test(test_continuation_without_leading),
        cmocka_unit_test(test_surrogate_pair_extended_boundary),
        cmocka_unit_test(test_multilingual_plane_cases),
        cmocka_unit_test(test_mixed_valid_invalid_utf8),
        cmocka_unit_test(test_boundary_cases),
        cmocka_unit_test(test_surrogate_range_after),
        cmocka_unit_test(test_invalid_start_bytes),
        cmocka_unit_test(test_invalid_second_byte_sequences),
        cmocka_unit_test(test_incomplete_three_byte_sequence),
        cmocka_unit_test(test_mixed_valid_invalid_with_surrogates),
        cmocka_unit_test(test_specific_byte_sequence_boundaries),
        cmocka_unit_test(test_non_characters),
        cmocka_unit_test(test_special_unicode_characters)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
