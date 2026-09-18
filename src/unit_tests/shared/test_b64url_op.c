/*
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
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

#include "shared.h"

/* Frozen vectors, shared with the C++ side (shared_modules/utils/jwt/testVectors.hpp) and
 * with the Python oracle of the enrollment token design.
 */
#define LOW_B64URL  "AAECAwQFBgcICQoLDA0ODw"
#define HIGH_B64URL "EBESExQVFhcYGRobHB0eHw"
#define PIN_B64URL  "YJHcNmXtXoM8jZRfk-u_FLNwIMzudzNORJesLvNZCqI"
#define PIN_HEX     "6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2"

/* The 32 bytes PIN_HEX names */
static const uint8_t PIN_BYTES[32] = {
    0x60, 0x91, 0xdc, 0x36, 0x65, 0xed, 0x5e, 0x83, 0x3c, 0x8d, 0x94, 0x5f, 0x93, 0xeb,
    0xbf, 0x14, 0xb3, 0x70, 0x20, 0xcc, 0xee, 0x77, 0x33, 0x4e, 0x44, 0x97, 0xac, 0x2e,
    0xf3, 0x59, 0x0a, 0xa2
};

/* Bytes 0x00..0x0f and 0x10..0x1f */
static void fill_range(uint8_t *out, uint8_t first)
{
    int i;

    for (i = 0; i < 16; i++) {
        out[i] = (uint8_t) (first + i);
    }
}

/* w_b64url_encode */

void test_encode_known_bytes(void **state)
{
    uint8_t bytes[16];
    char *encoded = NULL;

    (void) state;

    fill_range(bytes, 0x00);
    encoded = w_b64url_encode(bytes, sizeof(bytes));
    assert_non_null(encoded);
    assert_string_equal(encoded, LOW_B64URL);
    free(encoded);

    fill_range(bytes, 0x10);
    encoded = w_b64url_encode(bytes, sizeof(bytes));
    assert_non_null(encoded);
    assert_string_equal(encoded, HIGH_B64URL);
    free(encoded);

    encoded = w_b64url_encode(PIN_BYTES, sizeof(PIN_BYTES));
    assert_non_null(encoded);
    assert_string_equal(encoded, PIN_B64URL);
    assert_int_equal(strlen(encoded), 43);
    free(encoded);
}

void test_encode_empty_is_the_empty_string(void **state)
{
    char *encoded = NULL;

    (void) state;

    encoded = w_b64url_encode(NULL, 0);
    assert_non_null(encoded);
    assert_string_equal(encoded, "");
    free(encoded);

    assert_null(w_b64url_encode(NULL, 1));
}

/* w_b64url_decode */

void test_decode_known_bytes(void **state)
{
    uint8_t expected[16];
    uint8_t *decoded = NULL;
    size_t len = 0;

    (void) state;

    fill_range(expected, 0x00);
    assert_int_equal(w_b64url_decode(LOW_B64URL, &decoded, &len), 0);
    assert_int_equal(len, sizeof(expected));
    assert_memory_equal(decoded, expected, sizeof(expected));
    free(decoded);
    decoded = NULL;

    fill_range(expected, 0x10);
    assert_int_equal(w_b64url_decode(HIGH_B64URL, &decoded, &len), 0);
    assert_int_equal(len, sizeof(expected));
    assert_memory_equal(decoded, expected, sizeof(expected));
    free(decoded);
    decoded = NULL;

    assert_int_equal(w_b64url_decode(PIN_B64URL, &decoded, &len), 0);
    assert_int_equal(len, sizeof(PIN_BYTES));
    assert_memory_equal(decoded, PIN_BYTES, sizeof(PIN_BYTES));
    free(decoded);
}

void test_decode_rejects_noncanonical(void **state)
{
    static const char *invalid[] = {
        "AAECAwQFBgcICQoLDA0ODw==", /* padded */
        "AAEC+wQF/gcICQoLDA0ODw",   /* standard alphabet */
        "AAECA",                    /* length 4n + 1 */
        "AAECAwQFBgcICQoLDA0ODx",   /* non-zero trailing bits */
        "",                         /* empty */
        NULL                        /* no input */
    };
    uint8_t *decoded = NULL;
    size_t len = 0;
    size_t i;

    (void) state;

    for (i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        decoded = (uint8_t *) 0x1;
        len = 1;
        assert_int_equal(w_b64url_decode(invalid[i], &decoded, &len), -1);
        assert_null(decoded);
        assert_int_equal(len, 0);
    }
}

void test_decode_roundtrips_every_length(void **state)
{
    uint8_t bytes[24];
    uint8_t *decoded = NULL;
    size_t len = 0;
    size_t size;

    (void) state;

    fill_range(bytes, 0x00);
    fill_range(bytes + 8, 0x08);

    for (size = 1; size <= sizeof(bytes); size++) {
        char *encoded = w_b64url_encode(bytes, size);

        assert_non_null(encoded);
        assert_null(strchr(encoded, '='));
        assert_int_equal(w_b64url_decode(encoded, &decoded, &len), 0);
        assert_int_equal(len, size);
        assert_memory_equal(decoded, bytes, size);
        free(decoded);
        free(encoded);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_encode_known_bytes),
        cmocka_unit_test(test_encode_empty_is_the_empty_string),
        cmocka_unit_test(test_decode_known_bytes),
        cmocka_unit_test(test_decode_rejects_noncanonical),
        cmocka_unit_test(test_decode_roundtrips_every_length)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
