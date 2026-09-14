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
#include <string.h>

#include "reenroll_verify.h"

/* w_reenroll_verify() is authd's C door into the shared JWT verifier (shared_modules/utils/jwt/, C++). Nothing
 * is wrapped here: the point of these cases is that the bridge, the HKDF and the verifier reached through it
 * give the verdict the other implementations (remoted, the agent, the Go sender, the Python oracle) give for
 * the same frozen vector.
 *
 * The vector is enroll_token::kAgentKidJwt / kReenrollSecretHex / kAgentKid of jwt/testVectors.hpp: secret
 * bytes 00..1f, `kid` "001", iat/nbf 1700000000, exp +60, jti of bytes 00..0f, signed HS256 with
 * HKDF-SHA256(secret, salt 32 x 00, "WAZUH-REENROLL-KEY" || 0x01). Copied, not included: that header is C++. */
static const char kAgentKidJwt[] =
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ."
    "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH0."
    "waWOzsJ3GP5kj1tOAEdpWNBzjqbjGPSqE039h8irCKc";
static const char kSecretHex[] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char kAgentKid[] = "001";
#define K_IAT 1700000000L
/* remoted's defaults for remoted.jwt_max_age / remoted.jwt_clock_skew, the pair authd reads. */
#define K_MAX_AGE 60
#define K_SKEW    30

static void test_vector_verifies_within_the_window(void **state) {
    (void)state;
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_OK);
    /* The boundary the profile allows: exactly max_age old is still accepted. */
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + K_MAX_AGE, K_MAX_AGE, K_SKEW), W_REENROLL_OK);
    /* An out-of-range pair (max_age 0) falls back to the profile defaults, it never widens or zeroes the window. */
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + 10, 0, 0), W_REENROLL_OK);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + 9999, 0, 0), W_REENROLL_STALE);
}

static void test_wrong_secret_is_invalid(void **state) {
    (void)state;
    /* Same shape, last byte differs: the derived key differs, the signature does not verify. */
    static const char other_secret[] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1e";
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, other_secret, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
}

static void test_another_agent_id_is_invalid(void **state) {
    (void)state;
    /* Correctly signed for "001", presented as agent "002": the header's kid must name the agent the request
     * names -- a bearer is never verified against a key it did not ask for. */
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, "002", kSecretHex, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, "1", kSecretHex, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
}

static void test_outside_the_window_is_stale(void **state) {
    (void)state;
    /* Too old, and issued in the future beyond the skew: both clock-relative, both stale -- never invalid,
     * so the caller can tell a clock problem from a forged credential. The profile's window is
     * max_age + skew on the old side (jwtProfileV1.hpp: 90 s by default) and skew on the future side. */
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + 9999, K_MAX_AGE, K_SKEW), W_REENROLL_STALE);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + K_MAX_AGE + K_SKEW, K_MAX_AGE, K_SKEW), W_REENROLL_OK);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + K_MAX_AGE + K_SKEW + 1, K_MAX_AGE, K_SKEW), W_REENROLL_STALE);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT - K_SKEW, K_MAX_AGE, K_SKEW), W_REENROLL_OK);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT - K_SKEW - 1, K_MAX_AGE, K_SKEW), W_REENROLL_STALE);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT - 1000, K_MAX_AGE, K_SKEW), W_REENROLL_STALE);
    /* The window is the configured one -- the two knobs reach the verifier. The bearer's own exp (iat + 60,
     * a fixed lifetime) is also judged against the skew, so a wider skew is what lets an older bearer through;
     * a wider max_age alone cannot outlive the exp rule. */
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + 100, K_MAX_AGE, 0), W_REENROLL_STALE);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + 100, K_MAX_AGE, 40), W_REENROLL_OK);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, kSecretHex, K_IAT + 9999, K_MAX_AGE, 43200), W_REENROLL_OK);
}

static void test_garbage_and_bad_arguments_are_invalid(void **state) {
    (void)state;
    assert_int_equal(w_reenroll_verify("not.a.jwt", kAgentKid, kSecretHex, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
    assert_int_equal(w_reenroll_verify("", kAgentKid, kSecretHex, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
    assert_int_equal(w_reenroll_verify(NULL, kAgentKid, kSecretHex, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, NULL, kSecretHex, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, NULL, K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
    /* A secret that is not exactly 64 lowercase hex chars is not a secret: 63 chars, and uppercase. */
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1",
                                       K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
    assert_int_equal(w_reenroll_verify(kAgentKidJwt, kAgentKid, "000102030405060708090A0B0C0D0E0F101112131415161718191a1b1c1d1e1f",
                                       K_IAT + 10, K_MAX_AGE, K_SKEW), W_REENROLL_INVALID);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_vector_verifies_within_the_window),
        cmocka_unit_test(test_wrong_secret_is_invalid),
        cmocka_unit_test(test_another_agent_id_is_invalid),
        cmocka_unit_test(test_outside_the_window_is_stale),
        cmocka_unit_test(test_garbage_and_bad_arguments_are_invalid),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
