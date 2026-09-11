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
#include "enrollment_token.h"

/* The CA of the frozen test material (public), the one PIN_HEX pins */
#define ROOT_CA_PEM \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIIDSzCCAjOgAwIBAgIUJP7/SAPLSdxLbWKDzjDp88k4AAAwDQYJKoZIhvcNAQEL\n" \
    "BQAwNTEOMAwGA1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApD\n" \
    "YWxpZm9ybmlhMB4XDTI2MDQxNDEzNTAzN1oXDTM2MDQxMTEzNTAzN1owNTEOMAwG\n" \
    "A1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApDYWxpZm9ybmlh\n" \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQFyQMfZg9BkCde6Sa6O\n" \
    "8834rzeI81clYfEuDjflnwUTyp6BwHZTZ4F/cOBchKt2ZtnNR7Vx2wU5muDdF1QR\n" \
    "xnzDEV3vqETcGN7dxarYQtNCuvi/V0Zm0rme9Q9tW8u4iVwhva/jB5VJuDxlREfH\n" \
    "RL9pcjf9Dmvr1A9QRBgN0gsofAPri6gi8fLOfqddyNhLDHVd4BhYvB4wgxN5gXs/\n" \
    "KOCPGBhIuBb7BbdZDXMm+1PrBebZ1PgL1NEN4dtLQEq7/JXsJpeh8HGsH+WA91V7\n" \
    "HRI6O2nsT7YEiw4lGK/DfNroPrQ+G5Qq+Ouy5Z+8NnWV/WJu6tsv2TtqVCNG2Ift\n" \
    "vwIDAQABo1MwUTAdBgNVHQ4EFgQU2CaFfHEP1s0zMeo5QL/yLQl69EAwHwYDVR0j\n" \
    "BBgwFoAU2CaFfHEP1s0zMeo5QL/yLQl69EAwDwYDVR0TAQH/BAUwAwEB/zANBgkq\n" \
    "hkiG9w0BAQsFAAOCAQEAW2F0iQS92w4Q1im3ijS9qg2rnLuzrFeLkbhDNc1P4UIR\n" \
    "Wst/FKUV0MsYBvbotf2gNWSZEsKqDV5kYB4Ad1RUFIJGq0HEnrLEIgXZDgUkHaLQ\n" \
    "2FXSWDbq4Q3tROB2SiXk61Md6HOvfgT4/MYx/IoZB3fE8pP0vINA/TPw6WZsbz+K\n" \
    "93PEjHaMASUlUoowImFgV4uxzgfVWYWcUwi+IUehMqBgU3apvZ1ntUgw8CZTR7BQ\n" \
    "E3f6uPqaFJnQg2NZpc0bST6iF/bwKemDhdtd0pwgTivB3RrgSDjBqcR0DGTCKydU\n" \
    "gifB+SqxOI0UFNS5zvIQzUTRxMVDcdnB4NnkcZ/CBQ==\n" \
    "-----END CERTIFICATE-----\n"

/* Frozen vectors, computed with an independent Python oracle and mirrored on the C++ side
 * in shared_modules/utils/jwt/testVectors.hpp.
 */
#define PIN_HEX     "6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2"
#define PIN_B64URL  "YJHcNmXtXoM8jZRfk-u_FLNwIMzudzNORJesLvNZCqI"
#define ID_B64URL   "AAECAwQFBgcICQoLDA0ODw"
#define SEC_B64URL  "EBESExQVFhcYGRobHB0eHw"
#define KEY_B64URL  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
#define DERIVED_HEX "5da72b786a15757caa8d825a74a3474c3f15b048fd1064b49863ffc715a95860"

#define TOKEN_PIN_ONLY \
    "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCIsInBpbiI6IllKSGNObVh0WG9NOGpaUmZrLXVf" \
    "RkxOd0lNenVkek5PUkplc0x2TlpDcUkifQ"

#define TOKEN_WITH_KEY \
    "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCIsInBpbiI6IllKSGNObVh0WG9NOGpaUmZrLXVf" \
    "RkxOd0lNenVkek5PUkplc0x2TlpDcUkiLCJrZXkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZ" \
    "WEdCa2FHeHdkSGg4In0"

#define TOKEN_PORT_PREFIX \
    "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbDo4NDQzL3dhenVoLyIsInBpbiI6IllKSGNObVh0" \
    "WG9NOGpaUmZrLXVfRkxOd0lNenVkek5PUkplc0x2TlpDcUkifQ"

/* The 32 bytes PIN_HEX names */
static const uint8_t PIN_BYTES[W_ETOKEN_PIN_BYTES] = {
    0x60, 0x91, 0xdc, 0x36, 0x65, 0xed, 0x5e, 0x83, 0x3c, 0x8d, 0x94, 0x5f, 0x93, 0xeb,
    0xbf, 0x14, 0xb3, 0x70, 0x20, 0xcc, 0xee, 0x77, 0x33, 0x4e, 0x44, 0x97, 0xac, 0x2e,
    0xf3, 0x59, 0x0a, 0xa2
};

static void hex_of(const uint8_t *bytes, size_t len, char *out)
{
    size_t i;

    for (i = 0; i < len; i++) {
        snprintf(out + i * 2, 3, "%02x", bytes[i]);
    }
}

/* A token pinning the frozen CA, on `adr`, optionally carrying id 0x00..0x0f and secret
 * 0x10..0x1f. The caller releases it with w_etoken_free().
 */
static void make_token(w_etoken_t *token, const char *adr, int with_key)
{
    int i;

    memset(token, 0, sizeof(*token));
    token->ver = 1;
    token->adr = strdup(adr);
    assert_non_null(token->adr);
    token->has_pin = 1;
    memcpy(token->pin, PIN_BYTES, sizeof(PIN_BYTES));

    if (with_key) {
        token->has_key = 1;

        for (i = 0; i < W_ETOKEN_ID_BYTES; i++) {
            token->id[i] = (uint8_t) i;
            token->secret[i] = (uint8_t) (0x10 + i);
        }
    }
}

/* The JSON text a token wraps */
static char *json_of(const char *token)
{
    uint8_t *raw = NULL;
    size_t len = 0;
    char *json = NULL;

    assert_int_equal(w_b64url_decode(token, &raw, &len), 0);
    json = (char *) calloc(len + 1, sizeof(char));
    assert_non_null(json);
    memcpy(json, raw, len);
    free(raw);

    return json;
}

/* Wrap a JSON text into a token */
static char *token_of(const char *json)
{
    char *token = w_b64url_encode((const uint8_t *) json, strlen(json));

    assert_non_null(token);

    return token;
}

static void assert_decode_error(const char *json, w_etoken_error_t expected)
{
    char *token = token_of(json);
    w_etoken_t decoded;

    assert_int_equal(w_etoken_decode(token, &decoded), expected);
    assert_null(decoded.adr);
    w_etoken_free(&decoded);
    free(token);
}

static void assert_adr_error(const char *adr, w_etoken_error_t expected)
{
    char json[512];

    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"%s\",\"pin\":\"%s\"}", adr,
             PIN_B64URL);
    assert_decode_error(json, expected);
}

static void assert_adr_accepted(const char *adr)
{
    char json[512];
    char *token = NULL;
    w_etoken_t decoded;

    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"%s\",\"pin\":\"%s\"}", adr,
             PIN_B64URL);
    token = token_of(json);
    assert_int_equal(w_etoken_decode(token, &decoded), ETOKEN_OK);
    assert_string_equal(decoded.adr, adr);
    w_etoken_free(&decoded);
    free(token);
}

/* w_etoken_encode */

void test_encode_matches_the_frozen_vectors(void **state)
{
    w_etoken_t token;
    char *encoded = NULL;

    (void) state;

    make_token(&token, "siem.example.local", 0);
    encoded = w_etoken_encode(&token);
    assert_non_null(encoded);
    assert_string_equal(encoded, TOKEN_PIN_ONLY);
    assert_int_equal(strlen(encoded), 118);
    free(encoded);
    w_etoken_free(&token);

    make_token(&token, "siem.example.local", 1);
    encoded = w_etoken_encode(&token);
    assert_non_null(encoded);
    assert_string_equal(encoded, TOKEN_WITH_KEY);
    assert_int_equal(strlen(encoded), 187);
    free(encoded);
    w_etoken_free(&token);

    make_token(&token, "siem.example.local:8443/wazuh/", 0);
    encoded = w_etoken_encode(&token);
    assert_non_null(encoded);
    assert_string_equal(encoded, TOKEN_PORT_PREFIX);
    assert_int_equal(strlen(encoded), 134);
    free(encoded);
    w_etoken_free(&token);
}

void test_encode_rejects_an_unusable_struct(void **state)
{
    w_etoken_t token;

    (void) state;

    assert_null(w_etoken_encode(NULL));

    /* No anchor */
    make_token(&token, "h", 0);
    token.has_pin = 0;
    assert_null(w_etoken_encode(&token));

    /* Both anchors */
    token.has_pin = 1;
    token.ca_pem = strdup(ROOT_CA_PEM);
    assert_non_null(token.ca_pem);
    assert_null(w_etoken_encode(&token));

    /* Unknown version */
    free(token.ca_pem);
    token.ca_pem = NULL;
    token.ver = 2;
    assert_null(w_etoken_encode(&token));

    w_etoken_free(&token);
}

void test_encode_omits_defaults(void **state)
{
    static const char *cases[][2] = {
        {"h:1517/wazuh-manager", "\"adr\":\"h\""},
        {"h:1517/wazuh-manager/", "\"adr\":\"h\""},
        {"h:1517", "\"adr\":\"h\""},
        {"h/wazuh-manager", "\"adr\":\"h\""},
        {"h/", "\"adr\":\"h/\""},
        {"h:8443", "\"adr\":\"h:8443\""},
        {"h:8443/wazuh/", "\"adr\":\"h:8443/wazuh/\""},
        {"[2001:db8::1]:1517", "\"adr\":\"[2001:db8::1]\""}
    };
    size_t i;

    (void) state;

    for (i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        w_etoken_t token;
        char *encoded = NULL;
        char *json = NULL;

        make_token(&token, cases[i][0], 0);
        encoded = w_etoken_encode(&token);
        assert_non_null(encoded);
        json = json_of(encoded);
        assert_non_null(strstr(json, cases[i][1]));
        free(json);
        free(encoded);
        w_etoken_free(&token);
    }
}

/* w_etoken_decode */

void test_decode_roundtrip_and_defaults(void **state)
{
    w_etoken_t decoded;
    int i;

    (void) state;

    assert_int_equal(w_etoken_decode(TOKEN_PIN_ONLY, &decoded), ETOKEN_OK);
    assert_int_equal(decoded.ver, 1);
    assert_string_equal(decoded.adr, "siem.example.local");
    assert_int_equal(decoded.has_pin, 1);
    assert_memory_equal(decoded.pin, PIN_BYTES, sizeof(PIN_BYTES));
    assert_null(decoded.ca_pem);
    assert_int_equal(decoded.has_key, 0);
    w_etoken_free(&decoded);

    assert_int_equal(w_etoken_decode(TOKEN_WITH_KEY, &decoded), ETOKEN_OK);
    assert_string_equal(decoded.adr, "siem.example.local");
    assert_int_equal(decoded.has_key, 1);

    for (i = 0; i < W_ETOKEN_ID_BYTES; i++) {
        assert_int_equal(decoded.id[i], i);
        assert_int_equal(decoded.secret[i], 0x10 + i);
    }

    w_etoken_free(&decoded);

    /* The address is kept exactly as written: normalising is an encoding step only */
    assert_int_equal(w_etoken_decode(TOKEN_PORT_PREFIX, &decoded), ETOKEN_OK);
    assert_string_equal(decoded.adr, "siem.example.local:8443/wazuh/");
    assert_int_equal(decoded.has_key, 0);
    w_etoken_free(&decoded);
}

void test_decode_errors(void **state)
{
    char json[4096];
    char *short_pin = NULL;
    char *long_key = NULL;
    uint8_t bytes[33];
    size_t i;

    (void) state;

    /* Not base64url at all */
    {
        w_etoken_t decoded;

        assert_int_equal(w_etoken_decode("!!!", &decoded), ETOKEN_MALFORMED);
        w_etoken_free(&decoded);
        assert_int_equal(w_etoken_decode(NULL, &decoded), ETOKEN_MALFORMED);
        w_etoken_free(&decoded);
    }

    assert_decode_error("{\"ver\":1", ETOKEN_MALFORMED);
    assert_decode_error("[1]", ETOKEN_MALFORMED);
    assert_decode_error("\"a string\"", ETOKEN_MALFORMED);

    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"h\",\"pin\":\"%s\",\"x\":1}",
             PIN_B64URL);
    assert_decode_error(json, ETOKEN_MALFORMED);

    /* Duplicate member */
    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"h\",\"adr\":\"h\",\"pin\":\"%s\"}",
             PIN_B64URL);
    assert_decode_error(json, ETOKEN_MALFORMED);

    /* Wrongly typed members */
    snprintf(json, sizeof(json), "{\"ver\":\"1\",\"adr\":\"h\",\"pin\":\"%s\"}", PIN_B64URL);
    assert_decode_error(json, ETOKEN_MALFORMED);
    assert_decode_error("{\"ver\":1,\"adr\":1,\"pin\":1}", ETOKEN_MALFORMED);

    snprintf(json, sizeof(json), "{\"ver\":2,\"adr\":\"h\",\"pin\":\"%s\"}", PIN_B64URL);
    assert_decode_error(json, ETOKEN_VERSION);
    assert_decode_error("{\"adr\":\"h\",\"pin\":\"" PIN_B64URL "\"}", ETOKEN_VERSION);

    assert_decode_error("{\"ver\":1,\"adr\":\"h\"}", ETOKEN_NO_ANCHOR);

    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"h\",\"pin\":\"%s\",\"ca\":\"%s\"}",
             PIN_B64URL, "-----BEGIN CERTIFICATE-----");
    assert_decode_error(json, ETOKEN_BOTH_ANCHORS);

    /* 31 bytes: canonical base64url, wrong length */
    short_pin = w_b64url_encode(PIN_BYTES, sizeof(PIN_BYTES) - 1);
    assert_non_null(short_pin);
    assert_int_equal(strlen(short_pin), 42);
    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"h\",\"pin\":\"%s\"}", short_pin);
    assert_decode_error(json, ETOKEN_BAD_PIN);
    free(short_pin);

    /* A pin that is not canonical base64url is a bad pin too */
    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"h\",\"pin\":\"%s==\"}", PIN_B64URL);
    assert_decode_error(json, ETOKEN_BAD_PIN);

    /* 33 bytes: canonical base64url, wrong length */
    for (i = 0; i < sizeof(bytes); i++) {
        bytes[i] = (uint8_t) i;
    }

    long_key = w_b64url_encode(bytes, sizeof(bytes));
    assert_non_null(long_key);
    assert_int_equal(strlen(long_key), 44);
    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"h\",\"pin\":\"%s\",\"key\":\"%s\"}",
             PIN_B64URL, long_key);
    assert_decode_error(json, ETOKEN_BAD_KEY);
    free(long_key);

    /* A bad address is reported before a bad pin */
    snprintf(json, sizeof(json), "{\"ver\":1,\"adr\":\"h:0\",\"pin\":\"nope\"}");
    assert_decode_error(json, ETOKEN_BAD_ADR);
}

void test_decode_checks_the_address_grammar(void **state)
{
    static const char *invalid[] = {
        "https://h",       /* a scheme is not part of the grammar */
        "h:0",             /* port out of range */
        "h:70000",         /* port out of range */
        "h:+80",           /* no sign */
        "h:",              /* empty port */
        "h/a b",           /* space in the prefix */
        "[fe80::1%eth0]",  /* the zone identifier must be percent encoded */
        "[2001:db8::1",    /* unclosed bracket */
        "-bad-.example",   /* label starting with a hyphen */
        "bad-.example",    /* label ending with a hyphen */
        "a..b",            /* empty label */
        ""                 /* no host */
    };
    static const char *valid[] = {
        "siem.example.local",
        "192.0.2.10",
        "manager.example.com:8443/gateway",
        "[2001:db8::1]:1517",
        "[fe80::1%25eth0]",
        "h/",
        "h",
        "h:65535/a/b/c"
    };
    size_t i;

    (void) state;

    for (i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        assert_adr_error(invalid[i], ETOKEN_BAD_ADR);
    }

    for (i = 0; i < sizeof(valid) / sizeof(*valid); i++) {
        assert_adr_accepted(valid[i]);
    }
}

/* w_etoken_free */

void test_free_zeroes_the_secret(void **state)
{
    w_etoken_t token;
    uint8_t zeroes[W_ETOKEN_SECRET_BYTES];

    (void) state;

    memset(zeroes, 0, sizeof(zeroes));
    make_token(&token, "siem.example.local", 1);
    w_etoken_free(&token);

    assert_null(token.adr);
    assert_null(token.ca_pem);
    assert_int_equal(token.has_key, 0);
    assert_int_equal(token.has_pin, 0);
    assert_int_equal(token.ver, 0);
    assert_memory_equal(token.secret, zeroes, sizeof(zeroes));
    assert_memory_equal(token.id, zeroes, W_ETOKEN_ID_BYTES);

    /* A second release, and a NULL one, must be harmless */
    w_etoken_free(&token);
    w_etoken_free(NULL);
}

/* w_etoken_describe */

void test_describe_never_prints_the_key(void **state)
{
    w_etoken_t decoded;
    w_etoken_t token;
    char *text = NULL;

    (void) state;

    assert_int_equal(w_etoken_decode(TOKEN_WITH_KEY, &decoded), ETOKEN_OK);
    text = w_etoken_describe(&decoded);
    assert_non_null(text);

    assert_non_null(strstr(text, "ver: 1"));
    assert_non_null(strstr(text, "adr: siem.example.local"));
    assert_non_null(strstr(text, PIN_HEX));
    assert_non_null(strstr(text, "credential: present"));

    assert_null(strstr(text, SEC_B64URL));
    assert_null(strstr(text, ID_B64URL));
    assert_null(strstr(text, KEY_B64URL));
    assert_null(strstr(text, "key"));

    free(text);
    w_etoken_free(&decoded);

    /* An embedded CA is described, never dumped as PEM */
    memset(&token, 0, sizeof(token));
    token.ver = 1;
    token.adr = strdup("siem.example.local");
    assert_non_null(token.adr);
    token.ca_pem = strdup(ROOT_CA_PEM);
    assert_non_null(token.ca_pem);

    text = w_etoken_describe(&token);
    assert_non_null(text);
    assert_non_null(strstr(text, "ca subject: "));
    assert_non_null(strstr(text, "Wazuh"));
    assert_non_null(strstr(text, "ca issuer: "));
    assert_non_null(strstr(text, "ca not before: "));
    assert_non_null(strstr(text, "ca not after: "));
    assert_non_null(strstr(text, "ca sha256: "));
    assert_non_null(strstr(text, "credential: absent"));
    assert_null(strstr(text, "-----BEGIN CERTIFICATE-----"));
    assert_null(strstr(text, "key"));

    free(text);
    w_etoken_free(&token);

    assert_null(w_etoken_describe(NULL));
}

/* w_etoken_derive_key */

void test_derive_key_matches_the_cpp_vector(void **state)
{
    uint8_t secret[W_ETOKEN_SECRET_BYTES];
    uint8_t other[W_ETOKEN_SECRET_BYTES];
    uint8_t key[W_ETOKEN_KEY_BYTES];
    uint8_t key_of_zeroes[W_ETOKEN_KEY_BYTES];
    char hex[W_ETOKEN_KEY_BYTES * 2 + 1];
    int i;

    (void) state;

    for (i = 0; i < W_ETOKEN_SECRET_BYTES; i++) {
        secret[i] = (uint8_t) (0x10 + i);
    }

    assert_int_equal(w_etoken_derive_key(secret, key), 0);
    hex_of(key, sizeof(key), hex);
    assert_string_equal(hex, DERIVED_HEX);

    memset(other, 0, sizeof(other));
    assert_int_equal(w_etoken_derive_key(other, key_of_zeroes), 0);
    assert_memory_not_equal(key_of_zeroes, key, sizeof(key));

    assert_int_equal(w_etoken_derive_key(NULL, key), -1);
    assert_int_equal(w_etoken_derive_key(secret, NULL), -1);
}

/* w_etoken_strerror */

void test_strerror_covers_every_code(void **state)
{
    int code;

    (void) state;

    for (code = ETOKEN_OK; code <= ETOKEN_BAD_ADR; code++) {
        const char *message = w_etoken_strerror((w_etoken_error_t) code);

        assert_non_null(message);
        assert_true(strlen(message) > 0);
    }

    assert_string_equal(w_etoken_strerror((w_etoken_error_t) 99), "unknown error");
}

/* A token is a canonical encoding of its content: one text, one token, and nothing in the text that
 * the decoder does not look at. An embedded NUL breaks all three at once, because cJSON takes the
 * document's length from strlen() -- so everything past the NUL is parsed by nobody, checked by
 * nobody and wiped by nobody, while the base64url layer below still says the two texts differ.
 */
void test_decode_rejects_an_embedded_nul(void **state)
{
    const char valid[] = "{\"ver\":1,\"adr\":\"h\",\"pin\":\"" PIN_B64URL "\"}";
    uint8_t blob[512];
    size_t len;
    char *token = NULL;
    w_etoken_t decoded;

    (void) state;

    /* A whole, valid token followed by a NUL and then anything at all. Accepting this would mean
     * unlimited different texts decoding to one token -- exactly what b64url_op.h promises cannot
     * happen -- and it would make any bound on the token's length unenforceable on input */
    len = strlen(valid);
    assert_true(len + 32 < sizeof(blob));
    memcpy(blob, valid, len);
    blob[len] = '\0';
    memcpy(blob + len + 1, "{\"ver\":1,\"adr\":\"o\"}", 19);

    token = w_b64url_encode(blob, len + 1 + 19);
    assert_non_null(token);
    assert_int_equal(w_etoken_decode(token, &decoded), ETOKEN_MALFORMED);
    assert_null(decoded.adr);
    w_etoken_free(&decoded);
    free(token);

    /* A NUL anywhere else is no different: the parser would only ever see the prefix */
    memcpy(blob, valid, len);
    blob[8] = '\0';
    token = w_b64url_encode(blob, len);
    assert_non_null(token);
    assert_int_equal(w_etoken_decode(token, &decoded), ETOKEN_MALFORMED);
    w_etoken_free(&decoded);
    free(token);

    /* A trailing NUL is not a "harmless terminator" either: the same content has one canonical
     * text, and this is not it */
    memcpy(blob, valid, len);
    blob[len] = '\0';
    token = w_b64url_encode(blob, len + 1);
    assert_non_null(token);
    assert_int_equal(w_etoken_decode(token, &decoded), ETOKEN_MALFORMED);
    w_etoken_free(&decoded);
    free(token);

    /* And the same bytes without the NUL still decode: what is refused is the NUL, not the token */
    token = token_of(valid);
    assert_int_equal(w_etoken_decode(token, &decoded), ETOKEN_OK);
    assert_string_equal(decoded.adr, "h");
    w_etoken_free(&decoded);
    free(token);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_encode_matches_the_frozen_vectors),
        cmocka_unit_test(test_encode_rejects_an_unusable_struct),
        cmocka_unit_test(test_encode_omits_defaults),
        cmocka_unit_test(test_decode_roundtrip_and_defaults),
        cmocka_unit_test(test_decode_errors),
        cmocka_unit_test(test_decode_rejects_an_embedded_nul),
        cmocka_unit_test(test_decode_checks_the_address_grammar),
        cmocka_unit_test(test_free_zeroes_the_secret),
        cmocka_unit_test(test_describe_never_prints_the_key),
        cmocka_unit_test(test_derive_key_matches_the_cpp_vector),
        cmocka_unit_test(test_strerror_covers_every_code)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
