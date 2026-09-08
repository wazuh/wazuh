/*
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ENROLLMENT_TOKEN_H
#define ENROLLMENT_TOKEN_H

#include <stdint.h>

/* Sizes of the binary fields of a token */
#define W_ETOKEN_PIN_BYTES    32
#define W_ETOKEN_ID_BYTES     16
#define W_ETOKEN_SECRET_BYTES 16
#define W_ETOKEN_KEY_BYTES    32

/* Defaults that the `adr` field omits when a token is encoded */
#define W_ETOKEN_DEFAULT_PORT   1517
#define W_ETOKEN_DEFAULT_PREFIX "wazuh-manager"

/**
 * @brief Why a token could not be decoded.
 */
typedef enum {
    ETOKEN_OK = 0,       /**< The token is well formed */
    ETOKEN_MALFORMED,    /**< Not base64url, not a JSON object, or an unknown, duplicate or
                              wrongly typed member */
    ETOKEN_VERSION,      /**< `ver` is not 1 */
    ETOKEN_NO_ANCHOR,    /**< Neither `pin` nor `ca` */
    ETOKEN_BOTH_ANCHORS, /**< Both `pin` and `ca` */
    ETOKEN_BAD_PIN,      /**< `pin` does not decode to exactly 32 bytes */
    ETOKEN_BAD_KEY,      /**< `key` does not decode to exactly 32 bytes */
    ETOKEN_BAD_ADR       /**< `adr` violates the <endpoint> grammar */
} w_etoken_error_t;

/**
 * @brief Decoded enrollment token.
 *
 * Exactly one anchor is carried: either the SPKI pin of the CA (@a has_pin) or the PEM text
 * of the CA itself (@a ca_pem). The credential (@a id and @a secret) is optional.
 */
typedef struct {
    int ver;                                /**< Format version, always 1 */
    char *adr;                              /**< Endpoint, verbatim as written in the token */
    int has_pin;                            /**< Whether @a pin is set */
    uint8_t pin[W_ETOKEN_PIN_BYTES];        /**< SHA-256 of the SubjectPublicKeyInfo of the CA */
    char *ca_pem;                           /**< PEM of the CA when it is embedded, else NULL */
    int has_key;                            /**< Whether @a id and @a secret are set */
    uint8_t id[W_ETOKEN_ID_BYTES];          /**< Token identifier */
    uint8_t secret[W_ETOKEN_SECRET_BYTES];  /**< Token secret */
} w_etoken_t;

/**
 * @brief Encode a token.
 *
 * The JSON object is compact and its members are written in the order `ver`, `adr`,
 * `pin` or `ca`, `key`; the whole text is then base64url encoded without padding. `adr` is
 * normalised on the way out: the default port and the default prefix are dropped.
 *
 * @param token Token to encode.
 * @return Newly allocated NUL-terminated token the caller must free(), or NULL when the
 *         struct is not encodable (no anchor, both anchors, `ver` other than 1, or an
 *         `adr` outside the <endpoint> grammar).
 */
char *w_etoken_encode(const w_etoken_t *token);

/**
 * @brief Decode a token.
 *
 * @param text Token text.
 * @param out Receives the decoded token. Zeroed on error, otherwise owns heap memory that
 *            the caller must release with w_etoken_free().
 * @return ETOKEN_OK, or the first violation found in the order MALFORMED, VERSION,
 *         NO_ANCHOR/BOTH_ANCHORS, BAD_ADR, BAD_PIN, BAD_KEY.
 */
w_etoken_error_t w_etoken_decode(const char *text, w_etoken_t *out);

/**
 * @brief Release a token and wipe its secret.
 *
 * @param token Token to release. The struct itself is left zeroed.
 */
void w_etoken_free(w_etoken_t *token);

/**
 * @brief Render a token for a human, without any credential material.
 *
 * The identifier, the secret and the `key` field never reach the output: only the version,
 * the endpoint, the anchor (pin in hexadecimal, or the subject, issuer, validity window and
 * SHA-256 of the embedded CA) and whether a credential is present.
 *
 * @param token Token to describe.
 * @return Newly allocated multi-line text the caller must free(), or NULL on error.
 */
char *w_etoken_describe(const w_etoken_t *token);

/**
 * @brief Derive the HS256 key of a token credential.
 *
 * HKDF-SHA256 in extract-and-expand mode over the 16 secret bytes, with a 32 zero byte salt
 * and the info label "WAZUH-ENROLL-TOKEN-KEY" followed by the version byte 0x01 -- the same
 * construction as shared_modules/utils/jwt/enrollKeyDerivation.hpp with its own label.
 *
 * @param secret The 16 secret bytes of the token.
 * @param out Receives the 32 bytes of the key.
 * @return 0 on success, -1 on error.
 */
int w_etoken_derive_key(const uint8_t secret[W_ETOKEN_SECRET_BYTES],
                        uint8_t out[W_ETOKEN_KEY_BYTES]);

/**
 * @brief Message of a decoding error.
 *
 * @param err Error code.
 * @return A static, never NULL, description.
 */
const char *w_etoken_strerror(w_etoken_error_t err);

#endif /* ENROLLMENT_TOKEN_H */
