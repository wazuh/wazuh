/*
 * Wazuh authd - enrollment token store
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ENROLLMENT_TOKEN_STORE_H
#define ENROLLMENT_TOKEN_STORE_H

#include <stdint.h>
#include <time.h>

#include "cJSON.h"
#include "enrollment_token.h"

/* Characters of a token identifier: the 16 id bytes as unpadded base64url */
#define ETOKEN_ID_CHARS 22

/* Default lifetime of a token when the caller gives none: 30 days */
#define ETOKEN_DEFAULT_TTL 2592000L

/**
 * @brief One enrollment token as authd keeps it (issue #38993).
 *
 * The master mints, revokes and consumes; the workers hold a read-only replica of the file the
 * cluster synchronises. Exactly one anchor is set: the SPKI pin of the CA (@a has_pin) or the PEM
 * text of the CA itself (@a ca_pem). The credential (@a secret) is optional: a token without one is
 * public information.
 */
typedef struct {
    char id[ETOKEN_ID_CHARS + 1];            /**< Identifier, base64url of the 16 id bytes */
    int has_secret;                          /**< Whether @a secret is set */
    uint8_t secret[W_ETOKEN_SECRET_BYTES];   /**< The credential secret, never logged */
    char *adr;                               /**< Endpoint as written in the token */
    int has_pin;                             /**< Whether @a pin is set */
    uint8_t pin[W_ETOKEN_PIN_BYTES];         /**< SHA-256 of the SubjectPublicKeyInfo of the CA */
    char *ca_pem;                            /**< Embedded CA, or NULL */
    time_t created;                          /**< Mint time */
    time_t expires;                          /**< Absolute expiry */
    unsigned int max_uses;                   /**< 0 = unlimited */
    unsigned int uses;                       /**< Enrollments consumed so far */
    int revoked;                             /**< Set by token_revoke; never cleared */
    char *description;                       /**< Free text from the operator, or NULL */
} etoken_entry_t;

/**
 * @brief What a validated mint request carries into the store (filled by enrollment_token_mint.c).
 *
 * Exactly one of @a has_pin / @a ca_pem must be set. The store generates the id and the secret.
 */
typedef struct {
    char *adr;                               /**< Canonical endpoint (default port/prefix already dropped) */
    int has_pin;
    uint8_t pin[W_ETOKEN_PIN_BYTES];
    char *ca_pem;                            /**< Set when the operator asked to embed the CA */
    long ttl;                                /**< Lifetime in seconds, > 0 */
    unsigned int max_uses;                   /**< 0 = unlimited */
    int no_credential;                       /**< 1: the token carries no `key` (no secret is generated) */
    char *description;                       /**< May be NULL */
} etoken_mint_t;

/**
 * @brief Outcome of consuming one use of a token on an enrollment.
 */
typedef enum {
    ETOKEN_USE_OK = 0,
    ETOKEN_USE_NOT_FOUND,   /**< Unknown id, or revoked (both answer 9022: nothing leaks either way) */
    ETOKEN_USE_EXPIRED,     /**< 9023 */
    ETOKEN_USE_EXHAUSTED    /**< 9024: max_uses reached */
} etoken_use_t;

/**
 * @brief Point the store at its file. Does not read it. Call once, before any other function.
 *
 * @param path Path of the JSON store (ENROLLMENT_TOKENS_FILE, relative to the manager home).
 */
void etoken_store_init(const char *path);

/**
 * @brief Read the file into memory, replacing the in-memory tokens.
 *
 * An absent file is not an error: the store is simply empty. An unreadable or malformed file
 * returns -1, logs a warning and leaves whatever was loaded before untouched.
 *
 * @return 0 on success, -1 on error.
 */
int etoken_store_load(void);

/**
 * @brief Reload the file when its modification time differs from the last load.
 *
 * Cheap (one stat); called before every token verb and every enrollment that presents a token,
 * on masters and workers alike, so a file the cluster just synchronised is seen at once.
 *
 * @return 1 when the file was reloaded, 0 when unchanged or still absent, -1 when the reload failed
 *         (the previous tokens are kept).
 */
int etoken_store_reload_if_changed(void);

/**
 * @brief Mint a token: generate id (and secret unless no_credential), append the entry, persist the
 *        file and encode the token text.
 *
 * @param mint Validated request (ownership stays with the caller).
 * @param now Mint time; expires = now + mint->ttl.
 * @param data Receives {"token", "id", "adr", "expires"[, "pin_hex"]} on success (caller cJSON_Delete()s).
 *             `token` is the only place the secret ever leaves authd.
 * @return 0 on success; -1 when the file could not be written (nothing is kept in memory either).
 */
int etoken_store_create(const etoken_mint_t *mint, time_t now, cJSON **data);

/**
 * @brief The tokens as the operator may see them: no secret, no token text.
 *
 * @return JSON array of {"id", "adr", "created", "expires", "max_uses", "uses", "revoked",
 *         "credential" (bool), "description"}; caller cJSON_Delete()s. Never NULL.
 */
cJSON *etoken_store_list(void);

/**
 * @brief Mark a token revoked and persist the file. Idempotent on an already revoked token.
 *
 * @return 0 on success, -1 when the id is unknown or the file could not be written.
 */
int etoken_store_revoke(const char *id);

/**
 * @brief Consume one use of a token for an enrollment that is about to be performed.
 *
 * Checks, in this order, that the id exists and is not revoked, that it has not expired at @p now
 * and that max_uses (when non-zero) leaves room; then increments `uses` and persists the file.
 * The caller undoes the use with etoken_store_release() if the enrollment itself fails afterwards.
 *
 * @return ETOKEN_USE_OK, or the first violation found.
 */
etoken_use_t etoken_store_consume(const char *id, time_t now);

/**
 * @brief Undo a use reserved by etoken_store_consume() when the enrollment failed. Persists.
 */
void etoken_store_release(const char *id);

/**
 * @brief Number of tokens in memory (revoked ones included).
 */
int etoken_store_count(void);

/**
 * @brief Release every in-memory token and wipe the secrets (tests and shutdown).
 */
void etoken_store_free(void);

/**
 * @brief Release the heap members of a mint request.
 */
void etoken_mint_free(etoken_mint_t *mint);

#endif /* ENROLLMENT_TOKEN_STORE_H */
