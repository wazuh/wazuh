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

/* Longest lifetime a mint accepts: 10 years, already far beyond any rollout a token is minted for.
 *
 * The bound is not about taste. An entry's expiry is `now + ttl` in a signed time_t, and a lifetime
 * near the type's own maximum wraps into a NEGATIVE expiry -- a value the store's own loader
 * refuses (etoken_parse_entry()). One such record is enough to matter: the master persists it,
 * answers success, and at its next restart the file is one the loader drops a token from; the
 * workers receive the same file through the cluster. Refusing the lifetime is what keeps the store
 * something authd can always read back. */
#define ETOKEN_MAX_TTL 315360000L

/* Longest `description` and `prefix` a mint accepts. Free text from an operator, but text that is
 * persisted in the file the cluster replicates and re-serialized on every consumed use, so it is
 * bounded where both the socket and the command line pass rather than left to whatever arrives */
#define ETOKEN_DESCRIPTION_MAX 256
#define ETOKEN_PREFIX_MAX 256

/* Most tokens the store will hold. A mint that would cross it purges the dead entries first and is
 * only refused when that many tokens are still alive. Sized against the file remoted will accept:
 * an entry measures ~240 bytes, or ~1.4 KB when the operator embeds the CA, so 5000 of the widest
 * kind stay under W_ETOKEN_STORE_MAX_BYTES with room to spare (issue #38994) */
#define ETOKEN_MAX_TOKENS 5000

/* What etoken_store_purge() removes */
typedef enum {
    ETOKEN_PURGE_DEAD = 0,  /**< Revoked, expired or out of uses: whatever can no longer authorise an enrollment */
    ETOKEN_PURGE_ALL        /**< Every token, live ones included */
} etoken_purge_t;

/* etoken_store_create() failures the caller reports differently from a plain error */
#define ETOKEN_CREATE_FULL   (-2)  /**< ETOKEN_MAX_TOKENS live tokens: purge before minting again */
#define ETOKEN_CREATE_TOOBIG (-3)  /**< The store would cross W_ETOKEN_STORE_MAX_BYTES */

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
 * @return 0 on success; ETOKEN_CREATE_FULL when the store already holds ETOKEN_MAX_TOKENS live
 *         tokens (the dead ones are purged first, so this means the cap is genuinely in use);
 *         ETOKEN_CREATE_TOOBIG when the resulting file would cross W_ETOKEN_STORE_MAX_BYTES;
 *         -1 on any other failure. Nothing is kept in memory unless the file was written.
 */
int etoken_store_create(const etoken_mint_t *mint, time_t now, cJSON **data);

/**
 * @brief Remove tokens from the store and persist the file.
 *
 * Revoking and purging are different acts: a revoked token stays listed, a purged one is gone. The
 * file is only rewritten when something was actually removed, so a purge with no victims does not
 * wake the watchers that replicate it.
 *
 * @param scope What to remove (ETOKEN_PURGE_DEAD or ETOKEN_PURGE_ALL).
 * @param now Reference time for the expiry check.
 * @param ids Optional; receives a JSON array with the ids removed (caller cJSON_Delete()s).
 * @return Number of tokens removed, or -1 when the file could not be written (the store keeps its
 *         previous content in memory too).
 */
int etoken_store_purge(etoken_purge_t scope, time_t now, cJSON **ids);

/**
 * @brief The tokens as the operator may see them: no secret, no token text.
 *
 * @return JSON array of {"id", "adr", "created", "expires", "max_uses", "uses", "revoked",
 *         "credential" (bool), "description"}; caller cJSON_Delete()s. Never NULL.
 */
cJSON *etoken_store_list(void);

/* etoken_store_revoke() failures the caller reports differently from an unknown id */
#define ETOKEN_STORE_FAILED (-2)  /**< Revoked in memory, but the store could not be written */

/**
 * @brief Mark a token revoked and persist the file.
 *
 * Idempotent on a token that is already revoked **and already written**: that answers 0 without
 * rewriting the file. A revocation that could not be persisted is remembered instead, so this
 * authd stops honouring the token at once and every later call -- this one included -- retries the
 * write until it lands. Success therefore always means "the file says so" (issue #39078, H04).
 *
 * @return 0 on success, -1 when the id is unknown, ETOKEN_STORE_FAILED when it is revoked in
 *         memory but the file could not be written.
 */
int etoken_store_revoke(const char *id);

/**
 * @brief Consume one use of a token for an enrollment that is about to be performed.
 *
 * Checks, in this order, that the id exists and is not revoked, that it has not expired at @p now
 * and that max_uses (when non-zero) leaves room; then increments `uses` and persists the file.
 *
 * The use stays RESERVED until the caller closes it with etoken_store_commit() (the enrollment
 * happened) or etoken_store_release() (it did not, so the use goes back). Exactly one of the two
 * must be called: while a reservation is open the token is never purged as dead, so leaving it
 * open keeps a spent token in the store until authd restarts.
 *
 * @return ETOKEN_USE_OK, or the first violation found.
 */
etoken_use_t etoken_store_consume(const char *id, time_t now);

/**
 * @brief Undo a use reserved by etoken_store_consume() when the enrollment failed. Persists.
 */
void etoken_store_release(const char *id);

/**
 * @brief Close a reservation whose enrollment succeeded. Touches no file: the use is already spent.
 */
void etoken_store_commit(const char *id);

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
