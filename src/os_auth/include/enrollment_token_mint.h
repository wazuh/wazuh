/*
 * Wazuh authd - enrollment token mint validation
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ENROLLMENT_TOKEN_MINT_H
#define ENROLLMENT_TOKEN_MINT_H

#include <stddef.h>

#include "enrollment_token_store.h"

/**
 * @brief A `token_create` request as it arrives on auth.sock, before validation.
 */
typedef struct {
    const char *address;     /**< Host the agents will connect to: DNS name or IP literal (mandatory) */
    long port;               /**< 0: take remote.https.port from the configuration */
    const char *prefix;      /**< NULL: take remote.https.global_prefix; "" means "no prefix" (host/) */
    long ttl;                /**< 0: ETOKEN_DEFAULT_TTL */
    unsigned int max_uses;   /**< 0: unlimited */
    int embed_ca;            /**< 1: carry the CA PEM instead of its pin */
    int no_credential;       /**< 1: no `key` in the token */
    const char *description; /**< May be NULL */
} etoken_mint_request_t;

/**
 * @brief Validate a mint request against the running listener and build what the store needs.
 *
 * Reads the `remote` section of etc/wazuh-manager.conf (w_mconf_section(), already loaded by
 * authd_read_config()) for `https.port`, `https.global_prefix`, `https.certificate` and
 * `https.ca_certificate`; loads the listener certificate and refuses when @p address is not in its
 * subject alternative names, when those names are loopback only, when the CA file cannot be read or
 * when the CA does not sign the listener certificate. Warns when @p address is an IP literal. The
 * pin is the SPKI SHA-256 of the CA as it is on disk right now.
 *
 * @param req The request.
 * @param out Receives the validated mint on success (release with etoken_mint_free()).
 * @param detail Receives the human-readable reason of a refusal, e.g.
 *               "address not in certificate SAN".
 * @param detail_size Size of @p detail.
 * @return 0 on success; -1 when refused (@p detail set); -2 on an internal error (@p detail set).
 */
int etoken_mint_prepare(const etoken_mint_request_t *req, etoken_mint_t *out, char *detail, size_t detail_size);

#endif /* ENROLLMENT_TOKEN_MINT_H */
