/*
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef B64URL_OP_H
#define B64URL_OP_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Encode a byte string as unpadded base64url (RFC 4648 section 5).
 *
 * The output uses the URL-safe alphabet ('-' and '_' instead of '+' and '/') and carries
 * no '=' padding, which is the form every Wazuh token field is written in.
 *
 * @param in Bytes to encode. May be NULL only when @p len is 0.
 * @param len Number of bytes to encode. 0 yields the empty string.
 * @return Newly allocated NUL-terminated string the caller must free(), or NULL on error.
 */
char *w_b64url_encode(const uint8_t *in, size_t len);

/**
 * @brief Decode a *canonical* unpadded base64url string.
 *
 * Strict on purpose: only 'A'-'Z', 'a'-'z', '0'-'9', '-' and '_' are accepted, '=' padding
 * and the standard alphabet ('+', '/') are rejected, a length of 4n+1 is rejected and the
 * unused trailing bits of the last character must be zero. Two different texts can therefore
 * never decode to the same bytes (RFC 7515 section 2, RFC 8725 section 3.12). This mirrors
 * isCanonicalBase64Url() in shared_modules/utils/jwt/base64Url.hpp.
 *
 * @param in NUL-terminated text to decode. NULL or empty is an error.
 * @param out Receives a newly allocated buffer the caller must free(). Binary safe.
 * @param out_len Receives the number of decoded bytes.
 * @return 0 on success; -1 on any violation, with *out set to NULL and *out_len to 0.
 */
int w_b64url_decode(const char *in, uint8_t **out, size_t *out_len);

#endif /* B64URL_OP_H */
