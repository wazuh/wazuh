/*
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Unpadded base64url (RFC 4648 section 5) helpers.
 *
 * The encoder reuses encode_base64() from b64.c and rewrites the alphabet; the decoder is
 * written from scratch because decode_base64() silently skips characters outside the
 * base64 alphabet and returns a C string, which can neither reject a non-canonical text nor
 * carry binary data safely.
 */

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "b64url_op.h"

/* Value of a base64url character, or -1 when the character is outside the alphabet */
static int b64url_sextet(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '-') {
        return 62;
    }
    if (c == '_') {
        return 63;
    }

    return -1;
}

char *w_b64url_encode(const uint8_t *in, size_t len)
{
    char *encoded = NULL;
    char *p = NULL;

    if (len == 0) {
        char *empty = (char *) malloc(1);

        if (empty != NULL) {
            empty[0] = '\0';
        }

        return empty;
    }

    if (in == NULL || len > (size_t) (INT_MAX / 4) * 3) {
        return NULL;
    }

    if ((encoded = encode_base64((int) len, (const char *) in)) == NULL) {
        return NULL;
    }

    for (p = encoded; *p != '\0'; p++) {
        if (*p == '+') {
            *p = '-';
        } else if (*p == '/') {
            *p = '_';
        } else if (*p == '=') {
            /* Padding is never part of a base64url token field */
            *p = '\0';
            break;
        }
    }

    return encoded;
}

int w_b64url_decode(const char *in, uint8_t **out, size_t *out_len)
{
    size_t len = 0;
    size_t rest = 0;
    size_t size = 0;
    size_t i = 0;
    size_t o = 0;
    int zero_bits = 0;
    uint8_t *buf = NULL;

    if (out != NULL) {
        *out = NULL;
    }

    if (out_len != NULL) {
        *out_len = 0;
    }

    if (in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    if ((len = strlen(in)) == 0) {
        return -1;
    }

    /* A trailing group of one character cannot come from any byte string */
    if ((rest = len % 4) == 1) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        if (b64url_sextet(in[i]) < 0) {
            return -1;
        }
    }

    /* The bits the last character does not carry must be zero, otherwise two different
     * texts would decode to the same bytes.
     */
    if (rest != 0) {
        zero_bits = (rest == 2) ? 4 : 2;

        if ((b64url_sextet(in[len - 1]) & ((1 << zero_bits) - 1)) != 0) {
            return -1;
        }
    }

    size = (len / 4) * 3 + ((rest == 0) ? 0 : rest - 1);

    if ((buf = (uint8_t *) malloc(size)) == NULL) {
        return -1;
    }

    for (i = 0, o = 0; i < len; i += 4) {
        size_t chunk = len - i;
        int sextets[4];
        int j;

        if (chunk > 4) {
            chunk = 4;
        }

        for (j = 0; j < 4; j++) {
            sextets[j] = ((size_t) j < chunk) ? b64url_sextet(in[i + j]) : 0;
        }

        buf[o++] = (uint8_t) ((sextets[0] << 2) | (sextets[1] >> 4));

        if (chunk > 2) {
            buf[o++] = (uint8_t) (((sextets[1] & 0x0F) << 4) | (sextets[2] >> 2));
        }

        if (chunk > 3) {
            buf[o++] = (uint8_t) (((sextets[2] & 0x03) << 6) | sextets[3]);
        }
    }

    *out = buf;
    *out_len = size;

    return 0;
}
