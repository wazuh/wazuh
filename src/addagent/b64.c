/*
 * Copyright (C), 2000-2004 by the monit project group.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* base64 encoding/decoding
 * Author: Jan-Henrik Haukeland <hauk@tildeslash.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRUE    1
#define FALSE   0

/* Prototypes */
static int is_base64(char c);
static char encode(unsigned char u);
static unsigned char decode(char c);

/* Global variables */
char *decode_base64(const char *src);
char *encode_base64(int size, char *src);


/* Base64 encode and return size data in 'src'. The caller must free the
 * returned string.
 * Returns encoded string otherwise NULL
 */
char *encode_base64(int size, char *src)
{
    int i;
    char *out, *p;

    if (!src) {
        return NULL;
    }

    if (!size) {
        size = strlen((char *)src);
    }

    out = (char *)calloc(sizeof(char), size * 4 / 3 + 4);
    if (!out) {
        return NULL;
    }

    p = out;

    for (i = 0; i < size; i += 3) {
        unsigned char b1 = 0, b2 = 0, b3 = 0, b4 = 0, b5 = 0, b6 = 0, b7 = 0;

        b1 = src[i];

        if (i + 1 < size) {
            b2 = src[i + 1];
        }

        if (i + 2 < size) {
            b3 = src[i + 2];
        }

        b4 = b1 >> 2;
        b5 = ((b1 & 0x3) << 4) | (b2 >> 4);
        b6 = ((b2 & 0xf) << 2) | (b3 >> 6);
        b7 = b3 & 0x3f;

        *p++ = encode(b4);
        *p++ = encode(b5);

        if (i + 1 < size) {
            *p++ = encode(b6);
        } else {
            *p++ = '=';
        }

        if (i + 2 < size) {
            *p++ = encode(b7);
        } else {
            *p++ = '=';
        }
    }

    return out;
}

/* Decode the base64 encoded string 'src' into the memory pointed to by
 * 'dest'. The dest buffer is NUL terminated.
 * Returns NULL in case of error
 */
char *decode_base64(const char *src)
{
    if (src && *src) {
        char *dest;
        unsigned char *p;
        int k, l = strlen(src) + 1;
        unsigned char *buf;

        /* The size of the dest will always be less than the source */
        dest = (char *)calloc(sizeof(char), l + 13);
        if (!dest) {
            return (NULL);
        }

        p = (unsigned char *)dest;

        buf = (unsigned char *) malloc(l);
        if (!buf) {
            free(dest);
            return (NULL);
        }

        /* Ignore non base64 chars as per the POSIX standard */
        for (k = 0, l = 0; src[k]; k++) {
            if (is_base64(src[k])) {
                buf[l++] = src[k];
            }
        }

        for (k = 0; k < l; k += 4) {
            char c1 = 'A', c2 = 'A', c3 = 'A', c4 = 'A';
            unsigned char b1 = 0, b2 = 0, b3 = 0, b4 = 0;

            c1 = buf[k];

            if (k + 1 < l) {
                c2 = buf[k + 1];
            }

            if (k + 2 < l) {
                c3 = buf[k + 2];
            }

            if (k + 3 < l) {
                c4 = buf[k + 3];
            }

            b1 = decode(c1);
            b2 = decode(c2);
            b3 = decode(c3);
            b4 = decode(c4);

            *p++ = ((b1 << 2) | (b2 >> 4) );

            if (c3 != '=') {
                *p++ = (((b2 & 0xf) << 4) | (b3 >> 2) );
            }

            if (c4 != '=') {
                *p++ = (((b3 & 0x3) << 6) | b4 );
            }

        }

        free(buf);

        return (dest);
    }
    return (NULL);
}

static char encode(unsigned char u)
{
    if (u < 26) {
        return 'A' + u;
    }
    if (u < 52) {
        return 'a' + (u - 26);
    }
    if (u < 62) {
        return '0' + (u - 52);
    }
    if (u == 62) {
        return '+';
    }

    return '/';
}

/* Decode a base64 character */
static unsigned char decode(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (c - 'A');
    }
    if (c >= 'a' && c <= 'z') {
        return (c - 'a' + 26);
    }
    if (c >= '0' && c <= '9') {
        return (c - '0' + 52);
    }
    if (c == '+') {
        return 62;
    }

    return 63;
}

/* Returns TRUE if 'c' is a valid base64 character, otherwise FALSE */
static int is_base64(char c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || (c == '+')             ||
        (c == '/')             || (c == '=')) {

        return TRUE;
    }
    return FALSE;
}

