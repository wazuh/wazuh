/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * June 19, 2019
 * https://en.wikipedia.org/wiki/UTF-8
 */

#include <shared.h>

#define REPLACEMENT_INC 4096

/* Single byte: 0xxxxxxx */
#define valid_1(x) (x[0] & 0x80) == 0

/* Two bytes: 110xxxxx 10xxxxxx */
/* Starting bytes 0xC0 and 0xC1 are forbidden (overlong) */
#define valid_2(x) (((x)[0] & 0xE0) == 0xC0 && \
                    (x)[0] >= (char)0xC2 && ((x)[1] & 0xC0) == 0x80)

/* Three bytes: 1110xxxx 10xxxxxx 10xxxxxx */
/* 0xE0 could start overlong encodings */
/* 0xED (range U+D800–U+DFFF) is reserved for UTF-16 surrogate halves */
#define valid_3(x) (((x)[0] & 0xF0) == 0xE0 && \
                    ((x)[1] & 0xC0) == 0x80 && \
                    ((x)[2] & 0xC0) == 0x80 && \
                    ((x)[0] != (char)0xE0 || (unsigned char)(x)[1] >= 0xA0) && \
                    ((x)[0] != (char)0xED || (unsigned char)(x)[1] < 0xA0) && \
                    ((x)[0] != (char)0xEF || (unsigned char)(x)[1] <= 0xBF))

/* Four bytes: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
/* 0xF0 could start overlong encodings */
/* Start bytes 0xF5 and above are invalid for UTF-8 */
#define valid_4(x) (((x)[0] & 0xF8) == 0xF0 && \
                    (unsigned char)(x)[0] <= 0xF4 && \
                    ((x)[1] & 0xC0) == 0x80 && \
                    ((x)[2] & 0xC0) == 0x80 && \
                    ((x)[3] & 0xC0) == 0x80 && \
                    ((x)[0] != (char)0xF0 || (unsigned char)(x)[1] >= 0x90) && \
                    ((x)[0] != (char)0xF4 || (unsigned char)(x)[1] <= 0x8F))

/* Return whether a string is UTF-8 */
bool w_utf8_valid(const char * string) {
    assert(string != NULL);
    return *(w_utf8_drop(string)) == '\0';
}

/* Return pointer to the first character that does not match UTF-8, or the last byte (0) */
const char * w_utf8_drop(const char * string) {
    assert(string != NULL);

    while (*string) {
        if (valid_1(string)) {
            string++;
        } else if (valid_2(string)) {
            string += 2;
        } else if (valid_3(string)) {
            string += 3;
        } else if (valid_4(string)) {
            string += 4;
        } else {
            return string;
        }
    }

    return string;
}

/* Return a new string with valid UTF-8 characters only */
char * w_utf8_filter(const char * string, bool replacement) {
    assert(string != NULL);

    const char * valid = w_utf8_drop(string);

    if (*valid == '\0') {
        char * copy;
        os_strdup(string, copy);
        return copy;
    }

    size_t size = strlen(string) + 1;
    char * copy;
    size_t i = valid - string;
    size_t repl = 0;

    os_malloc(size, copy);
    memcpy(copy, string, i);

    while (*valid) {
        if (valid_1(valid)) {
            copy[i++] = *valid++;
        } else if (valid_2(valid)) {
            copy[i++] = *valid++;
            copy[i++] = *valid++;
        } else if (valid_3(valid)) {
            copy[i++] = *valid++;
            copy[i++] = *valid++;
            copy[i++] = *valid++;
        } else if (valid_4(valid)) {
            copy[i++] = *valid++;
            copy[i++] = *valid++;
            copy[i++] = *valid++;
            copy[i++] = *valid++;
        } else {
            if (replacement) {
                if (repl < 3) {
                    size += REPLACEMENT_INC;
                    os_realloc(copy, size, copy);
                    repl += REPLACEMENT_INC;
                }

                copy[i++] = 0xEF;
                copy[i++] = 0xBF;
                copy[i++] = 0xBD;
                repl -= 3;
            }

            valid++;
        }
    }

    copy[i] = '\0';
    return copy;
}
