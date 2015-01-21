/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "os_regex.h"
#include "os_regex_internal.h"


/* Compile a pattern to be used later
 * Allowed flags are:
 *      - OS_CASE_SENSITIVE
 * Returns 1 on success or 0 on error
 * The error code is set on reg->error
 */
int OSMatch_Compile(const char *pattern, OSMatch *reg, int flags)
{
    int usstrstr = 0;
    size_t i = 0;
    size_t count = 0;
    int end_of_string = 0;

    char *pt;
    char *new_str;
    char *new_str_free = NULL;

    /* Check for references not initialized */
    if (reg == NULL) {
        return (0);
    }

    /* Initialize OSRegex structure */
    reg->error = 0;
    reg->patterns = NULL;
    reg->size = NULL;
    reg->match_fp = NULL;

    /* The pattern can't be null */
    if (pattern == NULL) {
        reg->error = OS_REGEX_PATTERN_NULL;
        goto compile_error;
    }

    /* Maximum size of the pattern */
    if (strlen(pattern) > OS_PATTERN_MAXSIZE) {
        reg->error = OS_REGEX_MAXSIZE;
        goto compile_error;
    }

    /* Duping the pattern for our internal work */
    new_str = strdup(pattern);
    if (!new_str) {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }
    new_str_free = new_str;
    pt = new_str;

    /* Get the number of sub patterns */
    while (*pt != '\0') {
        /* The pattern must be always lower case if
         * case sensitive is set
         */
        if (!(flags & OS_CASE_SENSITIVE)) {
            *pt = (char) charmap[(uchar) * pt];
        }

        /* Number of sub patterns */
        if (*pt == OR) {
            count++;
        } else if (*pt == -29) {
            usstrstr = 1;
        }
        pt++;
    }

    /* For the last pattern */
    count++;
    reg->patterns = (char **) calloc(count + 1, sizeof(char *));
    reg->size = (size_t *) calloc(count + 1, sizeof(size_t));
    reg->match_fp = (int ( * *)(const char *, const char *, size_t, size_t)) calloc(count + 1, sizeof(int (*)(const char *, const char *, size_t, size_t)));

    /* Memory allocation error check */
    if (!reg->patterns || !reg->size || !reg->match_fp) {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }

    /* Initialize each sub pattern */
    for (i = 0; i <= count; i++) {
        reg->patterns[i] = NULL;
        reg->match_fp[i] = NULL;
        reg->size[i] = 0;
    }
    i = 0;

    /* Reassign pt to the beginning of the string */
    pt = new_str;

    /* Get the sub patterns */
    do {
        if ((*pt == OR) || (*pt == '\0')) {
            if (*pt == '\0') {
                end_of_string = 1;
            }

            *pt = '\0';

            /* Dupe the string */
            if (*new_str == BEGINREGEX) {
                reg->patterns[i] = strdup(new_str + 1);
            } else {
                reg->patterns[i] = strdup(new_str);
            }

            /* Memory error */
            if (!reg->patterns[i]) {
                reg->error = OS_REGEX_OUTOFMEMORY;
                goto compile_error;
            }

            /* If the string has ^ and $ */
            if ((*new_str == BEGINREGEX) && (*(pt - 1) == ENDREGEX)) {
                reg->match_fp[i] = _os_strcmp;
                reg->size[i] = strlen(reg->patterns[i]) - 1;
                reg->patterns[i][reg->size[i]] = '\0';
            } else if (strlen(new_str) == 0) {
                reg->match_fp[i] = _os_strmatch;
                reg->size[i] = 0;
            }

            /* String only has $ */
            else if (*(pt - 1) == ENDREGEX) {
                reg->match_fp[i] = _os_strcmp_last;
                reg->size[i] = strlen(reg->patterns[i]) - 1;
                reg->patterns[i][reg->size[i]] = '\0';
            }

            /* If string starts with ^, use strncmp */
            else if (*new_str == BEGINREGEX) {
                reg->match_fp[i] = _os_strncmp;
                reg->size[i] = strlen(reg->patterns[i]);
            }

            else if (usstrstr == 1) {
                reg->match_fp[i] = _os_strstr;
                reg->size[i] = strlen(reg->patterns[i]);
            }

            else {
                reg->match_fp[i] = _OS_Match;
                reg->size[i] = strlen(reg->patterns[i]);
            }

            if (end_of_string) {
                break;
            }

            new_str = ++pt;
            i++;
            continue;
        }
        pt++;

    } while (!end_of_string);

    /* Success return */
    free(new_str_free);
    return (1);

compile_error:
    /* Error handling */

    if (new_str_free) {
        free(new_str_free);
    }

    OSMatch_FreePattern(reg);

    return (0);
}

