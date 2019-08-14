/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Contributed by Dan Parriott (@ddpbsd)
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"


char *searchAndReplace(const char *orig, const char *search, const char *value)
{
    char *p;
    const size_t orig_len = strlen(orig);
    const size_t search_len = strlen(search);
    const size_t value_len = strlen(value);

    size_t inx_start;
    char *tmp = NULL;
    size_t tmp_offset = 0;
    size_t total_bytes_allocated = 1;
    size_t from;

    /* Check for any match */
    p = strstr(orig, search);
    if (p == NULL) {
        os_strdup(orig, tmp);

        return tmp;
    }

    inx_start = (size_t) (p - orig);
    from = inx_start + search_len;

    /* Copy content before first match, if any */
    if (inx_start > 0) {
        total_bytes_allocated = inx_start + 1;
        tmp = (char *) malloc(sizeof(char) * total_bytes_allocated);
        strncpy(tmp, orig, inx_start);
        tmp_offset = inx_start;
    }

    while (p != NULL) {
        /* Copy replacement */
        total_bytes_allocated += value_len;
        os_realloc(tmp, total_bytes_allocated, tmp);

        strncpy(tmp + tmp_offset, value, value_len);
        tmp_offset += value_len;

        /* Search for further occurrences */
        p = strstr(orig + inx_start + search_len, search);
        if (p != NULL) {
            size_t inx_start2 = (size_t) (p - orig);

            /* Copy content between matches, if any */
            if (inx_start2 > from) {
                size_t gap = inx_start2 - from;
                total_bytes_allocated += gap;
                os_realloc(tmp, total_bytes_allocated, tmp);
                strncpy(tmp + tmp_offset, orig + from, gap);
                tmp_offset += gap;
            }

            inx_start = inx_start2;
        }

        /* Set position for copying content after last match */
        from = inx_start + search_len;
    }

    /* Copy content after last match, if any */
    if ((from < orig_len) && from > 0) {
        total_bytes_allocated += orig_len - from;
        os_realloc(tmp, total_bytes_allocated, tmp);
        strncpy(tmp + tmp_offset, orig + from, orig_len - from);
    }

    tmp[total_bytes_allocated - 1] = '\0';

    return tmp;
}

/* Escape newline characters. Returns a new allocated string. */
char *escape_newlines(const char *orig)
{
    const char *ptr;
    char *ret, *retptr;
    size_t size;

    ptr = orig;
    size = 1;
    while (*ptr) {
        if ((*ptr == '\n') || (*ptr == '\r')) {
            size += 2;
        } else {
            size += 1;
        }
        ptr++;
    }

    ret = (char *) malloc (size);
    ptr = orig;
    retptr = ret;
    while (*ptr) {
        if (*ptr == '\n') {
            *retptr = '\\';
            *(retptr + 1) = 'n';
            retptr += 2;
        } else if (*ptr == '\r') {
            *retptr = '\\';
            *(retptr + 1) = 'n';
            retptr += 2;
        } else {
            *retptr = *ptr;
            retptr ++;
        }
        ptr++;
    }
    *retptr = '\0';

    return ret;
}
