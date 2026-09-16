/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "ca_publication.h"

/* The first line of the block, so a reader (or an operator opening the file) can tell what the
 * comment is for. Not parsed: only the generation line carries meaning. */
#define CA_PUBLICATION_BANNER "## wazuh-ca-bundle"
#define CA_PUBLICATION_PREFIX "## generation:"

/* A bundle's own leading comment is a handful of lines. Anything longer is not a trust store
 * this agent wrote, so stop looking rather than read an arbitrary file to its end hunting for a
 * line that is not coming. */
#define CA_PUBLICATION_MAX_HEADER_LINES 32

int64_t w_ca_publication_read(const char *path) {
    FILE *fp;
    char line[OS_BUFFER_SIZE];
    int64_t generation = W_CA_PUBLICATION_UNKNOWN;
    int lines = 0;

    if (path == NULL) {
        return W_CA_PUBLICATION_UNKNOWN;
    }

    if (fp = wfopen(path, "r"), fp == NULL) {
        return W_CA_PUBLICATION_UNKNOWN;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        const char *value;
        char *end = NULL;
        long long parsed;

        /* The certificates begin here: everything this function cares about is above them, and
         * a "## generation:" inside a base64 body is not a thing that can happen. */
        if (strncmp(line, "-----BEGIN", 10) == 0) {
            break;
        }

        if (++lines > CA_PUBLICATION_MAX_HEADER_LINES) {
            break;
        }

        if (strncmp(line, CA_PUBLICATION_PREFIX, strlen(CA_PUBLICATION_PREFIX)) != 0) {
            continue;
        }

        value = line + strlen(CA_PUBLICATION_PREFIX);
        errno = 0;
        parsed = strtoll(value, &end, 10);

        /* Everything after the digits must be blank: a trailing token means this line was not
         * written by w_ca_publication_render() and reading a publication out of it would be
         * guessing. */
        if (errno != 0 || end == value || parsed <= 0 || parsed > INT64_MAX) {
            break;
        }

        while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') {
            end++;
        }

        if (*end != '\0') {
            break;
        }

        generation = (int64_t) parsed;
        break;
    }

    fclose(fp);

    return generation;
}

int w_ca_publication_render(int64_t generation, char *out, size_t out_size) {
    int written;

    if (out == NULL || generation <= 0) {
        return -1;
    }

    written = snprintf(out, out_size, "%s\n%s %lld\n", CA_PUBLICATION_BANNER,
                       CA_PUBLICATION_PREFIX, (long long) generation);

    if (written < 0 || (size_t) written >= out_size) {
        return -1;
    }

    return 0;
}
