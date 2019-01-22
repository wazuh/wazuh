/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Contributed by Arshad Khan (@arshad01)
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <string.h>

#include "sha256_op.h"
#include "headers/defs.h"

#include <openssl/sha.h>

int OS_SHA256_File(const char *fname, os_sha256 output, int mode)
{
    SHA256_CTX c;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char md[SHA256_DIGEST_LENGTH];
    size_t n;

    memset(output, 0, 65);
    buf[2049] = '\0';

    fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return (-1);
    }

    SHA256_Init(&c);
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        SHA256_Update(&c, buf, n);
    }

    SHA256_Final(&(md[0]), &c);

    for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    fclose(fp);

    return (0);
}

int OS_SHA256_String(const char *str, os_sha256 output)
{
    SHA256_CTX c;
    unsigned char md[SHA256_DIGEST_LENGTH];
    size_t n;

    SHA256_Init(&c);
    SHA256_Update(&c, str, strlen(str));
    SHA256_Final(&(md[0]), &c);

    for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    return (0);
}
