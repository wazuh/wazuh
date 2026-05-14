/*
 * Copyright (C) 2015, Wazuh Inc.
 * Mar 14, 2019
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "file_op.h"
#include "sha512_op.h"
#include "headers/defs.h"

int OS_SHA512_File(const char *fname, os_sha512 output, int mode)
{
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char md[SHA512_DIGEST_LENGTH];
    size_t n;

    buf[2049] = '\0';

    fp = wfopen(fname, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return (-1);
    }

    EVP_MD_CTX *sha512_ctx = EVP_MD_CTX_new();

    if (!sha512_ctx) {
        fclose(fp);
        return (-1);
    }

    EVP_DigestInit(sha512_ctx, EVP_sha512());

    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        EVP_DigestUpdate(sha512_ctx, buf, n);
    }

    EVP_DigestFinal(sha512_ctx, md, NULL);
    EVP_MD_CTX_free(sha512_ctx);

    OS_SHA512_Hex(md, output);
    fclose(fp);

    return (0);
}

int OS_SHA512_String(const char *str, os_sha512 output)
{
    unsigned char md[SHA512_DIGEST_LENGTH];

    EVP_MD_CTX *sha512_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(sha512_ctx, EVP_sha512());
    EVP_DigestUpdate(sha512_ctx, str, strlen(str));
    EVP_DigestFinal(sha512_ctx, md, NULL);
    EVP_MD_CTX_free(sha512_ctx);

    OS_SHA512_Hex(md, output);

    return (0);
}

void OS_SHA512_Hex(const unsigned char md[SHA512_DIGEST_LENGTH], os_sha512 output)
{
    size_t n;

    for (n = 0; n < SHA512_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    *output = '\0';
}
