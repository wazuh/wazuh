/*
 * Copyright (C) 2015, Wazuh Inc.
 * Contributed by Arshad Khan (@arshad01)
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <string.h>

#include "file_op.h"
#include "sha256_op.h"
#include "headers/defs.h"

#include <openssl/sha.h>
#include <openssl/evp.h>

int OS_SHA256_File(const char *fname, os_sha256 output, int mode)
{
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char md[SHA256_DIGEST_LENGTH];
    size_t n;

    memset(output, 0, sizeof(os_sha256));
    buf[2049] = '\0';

    fp = wfopen(fname, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return (-1);
    }

    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();

    if (!sha256_ctx) {
        fclose(fp);
        return (-1);
    }

    EVP_DigestInit(sha256_ctx, EVP_sha256());

    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        EVP_DigestUpdate(sha256_ctx, buf, n);
    }

    EVP_DigestFinal(sha256_ctx, md, NULL);

    for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    EVP_MD_CTX_free(sha256_ctx);

    fclose(fp);

    return (0);
}

void OS_SHA256_String(const char *str, os_sha256 output)
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    size_t n;

    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();

    EVP_DigestInit(sha256_ctx, EVP_sha256());
    EVP_DigestUpdate(sha256_ctx, str, strlen(str));
    EVP_DigestFinal(sha256_ctx, md, NULL);

    for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    EVP_MD_CTX_free(sha256_ctx);
}

void OS_SHA256_String_sized(const char *str, char* output, size_t size)
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    size_t n;

    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();

    EVP_DigestInit(sha256_ctx, EVP_sha256());
    EVP_DigestUpdate(sha256_ctx, str, strlen(str));
    EVP_DigestFinal(sha256_ctx, md, NULL);

    for (n = 0; n < size/2 && n < SHA256_DIGEST_LENGTH; n++) {
        snprintf(output, 3, "%02x", md[n]);
        output += 2;
    }

    EVP_MD_CTX_free(sha256_ctx);
}
