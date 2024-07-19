/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/md5 Library
 * APIs for many crypto operations
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "md5_op.h"
#include "headers/defs.h"
#include "headers/file_op.h"

int OS_MD5_File(const char *fname, os_md5 output, int mode)
{
    FILE *fp;
    EVP_MD_CTX *mdctx;
    unsigned char buf[1024];
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t n;

    memset(output, 0, sizeof(os_md5));

    fp = wfopen(fname, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return (-1);
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(fp);
        return (-1);
    }

    EVP_DigestInit(mdctx, EVP_md5());
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        EVP_DigestUpdate(mdctx, buf, n);
    }

    EVP_DigestFinal(mdctx, digest, NULL);

    for (n = 0; n < 16; n++) {
        snprintf(output + n * 2, 3, "%02x", digest[n]);
    }

    EVP_MD_CTX_free(mdctx);
    fclose(fp);

    return (0);
}

int OS_MD5_Str(const char *str, ssize_t length, os_md5 output)
{
    EVP_MD_CTX *mdctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t n;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return (-1);
    }

    EVP_DigestInit(mdctx, EVP_md5());
    EVP_DigestUpdate(mdctx, str, length < 0 ? (size_t)strlen(str) : (size_t)length);
    EVP_DigestFinal(mdctx, digest, NULL);

    for (n = 0; n < 16; n++) {
        snprintf(output + n * 2, 3, "%02x", digest[n]);
    }

    EVP_MD_CTX_free(mdctx);

    return (0);
}
