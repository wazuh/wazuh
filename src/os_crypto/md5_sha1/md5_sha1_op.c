/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>

#include "file_op.h"
#include "md5_sha1_op.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "headers/defs.h"

int OS_MD5_SHA1_File(const char *fname, const char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output, int mode)
{
    size_t n;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char md5_digest[16];

    /* Clear the memory */
    md5output[0] = '\0';
    sha1output[0] = '\0';
    buf[2048 + 1] = '\0';

    /* Use prefilter_cmd if set */
    if (prefilter_cmd == NULL) {
        fp = wfopen(fname, mode == OS_BINARY ? "rb" : "r");
        if (!fp) {
            return (-1);
        }
    } else {
        char cmd[OS_MAXSTR];
        size_t target_length = strlen(prefilter_cmd) + 1 + strlen(fname);
        int res = snprintf(cmd, sizeof(cmd), "%s %s", prefilter_cmd, fname);
        if (res < 0 || (unsigned int)res != target_length) {
            return (-1);
        }
        fp = popen(cmd, "r");
        if (!fp) {
            return (-1);
        }
    }

    /* Initialize both hashes */
    EVP_MD_CTX *md5_ctx = EVP_MD_CTX_new();
    if (!md5_ctx) {
        if (prefilter_cmd == NULL) {
            fclose(fp);
        } else {
            pclose(fp);
        }
        return (-1);
    }

    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    if (!sha1_ctx) {
        EVP_MD_CTX_free(md5_ctx);
        if (prefilter_cmd == NULL) {
           fclose(fp);
        } else {
           pclose(fp);
        }
        return (-1);
    }

    EVP_DigestInit(md5_ctx, EVP_md5());
    EVP_DigestInit(sha1_ctx, EVP_sha1());

    /* Update for each one */
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        EVP_DigestUpdate(md5_ctx, buf, n);
        EVP_DigestUpdate(sha1_ctx, buf, n);
    }

    EVP_DigestFinal(md5_ctx, md5_digest, NULL);
    EVP_DigestFinal(sha1_ctx, sha1_digest, NULL);

    /* Set output for MD5 */
    for (n = 0; n < 16; n++) {
        snprintf(md5output, 3, "%02x", md5_digest[n]);
        md5output += 2;
    }

    /* Set output for SHA-1 */
    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(sha1output, 3, "%02x", sha1_digest[n]);
        sha1output += 2;
    }

    EVP_MD_CTX_free(md5_ctx);
    EVP_MD_CTX_free(sha1_ctx);

    /* Close it */
    if (prefilter_cmd == NULL) {
        fclose(fp);
    } else {
        pclose(fp);
    }

    return (0);
}
