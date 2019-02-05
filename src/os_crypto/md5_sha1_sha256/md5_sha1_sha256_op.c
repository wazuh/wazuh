/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <stdio.h>
#include <string.h>

#include "md5_sha1_sha256_op.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "headers/defs.h"


int OS_MD5_SHA1_SHA256_File(const char *fname, const char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output, os_sha256 sha256output, int mode)
{
    size_t n;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char md5_digest[16];
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];

    SHA_CTX sha1_ctx;
    MD5_CTX md5_ctx;
    SHA256_CTX sha256_ctx;

    /* Clear the memory */
    md5output[0] = '\0';
    sha1output[0] = '\0';
    sha256output[0] = '\0';
    buf[2048 + 1] = '\0';

    /* Use prefilter_cmd if set */
    if (prefilter_cmd == NULL) {
        fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
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
    MD5_Init(&md5_ctx);
    SHA1_Init(&sha1_ctx);
    SHA256_Init(&sha256_ctx);

    /* Update for each one */
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        SHA1_Update(&sha1_ctx, buf, n);
        SHA256_Update(&sha256_ctx, buf, n);
        MD5_Update(&md5_ctx, buf, (unsigned)n);
    }

    SHA1_Final(&(sha1_digest[0]), &sha1_ctx);
    SHA256_Final(&(sha256_digest[0]), &sha256_ctx);
    MD5_Final(md5_digest, &md5_ctx);

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

    /* Set output for SHA-256 */
    for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
        snprintf(sha256output, 3, "%02x", sha256_digest[n]);
        sha256output += 2;
    }

    /* Close it */
    if (prefilter_cmd == NULL) {
        fclose(fp);
    } else {
        pclose(fp);
    }

    return (0);
}
