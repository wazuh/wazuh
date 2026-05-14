/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <shared.h>
#include <stdio.h>
#include <string.h>

#include "md5_sha1_sha256_op.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "headers/defs.h"


int OS_MD5_SHA1_SHA256_File(const char *fname,
                            char **prefilter_cmd,
                            os_md5 md5output,
                            os_sha1 sha1output,
                            os_sha256 sha256output,
                            int mode,
                            size_t max_size)
{
    size_t n, read = 0;
    FILE *fp;
    wfd_t *wfd;
    unsigned char buf[OS_BUFFER_SIZE + 2];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char md5_digest[16];
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];

    EVP_MD_CTX *sha1_ctx = NULL;
    EVP_MD_CTX *md5_ctx = NULL;
    EVP_MD_CTX *sha256_ctx = NULL;

    /* Clear the memory */
    md5output[0] = '\0';
    sha1output[0] = '\0';
    sha256output[0] = '\0';
    buf[OS_BUFFER_SIZE + 1] = '\0';

    /* Use prefilter_cmd if set */
    if (prefilter_cmd == NULL) {
        fp = wfopen(fname, mode == OS_BINARY ? "rb" : "r");
        if (!fp) {
            return (-1);
        }
    } else {
        char **command = NULL;
        int cnt = 0;
        while(prefilter_cmd[cnt] != NULL) {
            cnt++;
        }
        os_calloc(cnt + 2, sizeof(char *), command);
        for (cnt = 0; prefilter_cmd[cnt]; cnt++) {
            os_strdup(prefilter_cmd[cnt], command[cnt]);
        }

        os_strdup(fname, command[cnt]);

        wfd = wpopenv(*command, command, W_BIND_STDOUT);
        free_strarray(command);

        if (wfd == NULL) {
            return -1;
        }

        fp = wfd->file_out;
    }

    /* Initialize all hashes */
    sha1_ctx = EVP_MD_CTX_new();
    md5_ctx = EVP_MD_CTX_new();
    sha256_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(sha1_ctx, EVP_sha1());
    EVP_DigestInit(md5_ctx, EVP_md5());
    EVP_DigestInit(sha256_ctx, EVP_sha256());

    /* Update for each one */
    while ((n = fread(buf, 1, OS_BUFFER_SIZE, fp)) > 0) {

        if (max_size > 0) {
            read = read + n;
            if (read >= max_size) {     // Maximum filesize error
                mwarn("'%s' filesize is larger than the maximum allowed (%d MB). File skipped.", fname, (int)max_size/1048576); // max_size is in bytes
                if (prefilter_cmd == NULL) {
                    fclose(fp);
                } else {
                    wpclose(wfd);
                }
                EVP_MD_CTX_free(sha1_ctx);
                EVP_MD_CTX_free(md5_ctx);
                EVP_MD_CTX_free(sha256_ctx);
                return (-1);
            }
        }

        buf[n] = '\0';

        EVP_DigestUpdate(sha1_ctx, buf, n);
        EVP_DigestUpdate(md5_ctx, buf, n);
        EVP_DigestUpdate(sha256_ctx, buf, n);
    }

    EVP_DigestFinal(sha1_ctx, sha1_digest, NULL);
    EVP_DigestFinal(md5_ctx, md5_digest, NULL);
    EVP_DigestFinal(sha256_ctx, sha256_digest, NULL);

    EVP_MD_CTX_free(sha1_ctx);
    EVP_MD_CTX_free(md5_ctx);
    EVP_MD_CTX_free(sha256_ctx);

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
        wpclose(wfd);
    }

    return (0);
}
