/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "monitord.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

/* Sign a log file */
void OS_SignLog(const char *logfile, const char *logfile_old, const char * ext)
{
    int i;
    size_t n;

    os_md5 mf_sum;
    os_md5 mf_sum_old;

    os_sha1 sf_sum;
    os_sha1 sf_sum_old;

    os_sha256 sf256_sum;
    os_sha256 sf256_sum_old;

    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *md5_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();

    char logfilesum[OS_FLSIZE + 1];
    char logfilesum_old[OS_FLSIZE + 1];
    char logfile_r[OS_FLSIZE + 1];
    char buffer[4096];

    FILE *fp;

    unsigned char md5_digest[16];
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned char md256[SHA256_DIGEST_LENGTH];

    bool sum_file_ok = true;

    /* Clear the memory */
    memset(logfilesum, '\0', OS_FLSIZE + 1);
    memset(logfilesum_old, '\0', OS_FLSIZE + 1);

    /* Set umask */
    umask(0027);

    /* Create the checksum file names */
    snprintf(logfile_r, OS_FLSIZE + 1, "%s.%s", logfile, ext);
    os_snprintf(logfilesum, OS_FLSIZE, "%s.sum", logfile_r);
    snprintf(logfilesum_old, OS_FLSIZE, "%s.%s.sum", logfile_old, ext);

    EVP_DigestInit(sha1_ctx, EVP_sha1());
    EVP_DigestInit(md5_ctx, EVP_md5());
    EVP_DigestInit(sha256_ctx, EVP_sha256());

    /* Generate MD5 of the old file */
    if (OS_MD5_File(logfilesum_old, mf_sum_old, OS_TEXT) < 0) {
        sum_file_ok = false;
        strncpy(mf_sum_old, "none", 6);
    }

    /* Generate SHA-1 of the old file  */
    if (OS_SHA1_File(logfilesum_old, sf_sum_old, OS_TEXT) < 0) {
        sum_file_ok = false;
        strncpy(sf_sum_old, "none", 6);
    }

    /* Generate SHA-256 of the old file  */
    if (OS_SHA256_File(logfilesum_old, sf256_sum_old, OS_TEXT) < 0) {
        sum_file_ok = false;
        strncpy(sf256_sum_old, "none", 6);
    }

    if (!sum_file_ok) {
        mdebug1("Checksum for previous log file is missing: '%s'. "
                "Starting new sequence.", logfilesum_old);
    }

    /* Generate MD5, SHA-1, and SHA-256 of the current file */

    if (fp = wfopen(logfile_r, "r"), fp) {
        while (n = fread(buffer, 1, 2048, fp), n > 0) {
            EVP_DigestUpdate(sha1_ctx, buffer, n);
            EVP_DigestUpdate(md5_ctx, buffer, n);
            EVP_DigestUpdate(sha256_ctx, buffer, n);
        }

        fclose(fp);

        // Include rotated files

        for (i = 1; snprintf(logfile_r, OS_FLSIZE + 1, "%s-%.3d.%s", logfile, i, ext), !IsFile(logfile_r) && FileSize(logfile_r) > 0; i++) {
            if (fp = wfopen(logfile_r, "r"), fp) {
                while (n = fread(buffer, 1, 2048, fp), n > 0) {
                    EVP_DigestUpdate(sha1_ctx, buffer, n);
                    EVP_DigestUpdate(md5_ctx, buffer, n);
                    EVP_DigestUpdate(sha256_ctx, buffer, n);
                }

                fclose(fp);
            } else {
                merror(FOPEN_ERROR, logfile_r, errno, strerror(errno));
                break;
            }
        }

        EVP_DigestFinal(md5_ctx, md5_digest, NULL);
        char *mpos = mf_sum;
        for (n = 0; n < 16; n++) {
            snprintf(mpos, 3, "%02x", md5_digest[n]);
            mpos += 2;
        }

        EVP_DigestFinal(sha1_ctx, md, NULL);
        char *spos = sf_sum;
        for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
            snprintf(spos, 3, "%02x", md[n]);
            spos += 2;
        }

        EVP_DigestFinal(sha256_ctx, md256, NULL);
        char *sspos = sf256_sum;
        for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
            snprintf(sspos, 3, "%02x", md256[n]);
            sspos += 2;
        }

    } else {
        strncpy(mf_sum, "none", 6);
        strncpy(sf_sum, "none", 6);
        strncpy(sf256_sum, "none", 6);
    }

    EVP_MD_CTX_free(md5_ctx);
    EVP_MD_CTX_free(sha1_ctx);
    EVP_MD_CTX_free(sha256_ctx);

    fp = wfopen(logfilesum, "w");
    if (!fp) {
        merror(FOPEN_ERROR, logfilesum, errno, strerror(errno));
        return;
    }

    fprintf(fp, "Current checksum:\n");
    fprintf(fp, "MD5  (%s) = %s\n", logfile, mf_sum);
    fprintf(fp, "SHA1 (%s) = %s\n", logfile, sf_sum);
    fprintf(fp, "SHA256 (%s) = %s\n\n", logfile, sf256_sum);

    fprintf(fp, "Chained checksum:\n");
    fprintf(fp, "MD5  (%s) = %s\n", logfilesum_old, mf_sum_old);
    fprintf(fp, "SHA1 (%s) = %s\n", logfilesum_old, sf_sum_old);
    fprintf(fp, "SHA256 (%s) = %s\n\n", logfilesum_old, sf256_sum_old);
    fclose(fp);

    return;
}
