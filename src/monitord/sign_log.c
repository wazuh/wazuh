/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "monitord.h"
#include <openssl/md5.h>
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

    SHA_CTX sha1_ctx;
    MD5_CTX md5_ctx;
    SHA256_CTX sha256_ctx;

    char logfilesum[OS_FLSIZE + 1];
    char logfilesum_old[OS_FLSIZE + 1];
    char logfile_r[OS_FLSIZE + 1];
    char buffer[4096];

    FILE *fp;

    unsigned char md5_digest[16];
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned char md256[SHA256_DIGEST_LENGTH];

    /* Clear the memory */
    memset(logfilesum, '\0', OS_FLSIZE + 1);
    memset(logfilesum_old, '\0', OS_FLSIZE + 1);

    /* Set umask */
    umask(0027);

    /* Create the checksum file names */
    snprintf(logfile_r, OS_FLSIZE + 1, "%s.%s", logfile, ext);
    snprintf(logfilesum, OS_FLSIZE, "%s.sum", logfile_r);
    snprintf(logfilesum_old, OS_FLSIZE, "%s.%s.sum", logfile_old, ext);

    MD5_Init(&md5_ctx);
    SHA1_Init(&sha1_ctx);
    SHA256_Init(&sha256_ctx);

    /* Generate MD5 of the old file */
    if (OS_MD5_File(logfilesum_old, mf_sum_old, OS_TEXT) < 0) {
        minfo("No previous md5 checksum found: '%s'. "
               "Starting over.", logfilesum_old);
        strncpy(mf_sum_old, "none", 6);
    }

    /* Generate SHA-1 of the old file  */
    if (OS_SHA1_File(logfilesum_old, sf_sum_old, OS_TEXT) < 0) {
        minfo("No previous sha1 checksum found: '%s'. "
               "Starting over.", logfilesum_old);
        strncpy(sf_sum_old, "none", 6);
    }

    /* Generate SHA-256 of the old file  */
    if (OS_SHA256_File(logfilesum_old, sf256_sum_old, OS_TEXT) < 0) {
        minfo("No previous sha256 checksum found: '%s'. "
               "Starting over.", logfilesum_old);
        strncpy(sf256_sum_old, "none", 6);
    }

    /* Generate MD5, SHA-1, and SHA-256 of the current file */

    if (fp = fopen(logfile_r, "r"), fp) {
        while (n = fread(buffer, 1, 2048, fp), n > 0) {
            SHA1_Update(&sha1_ctx, buffer, n);
            MD5_Update(&md5_ctx, buffer, (unsigned long)n);
            SHA256_Update(&sha256_ctx, buffer, n);
        }

        fclose(fp);

        // Include rotated files

        for (i = 1; snprintf(logfile_r, OS_FLSIZE + 1, "%s-%.3d.%s", logfile, i, ext), !IsFile(logfile_r) && FileSize(logfile_r) > 0; i++) {
            if (fp = fopen(logfile_r, "r"), fp) {
                while (n = fread(buffer, 1, 2048, fp), n > 0) {
                    SHA1_Update(&sha1_ctx, buffer, n);
                    MD5_Update(&md5_ctx, buffer, (unsigned long)n);
                    SHA256_Update(&sha256_ctx, buffer, n);
                }

                fclose(fp);
            } else {
                merror(FOPEN_ERROR, logfile_r, errno, strerror(errno));
                break;
            }
        }

        MD5_Final(md5_digest, &md5_ctx);
        char *mpos = mf_sum;
        for (n = 0; n < 16; n++) {
            snprintf(mpos, 3, "%02x", md5_digest[n]);
            mpos += 2;
        }

        SHA1_Final(&(md[0]), &sha1_ctx);
        char *spos = sf_sum;
        for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
            snprintf(spos, 3, "%02x", md[n]);
            spos += 2;
        }

        SHA256_Final(&(md256[0]), &sha256_ctx);
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

    fp = fopen(logfilesum, "w");
    if (!fp) {
        merror(FOPEN_ERROR, logfilesum, errno, strerror(errno));
        return;
    }

    fprintf(fp, "Current checksum:\n");
    fprintf(fp, "MD5  (%s) = %s\n", logfile, mf_sum);
    fprintf(fp, "SHA1 (%s) = %s\n\n", logfile, sf_sum);
    fprintf(fp, "SHA256 (%s) = %s\n\n", logfile, sf256_sum);

    fprintf(fp, "Chained checksum:\n");
    fprintf(fp, "MD5  (%s) = %s\n", logfilesum_old, mf_sum_old);
    fprintf(fp, "SHA1 (%s) = %s\n\n", logfilesum_old, sf_sum_old);
    fprintf(fp, "SHA256 (%s) = %s\n\n", logfilesum_old, sf256_sum_old);
    fclose(fp);

    return;
}
