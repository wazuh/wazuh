/* Copyright (C) 2009 Trend Micro Inc.
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
#include "monitord.h"


/* Sign a log file */
void OS_SignLog(const char *logfile, const char *logfile_old, int log_missing)
{
    os_md5 mf_sum;
    os_md5 mf_sum_old;

    os_sha1 sf_sum;
    os_sha1 sf_sum_old;

    char logfilesum[OS_FLSIZE + 1];
    char logfilesum_old[OS_FLSIZE + 1];

    FILE *fp;

    /* Clear the memory */
    memset(logfilesum, '\0', OS_FLSIZE + 1);
    memset(logfilesum_old, '\0', OS_FLSIZE + 1);

    /* Set umask */
    umask(0027);

    /* Create the checksum file names */
    snprintf(logfilesum, OS_FLSIZE, "%s.sum", logfile);
    snprintf(logfilesum_old, OS_FLSIZE, "%s.sum", logfile_old);

    /* Generate MD5 of the old file */
    if (OS_MD5_File(logfilesum_old, mf_sum_old, OS_TEXT) < 0) {
        merror("%s: No previous md5 checksum found: '%s'. "
               "Starting over.", ARGV0, logfilesum_old);
        strncpy(mf_sum_old, "none", 6);
    }

    /* Generate SHA-1 of the old file  */
    if (OS_SHA1_File(logfilesum_old, sf_sum_old, OS_TEXT) < 0) {
        merror("%s: No previous sha1 checksum found: '%s'. "
               "Starting over.", ARGV0, logfilesum_old);
        strncpy(sf_sum_old, "none", 6);
    }

    /* Generate MD5 of the current file */
    if (OS_MD5_File(logfile, mf_sum, OS_TEXT) < 0) {
        if (log_missing) {
            merror("%s: File '%s' not found. MD5 checksum skipped.",
                   ARGV0, logfile);
        }
        strncpy(mf_sum, "none", 6);
    }

    /* Generate SHA-1 of the current file */
    if (OS_SHA1_File(logfile, sf_sum, OS_TEXT) < 0) {
        if (log_missing) {
            merror("%s: File '%s' not found. SHA1 checksum skipped.",
                   ARGV0, logfile);
        }
        strncpy(sf_sum, "none", 6);
    }

    fp = fopen(logfilesum, "w");
    if (!fp) {
        merror(FOPEN_ERROR, ARGV0, logfilesum, errno, strerror(errno));
        return;
    }

    fprintf(fp, "Current checksum:\n");
    fprintf(fp, "MD5  (%s) = %s\n", logfile, mf_sum);
    fprintf(fp, "SHA1 (%s) = %s\n\n", logfile, sf_sum);

    fprintf(fp, "Chained checksum:\n");
    fprintf(fp, "MD5  (%s) = %s\n", logfilesum_old, mf_sum_old);
    fprintf(fp, "SHA1 (%s) = %s\n\n", logfilesum_old, sf_sum_old);
    fclose(fp);

    return;
}

