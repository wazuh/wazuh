/* @(#) $Id$ */

/* Copyright (C) 2006-2007 Daniel B. Cid <dcid@ossec.net>
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


/* Signs a log file */
void OS_SignLog(char *logfile, char *logfile_old)
{
    os_md5 mf_sum;
    os_md5 mf_sum_old;

    os_sha1 sf_sum;
    os_sha1 sf_sum_old;

    char logfilesum[OS_FLSIZE +1];
    char logfilesum_old[OS_FLSIZE +1];

    FILE *fp;


    /* Clearing the memory */
    memset(logfilesum, '\0', OS_FLSIZE +1);
    memset(logfilesum_old, '\0', OS_FLSIZE +1);


    /* Setting the umask */
    umask(0027);


    /* Creating the checksum file names */
    snprintf(logfilesum, OS_FLSIZE, "%s.sum", logfile);
    snprintf(logfilesum_old, OS_FLSIZE, "%s.sum", logfile_old);


    /* generating md5 of the old file */
    if(OS_MD5_File(logfilesum_old, mf_sum_old) < 0)
    {
        merror("%s: No previous md5 checksum found. Starting over.", ARGV0);
        strncpy(mf_sum_old, "none", 6);
    }

    /* generating sha1 of the old file.  */
    if(OS_SHA1_File(logfilesum_old, sf_sum_old) < 0)
    {
        merror("%s: No previous sha1 checksum found. Starting over.", ARGV0);
        strncpy(sf_sum_old, "none", 6);
    }


    /* Generating md5 of the current file */
    if(OS_MD5_File(logfile, mf_sum) < 0)
    {
        merror("%s: File '%s' not found. MD5 checksum skipped.", 
                                         ARGV0, logfile);
        strncpy(mf_sum, "none", 6);
    }

    /* Generating sha1 of the current file */
    if(OS_SHA1_File(logfile, sf_sum) < 0)
    {
        merror("%s: File '%s' not found. SHA1 checksum skipped.",
                                        ARGV0, logfile);
        strncpy(sf_sum, "none", 6);
    }

    
    fp = fopen(logfilesum, "w");
    if(!fp)
    {
        merror(FOPEN_ERROR, ARGV0, logfilesum);
        return;
    }


    fprintf(fp, "Current checksums\n");
    fprintf(fp, "MD5  (%s) = %s\n", logfile, mf_sum);
    fprintf(fp, "SHA1 (%s) = %s\n\n", logfile, sf_sum);
    
    fprintf(fp, "Chain checksums:\n");
    fprintf(fp, "MD5  (%s) = %s\n", logfilesum_old, mf_sum_old);
    fprintf(fp, "SHA1 (%s) = %s\n\n", logfilesum_old, sf_sum_old);
    fclose(fp);

    return;
}
	  

/* EOF */
