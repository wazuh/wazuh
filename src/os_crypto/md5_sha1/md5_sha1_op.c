/* @(#) $Id: ./src/os_crypto/md5_sha1/md5_sha1_op.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include "md5_sha1_op.h"

#include "../md5/md5.h"
#include "../sha1/sha.h"
#include "headers/defs.h"



int OS_MD5_SHA1_File(const char *fname, const char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output)
{
    int n;
    FILE *fp;
    unsigned char buf[2048 +2];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char md5_digest[16];

    char cmd[OS_MAXSTR];

    SHA_CTX sha1_ctx;
    MD5_CTX md5_ctx;


    /* Clearing the memory. */
    md5output[0] = '\0';
    sha1output[0] = '\0';
    buf[2048 +1] = '\0';

    /* Use prefilter_cmd if set */
    if (prefilter_cmd == NULL) {
	fp = fopen(fname,"r");
	if(!fp)
	    return(-1);
    } else {
	strncpy(cmd, prefilter_cmd, sizeof(cmd) - 1);
	strcat(cmd, " ");
	strncat(cmd, fname, sizeof(cmd) - strlen(cmd) - 1);
	fp = popen(cmd, "r");
	if(!fp)
	    return(-1);
    }

    /* Initializing both hashes */
    MD5Init(&md5_ctx);
    SHA1_Init(&sha1_ctx);


    /* Updating for each one. */
    while((n = fread(buf, 1, 2048, fp)) > 0)
    {
        buf[n] = '\0';
        SHA1_Update(&sha1_ctx, buf, (unsigned long)n);
        MD5Update(&md5_ctx, buf, n);
    }

    SHA1_Final(&(sha1_digest[0]), &sha1_ctx);
    MD5Final(md5_digest, &md5_ctx);


    /* Setting output for md5. */
    for(n = 0;n < 16; n++)
    {
        snprintf(md5output, 3, "%02x", md5_digest[n]);
        md5output+=2;
    }

    /* Setting output for sha1. */
    for (n = 0; n<SHA_DIGEST_LENGTH; n++)
    {
        snprintf(sha1output, 3, "%02x", sha1_digest[n]);
        sha1output+=2;
    }


    /* Closing it */
    if (prefilter_cmd == NULL) {
        fclose(fp);
    } else {
        pclose(fp);
    }

    return(0);
}


/* EOF */
