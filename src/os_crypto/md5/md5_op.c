/*      $OSSEC, os_crypto/md5_op.c, v0.2, 2005/09/17, Daniel B. Cid$      */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.2 (2005/09/17): char fixes (signal)
 * v0.1 (2004/08/09)
 */

/* OS_crypto/md5 Library.
 * APIs for many crypto operations.
 */

#include "md5_op.h"

#include <stdio.h>
#include <string.h>
#include "md5.h"

int OS_MD5_File(const char * fname, os_md5 output)
{
    FILE *fp;
    MD5_CTX ctx;
    unsigned char buf[1024 +1];
    unsigned char digest[16];
    int n;

    memset(output,0, 33);
    buf[1024] = '\0';

    fp = fopen(fname,"r");
    if(!fp)
    {
        return(-1);
    }

    MD5Init(&ctx);
    while((n = fread(buf, 1, sizeof(buf) -1, fp)) > 0)
    {
        buf[n] = '\0';
        MD5Update(&ctx,buf,n);
    }

    MD5Final(digest, &ctx);

    for(n = 0;n < 16; n++)
    {
        snprintf(output, 3, "%02x", digest[n]);
        output+=2;
    }

    /* Closing it */
    fclose(fp);

    return(0);
}

int OS_MD5_Str(const char * str, os_md5 output)
{
    unsigned char digest[16];

    int n;

    MD5_CTX ctx;

    MD5Init(&ctx);

    MD5Update(&ctx,(unsigned char *)str,strlen(str));

    MD5Final(digest, &ctx);

    output[32] = '\0';
    for(n = 0;n < 16;n++)
    {
        snprintf(output, 3, "%02x", digest[n]);
        output+=2;
    }

    return(0);
}

/* EOF */
