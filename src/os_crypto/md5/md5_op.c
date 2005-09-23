/*      $OSSEC, os_crypto/md5_op.c, v0.2, 2005/09/17, Daniel B. Cid$      */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
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
 * Available at http://www.ossec.net/c/os_crypto/
 */


#include <stdio.h>
#include <string.h>
#include "md5.h"

int OS_MD5_File(char * fname, char * output)
{
    FILE *fp;
    MD5_CTX ctx;
    unsigned char buf[1024];
    unsigned char digest[16];
    char tmpstr[6];
    int n;
    
    memset(output,0,33);
    
    fp = fopen(fname,"r");
    if(!fp)
        return(-1);
    
    MD5Init(&ctx);
    while((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        MD5Update(&ctx,buf,n);
    
    MD5Final(digest, &ctx);
    
    for(n = 0;n < 16; n++)
    {
        memset(tmpstr,0,6);
        snprintf(tmpstr,6,"%02x",digest[n]++);
        strncat(output, tmpstr,6);
    }

    /* Closing it */
    fclose(fp);
        
    return(0);
}

/* EOF */
int OS_MD5_Str(char * str, char * output)
{
    unsigned char digest[16];
    char tmpstr[6];
    
    int n;
    
    MD5_CTX ctx;

    memset(output,0,33);

    MD5Init(&ctx);
    
    MD5Update(&ctx,(unsigned char *)str,strlen(str));
    
    MD5Final(digest, &ctx);
    
    for(n = 0;n < 16;n++)
    {
        memset(tmpstr,0,6);
        snprintf(tmpstr,6,"%02x",digest[n]++);
        strncat(output,tmpstr,6);
    }
    return(0);
}

/* EOF */
