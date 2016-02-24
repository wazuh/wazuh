/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/md5 Library
 * APIs for many crypto operations
 */

#include <stdio.h>
#include <string.h>

#include "md5_op.h"
#include "md5.h"


int OS_MD5_File(const char *fname, os_md5 output)
{
    FILE *fp;
    MD5_CTX ctx;
    unsigned char buf[1024 + 1];
    unsigned char digest[16];
    size_t n;

    memset(output, 0, 33);
    buf[1024] = '\0';

    fp = fopen(fname, "rb");
    if (!fp) {
        return (-1);
    }

    MD5Init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf) - 1, fp)) > 0) {
        buf[n] = '\0';
        MD5Update(&ctx, buf, (unsigned)n);
    }

    MD5Final(digest, &ctx);

    for (n = 0; n < 16; n++) {
        snprintf(output, 3, "%02x", digest[n]);
        output += 2;
    }

    fclose(fp);

    return (0);
}

int OS_MD5_Str(const char *str, os_md5 output)
{
    unsigned char digest[16];

    int n;

    MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, (const unsigned char *)str, (unsigned)strlen(str));
    MD5Final(digest, &ctx);

    output[32] = '\0';
    for (n = 0; n < 16; n++) {
        snprintf(output, 3, "%02x", digest[n]);
        output += 2;
    }

    return (0);
}
