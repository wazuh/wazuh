/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "os_zlib.h"

#ifndef ARGV0
#define ARGV0   "zlib-test"
#endif


/* Zlib test */
int main(int argc, char **argv)
{
    unsigned long int ret, srcsize, dstsize = 2010;
    char dst[2048];
    char dst2[2048];

    memset(dst, 0, 2048);
    memset(dst2, 0, 2048);

    if (argc < 2) {
        printf("%s: string\n", argv[0]);
        exit(1);
    }

    srcsize = strlen(argv[1]);
    if (srcsize > 2000) {
        printf("%s: string too large\n", argv[0]);
        exit(1);

    }

    if ((ret = os_zlib_compress(argv[1], dst, srcsize, dstsize))) {
        printf("Compressed, from %lu->%lu\n", srcsize, ret);
    } else {
        printf("FAILED compressing.\n");
        exit(1);
    }

    /* Set new srcsize for decompression */
    srcsize = ret;

    if ((ret = os_zlib_uncompress(dst, dst2, srcsize, dstsize))) {
        printf("Uncompressed ok. String: '%s', size %lu->%lu\n",
               dst2, srcsize, ret);
    } else {
        printf("FAILED uncompressing.\n");
        exit(1);
    }

    return (0);
}
