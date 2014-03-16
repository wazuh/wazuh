/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "os_zlib.h"

unsigned long int os_zlib_compress(const char *src, char *dst, unsigned long int src_size,
		unsigned long int dst_size)
{
    if(compress2((Bytef *)dst,
                 &dst_size,
                 (const Bytef *)src,
                 src_size,
                 Z_BEST_COMPRESSION) == Z_OK)
    {
        dst[dst_size] = '\0';
        return(dst_size);
    }

    return(0);
}


unsigned long int os_zlib_uncompress(const char *src, char *dst, unsigned long int src_size,
		unsigned long int dst_size)
{
    if(uncompress((Bytef *)dst,
                  &dst_size,
                  (const Bytef *)src,
                  src_size) == Z_OK)
    {
        dst[dst_size] = '\0';
        return(dst_size);
    }

    return(0);
}


/* EOF */
