/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __OS_ZLIB_H
#define __OS_ZLIB_H

#include "zlib.h"

/* Compress a string with zlib
 * src: the source string to compress
 * dst: the destination buffer for the compressed string, will be
 *      null-terminated on success
 * src_size: the length of the source string
 * dst_size: the size of the destination buffer
 * Returns 0 on failure, else the length of the compressed string
 */
unsigned long int os_zlib_compress(const char *src, char *dst,
                                   unsigned long int src_size,
                                   unsigned long int dst_size);

/* Uncompress a string with zlib
 * src: the source string to uncompress
 * dst: the destination buffer for the uncompressed string, will be
 *      null-terminated on success
 * src_size: the length of the source string
 * dst_size: the size of the destination buffer
 * Returns 0 on failure, else the length of the uncompressed string
 */
unsigned long int os_zlib_uncompress(const char *src, char *dst,
                                     unsigned long int src_size,
                                     unsigned long int dst_size);

#endif /* __OS_ZLIB_H */

