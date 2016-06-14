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

#ifndef __MD5_OP_H
#define __MD5_OP_H

typedef char os_md5[33];

int OS_MD5_File(const char *fname, os_md5 output, int mode) __attribute((nonnull));
int OS_MD5_Str(const char *str, os_md5 output) __attribute((nonnull));

#endif

