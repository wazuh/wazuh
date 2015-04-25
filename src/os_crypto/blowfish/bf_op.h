/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/blowfish Library
 * APIs for many crypto operations
 */

#ifndef __BF_OP_H
#define __BF_OP_H

#define OS_ENCRYPT      1
#define OS_DECRYPT      0

int OS_BF_Str(const char *input, char *output, const char *charkey,
              long size, short int action) __attribute((nonnull));

#endif

