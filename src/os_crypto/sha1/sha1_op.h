/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __SHA1_OP_H
#define __SHA1_OP_H

typedef char os_sha1[65];

int OS_SHA1_File(const char *fname, os_sha1 output, int mode) __attribute((nonnull));

#endif

