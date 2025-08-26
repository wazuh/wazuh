/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MD5SHA1_OP_H
#define MD5SHA1_OP_H

#include "../md5/md5_op.h"
#include "../sha1/sha1_op.h"

int OS_MD5_SHA1_File(const char *fname, os_md5 md5output, os_sha1 sha1output, int mode) __attribute((nonnull(1, 3, 4)));

#endif /* MD5SHA1_OP_H */
