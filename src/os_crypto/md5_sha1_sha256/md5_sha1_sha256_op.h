/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifndef MD5SHA1SHA256_OP_H
#define MD5SHA1SHA256_OP_H

#include "../md5/md5_op.h"
#include "../sha1/sha1_op.h"
#include "../sha256/sha256_op.h"


int OS_MD5_SHA1_SHA256_File(const char *fname,
                            char **prefilter_cmd,
                            os_md5 md5output,
                            os_sha1 sha1output,
                            os_sha256 sha256output,
                            int mode,
                            size_t max_size) __attribute((nonnull(1, 3, 4)));

#endif /* MD5SHA1SHA256_OP_H */
