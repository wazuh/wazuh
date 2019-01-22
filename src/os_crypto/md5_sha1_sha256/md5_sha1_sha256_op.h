/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifndef __MD5SHA1SHA256_OP_H
#define __MD5SHA1SHA256_OP_H

#include "../md5/md5_op.h"
#include "../sha1/sha1_op.h"
#include "../sha256/sha256_op.h"


int OS_MD5_SHA1_SHA256_File(const char *fname, const char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output, os_sha256 sha256output, int mode) __attribute((nonnull(1, 3, 4)));

#endif

