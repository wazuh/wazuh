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

/* Declared with C linkage explicitly: this header has no guard of its own, and
 * the container baseline/FIM code that calls OS_MD5_SHA1_SHA256_File() is C++.
 * A C++ translation unit that reaches this header before any wrapped include
 * of it (the include guard makes the later, wrapped one a no-op) would compile
 * fine and then fail at link time with a mangled undefined reference. */
#ifdef __cplusplus
extern "C" {
#endif

int OS_MD5_SHA1_SHA256_File(const char *fname,
                            os_md5 md5output,
                            os_sha1 sha1output,
                            os_sha256 sha256output,
                            int mode,
                            size_t max_size) __attribute((nonnull(1, 3, 4)));

#ifdef __cplusplus
}
#endif

#endif /* MD5SHA1SHA256_OP_H */
