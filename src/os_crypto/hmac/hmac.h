/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Jun 21, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __HMAC_H
#define __HMAC_H

#define HMAC_SHA1_BLOCKSIZE 64

int OS_HMAC_SHA1_Str(const char *key, const char *text, os_sha1 output) __attribute((nonnull));
int OS_HMAC_SHA1_File(const char *key, const char *file_path, os_sha1 output, int mode) __attribute((nonnull));

#endif
