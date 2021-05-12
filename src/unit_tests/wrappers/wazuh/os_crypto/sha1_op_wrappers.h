/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SHA1_OP_WRAPPERS_H
#define SHA1_OP_WRAPPERS_H

#include "headers/shared.h"
#include <string.h>
#include <sys/types.h>

typedef char os_sha1[41];

int __wrap_OS_SHA1_File(const char *fname, os_sha1 output, int mode);
int __wrap_OS_SHA1_File_Nbytes(const char *fname, SHA_CTX *c, os_sha1 output, int mode, ssize_t nbytes);
void __wrap_OS_SHA1_Stream(SHA_CTX *c, os_sha1 output, char * buf);

#endif
