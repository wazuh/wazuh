/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef ZLIB_WRAPPERS_H
#define ZLIB_WRAPPERS_H

#include "../../../../external/zlib/zlib.h"

int __wrap_gzread(gzFile gz_fd,
                  void* buf,
                  int len);

gzFile __wrap_gzopen(const char * file,
                     const char * mode);

int __wrap_gzclose(gzFile file);

int __wrap_gzeof(gzFile file);

const char * __wrap_gzerror(gzFile file,
                            __attribute__((unused)) int *errnum);

int __wrap_gzwrite(gzFile file,
                   voidpc buf,
                   unsigned int len);

#endif
