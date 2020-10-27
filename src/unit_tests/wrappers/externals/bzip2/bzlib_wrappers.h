/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef BZLIB_WRAPPERS_H
#define BZLIB_WRAPPERS_H

#include "bzlib.h"

int __wrap_BZ2_bzRead(int* bzerror,
                      BZFILE* f,
                      void* buf,
                      int len);

void __wrap_BZ2_bzReadClose(int* bzerror,
                            BZFILE* f);

BZFILE* __wrap_BZ2_bzReadOpen(int* bzerror,
                          FILE* f,
                          int small,
                          int verbosity,
                          void* unused,
                          int nUnused);

void __wrap_BZ2_bzWrite(int* bzerror,
                       BZFILE* f,
                       void* buf,
                       int len);

void __wrap_BZ2_bzWriteClose64(int* bzerror,
                               BZFILE* f,
                               int abandon,
                               unsigned int* nbytes_in_lo32,
                               unsigned int* nbytes_in_hi32,
                               unsigned int* nbytes_out_lo32,
                               unsigned int* nbytes_out_hi32);

BZFILE* __wrap_BZ2_bzWriteOpen(int* bzerror,
                               FILE* f,
                               int blockSize100k,
                               int verbosity,
                               int workFactor);

#ifndef TEST_WINAGENT
int __wrap_bzip2_uncompress(const char *filebz2,
                            const char *file);
#endif

#endif
