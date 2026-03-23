/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "bzlib_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>


int __wrap_BZ2_bzRead(int* bzerror,
                      BZFILE* f,
                      void* buf,
                      int len) {
    check_expected_ptr(f);
    *bzerror = mock();
    int n = mock();
    if(n <= len) {
        memcpy(buf, mock_type(void*), n);
    }
    return n;
}

void __wrap_BZ2_bzReadClose(__attribute__ ((__unused__)) int* bzerror,
                            BZFILE* f) {
    check_expected_ptr(f);
}

BZFILE* __wrap_BZ2_bzReadOpen(int* bzerror,
                              FILE* f,
                              __attribute__ ((__unused__)) int small,
                              __attribute__ ((__unused__)) int verbosity,
                              __attribute__ ((__unused__)) void* unused,
                              __attribute__ ((__unused__)) int nUnused) {
    check_expected_ptr(f);
    *bzerror = mock();

    return mock_type(BZFILE*);
}

void __wrap_BZ2_bzWrite(int* bzerror,
                       BZFILE* f,
                       void* buf,
                       int len) {
    check_expected_ptr(f);
    check_expected(buf);
    check_expected(len);
    *bzerror = mock();
}

void __wrap_BZ2_bzWriteClose(__attribute__ ((__unused__)) int* bzerror,
                               BZFILE* f,
                               __attribute__ ((__unused__)) int abandon,
                               __attribute__ ((__unused__)) unsigned int* nbytes_in,
                               __attribute__ ((__unused__)) unsigned int* nbytes_out) {
    check_expected_ptr(f);
}

BZFILE* __wrap_BZ2_bzWriteOpen(int* bzerror,
                               FILE* f,
                               __attribute__ ((__unused__)) int blockSize100k,
                               __attribute__ ((__unused__)) int verbosity,
                               __attribute__ ((__unused__)) int workFactor) {
    check_expected_ptr(f);
    *bzerror = mock();

    return mock_type(BZFILE*);
}

#ifndef TEST_WINAGENT
int __wrap_bzip2_uncompress(const char *filebz2,
                            const char *file) {

    check_expected_ptr(filebz2);
    check_expected_ptr(file);
    return mock();
}
#endif
