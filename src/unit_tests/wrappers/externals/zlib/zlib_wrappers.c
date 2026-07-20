/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "zlib_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>


int __wrap_gzread(gzFile gz_fd,
                  void* buf,
                  int len) {
    check_expected_ptr(gz_fd);
    int n = mock();
    if(n <= len && (n > 0)) {
        memcpy(buf, mock_type(void*), n);
    }
    return n;
}

gzFile __wrap_gzopen(const char * path,
                     const char * mode) {
    check_expected(path);
    check_expected(mode);

    return mock_type(gzFile);
}

int __wrap_gzclose(gzFile file) {
    check_expected_ptr(file);
    return mock();
}

int __wrap_gzeof(gzFile file) {
    check_expected_ptr(file);
    return mock();
}

const char * __wrap_gzerror(gzFile file,
                            int *errnum) {
    check_expected_ptr(file);
    *errnum = mock();
    return mock_type(char*);
}

int __wrap_gzwrite(gzFile file,
                   voidpc buf,
                   unsigned int len) {
    check_expected_ptr(file);
    check_expected(buf);
    check_expected(len);
    return mock();

}
