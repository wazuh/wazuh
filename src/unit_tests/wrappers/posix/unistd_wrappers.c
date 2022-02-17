/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "unistd_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>
#include "../common.h"

int __wrap_unlink(const char *file) {
    check_expected_ptr(file);
    return mock();
}

#ifdef WIN32
int wrap__unlink(const char *file) {
    check_expected_ptr(file);
    return mock();
}
#endif

int __wrap_close(__attribute__ ((__unused__)) int fd) {
    return 1;
}

extern int __real_getpid();
int __wrap_getpid() {
    if (test_mode) {
        return 2345;
    }
    return __real_getpid();
}

#ifndef WIN32
void __wrap_sleep(unsigned int seconds) {
    check_expected(seconds);
    return;
}

int __wrap_usleep(__attribute__((unused)) useconds_t usec) {
    function_called();
    return 0;
}
#endif

int __wrap_sysconf(__attribute__((unused)) int name) {
    return mock();
}

ssize_t __wrap_read(__attribute__((unused)) int fildes,
                    void *buf,
                    size_t nbyte) {
    char * buffer = mock_type(char *);
    size_t n = mock_type(size_t);
    if(buffer) {
        if (nbyte > n){
            memcpy(buf, buffer, n);
            return n;
        } else {
            memcpy(buf, buffer, nbyte);
            return nbyte;
        }
    }
    errno = EFAULT;
    return -1;
}

int __wrap_gethostname(char *name, int len) {
    snprintf(name, len, "%s",mock_type(char*));
    return mock_type(int);
}

int __wrap_readlink(__attribute__((unused)) void **state) {
    return mock();
}

int __wrap_symlink(const char *path1, const char *path2) {
    check_expected(path1);
    check_expected(path2);
    return mock();
}

int __wrap_access (const char *__name, int __type) {
    check_expected(__name);
    check_expected(__type);
    return mock();
}

#ifdef WIN32
int __wrap__access (const char *__name, int __type) {
    check_expected(__name);
    check_expected(__type);
    return mock();
}
#endif
