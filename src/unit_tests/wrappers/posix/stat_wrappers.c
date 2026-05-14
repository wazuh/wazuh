/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "stat_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../common.h"

#include <string.h>


int __wrap_chmod(const char *path) {
    check_expected_ptr(path);
    return mock();
}

int __wrap_fchmod(int fd, mode_t mode) {
    check_expected(fd);
    check_expected(mode);
    return mock();
}

int __wrap_chown(const char *__file, int __owner, int __group) {
    check_expected(__file);
    check_expected(__owner);
    check_expected(__group);

    return mock();
}

int __wrap_lstat(const char *filename, struct stat *buf) {
    struct stat * mock_buf;
    check_expected(filename);

    mock_buf = mock_type(struct stat *);
    if (mock_buf != NULL) {
        memcpy(buf, mock_buf, sizeof(struct stat));
    }
    return mock();
}

int __wrap_fstat(int __fd, struct stat *__buf) {
    check_expected(__fd);
    __buf->st_mode = mock();
    __buf->st_size = mock();
    return mock();
}

#ifdef WIN32
int __wrap_mkdir(const char *__path) {
    check_expected(__path);
    return mock();
}
#elif defined(__MACH__)
int __wrap_mkdir(const char *__path, mode_t __mode) {
    check_expected(__path);
    check_expected(__mode);
    return mock();
}
#else
int __wrap_mkdir(const char *__path, __mode_t __mode) {
    check_expected(__path);
    check_expected(__mode);
    return mock();
}
#endif

#ifdef WIN32
void expect_mkdir(const char *__path, int ret) {
#elif defined(__MACH__)
void expect_mkdir(const char *__path, mode_t __mode, int ret) {
    expect_value(__wrap_mkdir, __mode, __mode);
#else
void expect_mkdir(const char *__path, __mode_t __mode, int ret) {
    expect_value(__wrap_mkdir, __mode, __mode);
#endif
    expect_string(__wrap_mkdir, __path, __path);
    will_return(__wrap_mkdir, ret);
}

extern int __real_stat(const char * __file, struct stat * __buf);
int __wrap_stat(const char * __file, struct stat * __buf) {
    struct stat * mock_buf;
    if (test_mode) {
        check_expected(__file);
        mock_buf = mock_type(struct stat *);
        if (mock_buf != NULL) {
            memcpy(__buf, mock_buf, sizeof(struct stat));
        }
        return mock_type(int);
    }
    return __real_stat(__file, __buf);
}

mode_t __wrap_umask(mode_t mode) {
    check_expected(mode);
    return mock();
}
