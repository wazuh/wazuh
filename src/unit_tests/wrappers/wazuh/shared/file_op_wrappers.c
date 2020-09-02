/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "file_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <errno.h>

int __wrap_abspath(const char *path, char *buffer, size_t size) {
    check_expected(path);

    strncpy(buffer, path, size);
    buffer[size - 1] = '\0';

    return mock();
}

int __wrap_check_path_type(const char *dir) {
    check_expected(dir);

    return mock();
}

int __wrap_File_DateofChange(const char * file) {
    check_expected_ptr(file);
    return mock();
}

int __wrap_IsDir(const char *file) {
    check_expected(file);
    return mock();
}

int __wrap_IsFile(const char *file) {
    check_expected(file);

    return mock();
}

int __wrap_IsLink(const char * file) {
    check_expected(file);
    return mock();
}

int __wrap_IsSocket(const char * sock) {
    check_expected(sock);
    return mock();
}

int __wrap_rmdir_ex(const char *name) {
    int ret = mock();

    if(ret == -1) {
        errno = ENOTEMPTY;
    } else {
        errno = 0;
    }

    check_expected(name);
    return ret;
}

int __wrap_w_compress_gzfile(const char *filesrc, const char *filedst) {
    check_expected(filesrc);
    check_expected(filedst);
    return mock();
}

int __wrap_w_uncompress_gzfile(const char *gzfilesrc, const char *gzfiledst) {
    check_expected(gzfilesrc);
    check_expected(gzfiledst);
    return mock();
}

FILE *__wrap_wfopen(const char * __filename, const char * __modes) {
    check_expected(__filename);
    check_expected(__modes);
    return mock_type(FILE *);
}

char ** __wrap_wreaddir(const char * name) {
    check_expected(name);
    return mock_type(char**);
}

#ifndef WIN32
off_t __wrap_FileSize(const char * path) {
    check_expected(path);
    return mock();
}
#else
DWORD __wrap_FileSizeWin(const char * file) {
    check_expected(file);
    return mock();
}
#endif

int __wrap_rename_ex(const char *source, const char *destination) {
    check_expected(source);
    check_expected(destination);

    return mock();
}

float __wrap_DirSize(const char *path) {
    check_expected(path);

    return mock();
}
