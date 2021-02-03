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

void expect_abspath(const char *path, int ret) {
    expect_string(__wrap_abspath, path, path);
    will_return(__wrap_abspath, ret);
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

void expect_rmdir_ex_call(const char *dir, int ret) {
    expect_string(__wrap_rmdir_ex, name, dir);
    will_return(__wrap_rmdir_ex, ret);
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

void expect_w_uncompress_gzfile(const char * gzfilesrc, const char * gzfiledst, FILE *ret) {
    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, gzfilesrc);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, gzfiledst);
    will_return(__wrap_w_uncompress_gzfile, ret);
}

FILE *__wrap_wfopen(const char * __filename, const char * __modes) {
    check_expected(__filename);
    check_expected(__modes);
    return mock_type(FILE *);
}

void expect_wfopen(const char * __filename, const char * __modes, FILE *ret) {
    expect_string(__wrap_wfopen, __filename, __filename);
    expect_string(__wrap_wfopen, __modes, __modes);
    will_return(__wrap_wfopen, ret);
}

char ** __wrap_wreaddir(const char * name) {
    check_expected(name);
    return mock_type(char**);
}

void expect_wreaddir_call(const char *dir, char **files) {
    expect_string(__wrap_wreaddir, name, dir);
    will_return(__wrap_wreaddir, files);
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

void expect_FileSize(const char *path, int ret) {
#ifndef WIN32
    expect_string(__wrap_FileSize, path, path);
    will_return(__wrap_FileSize, ret);
#else
    expect_string(__wrap_FileSizeWin, file, path);
    will_return(__wrap_FileSizeWin, ret);
#endif
}

int __wrap_rename_ex(const char *source, const char *destination) {
    check_expected(source);
    check_expected(destination);

    return mock();
}

void expect_rename_ex(const char *source, const char *destination, int ret) {
    expect_string(__wrap_rename_ex, source, source);
    expect_string(__wrap_rename_ex, destination, destination);
    will_return(__wrap_rename_ex, ret);
}

float __wrap_DirSize(const char *path) {
    check_expected(path);

    return mock();
}

int __wrap_mkdir_ex(const char *path) {
    check_expected(path);
    return mock();
}

void expect_mkdir_ex(const char *path, int ret) {
    expect_string(__wrap_mkdir_ex, path, path);
    will_return(__wrap_mkdir_ex, ret);
}

int __wrap_w_ref_parent_folder(const char * path) {
    check_expected(path);

    return mock();
}

int __wrap_cldir_ex(__attribute__((unused)) const char *name) {
    return mock();
}

int __wrap_UnmergeFiles(const char *finalpath, const char *optdir, int mode) {
    check_expected(finalpath);
    check_expected(optdir);
    check_expected(mode);
    return mock();
}

int64_t __wrap_w_ftell(__attribute__((unused)) FILE *fp) {
    return mock();
}

#ifdef WIN32
long long __wrap_get_UTC_modification_time(const char *file_path) {
    check_expected(file_path);
    return mock();
}
#endif
