/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef FILE_OP_WRAPPERS_H
#define FILE_OP_WRAPPERS_H

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef WIN32
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#endif

int __wrap_abspath(const char *path, char *buffer, size_t size);
void expect_abspath(const char *path, int ret);

int __wrap_check_path_type(const char *dir);

int __wrap_File_DateofChange(const char * file);

int __wrap_IsDir(const char *file);

int __wrap_IsFile(const char *file);

int __wrap_IsLink(const char * file);

int __wrap_IsSocket(const char * sock);

int __wrap_rmdir_ex(const char *name);

void expect_rmdir_ex_call(const char *dir, int ret);

int __wrap_w_compress_gzfile(const char *filesrc, const char *filedst);

int __wrap_w_uncompress_gzfile(const char *gzfilesrc, const char *gzfiledst);
void expect_w_uncompress_gzfile(const char * gzfilesrc, const char * gzfiledst, FILE *ret);

FILE *__wrap_wfopen(const char * __filename, const char * __modes);
void expect_wfopen(const char * __filename, const char * __modes, FILE *ret);

char ** __wrap_wreaddir(const char * name);

void expect_wreaddir_call(const char *dir, char **files);

#ifndef WIN32
off_t __wrap_FileSize(const char * path);
#else
DWORD __wrap_FileSizeWin(const char * file);
#endif
void expect_FileSize(const char *path, int ret);

int __wrap_rename_ex(const char *source, const char *destination);
void expect_rename_ex(const char *source, const char *destination, int ret);

int __wrap_mkstemp_ex(char *tmp_path);
void expect_mkstemp_ex(char *tmp_path, int ret);

float __wrap_DirSize(const char *path);

int __wrap_mkdir_ex(const char *path);
void expect_mkdir_ex(const char *path, int ret);

int __wrap_w_ref_parent_folder(const char * path);

int __wrap_cldir_ex(const char *name);

int __wrap_cldir_ex_ignore(const char *name, const char ** ignore);

int __wrap_UnmergeFiles(const char *finalpath, const char *optdir, int mode);

#ifdef WIN32
long long __wrap_get_UTC_modification_time(const char *file_path);
#endif

char *__wrap_GetRandomNoise();

const char *__wrap_getuname();

#endif
int64_t __wrap_w_ftell (FILE *x);

int __wrap_w_fseek(FILE *x, int64_t pos, int mode);

int __wrap_MergeAppendFile(FILE *finalfp, const char *files, int path_offset);

int __wrap_OS_MoveFile(const char *src, const char *dst);

int __wrap_TestUnmergeFiles(const char *finalpath, int mode);

int __wrap_checkBinaryFile(const char *f_name);

int __wrap_w_copy_file(const char *src, const char *dst, char mode, __attribute__((unused)) char * message, int silent);

char * __wrap_w_get_file_content(__attribute__ ((__unused__)) const char * path, __attribute__ ((__unused__)) int max_size);
void expect_w_get_file_content(const char *buffer);
