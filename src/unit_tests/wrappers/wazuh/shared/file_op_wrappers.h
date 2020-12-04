/* Copyright (C) 2015-2020, Wazuh Inc.
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

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

int __wrap_abspath(const char *path, char *buffer, size_t size);

int __wrap_check_path_type(const char *dir);

int __wrap_File_DateofChange(const char * file);

int __wrap_IsDir(const char *file);

int __wrap_IsFile(const char *file);

int __wrap_IsLink(const char * file);

int __wrap_IsSocket(const char * sock);

int __wrap_rmdir_ex(const char *name);

int __wrap_w_compress_gzfile(const char *filesrc, const char *filedst);

int __wrap_w_uncompress_gzfile(const char *gzfilesrc, const char *gzfiledst);

FILE *__wrap_wfopen(const char * __filename, const char * __modes);

char ** __wrap_wreaddir(const char * name);

#ifndef WIN32
off_t __wrap_FileSize(const char * path);
#else
DWORD __wrap_FileSizeWin(const char * file);
#endif

int __wrap_rename_ex(const char *source, const char *destination);

float __wrap_DirSize(const char *path);

int __wrap_w_ref_parent_folder(const char * path);

int __wrap_cldir_ex(const char *name);

int __wrap_UnmergeFiles(const char *finalpath, const char *optdir, int mode);

#ifdef WIN32
long long __wrap_get_UTC_modification_time(const char *file_path);
#endif

#endif
