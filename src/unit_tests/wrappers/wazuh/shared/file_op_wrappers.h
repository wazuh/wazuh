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

#endif
