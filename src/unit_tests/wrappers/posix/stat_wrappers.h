/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef STAT_WRAPPERS_H
#define STAT_WRAPPERS_H

#include <sys/stat.h>

int __wrap_chmod(const char *path);
int __wrap_fchmod(int fd, mode_t mode);

int __wrap_chown(const char *__file, int __owner, int __group);

int __wrap_lstat(const char *filename, struct stat *buf);

int __wrap_fstat (int __fd, struct stat *__buf);

#ifdef WIN32
int __wrap_mkdir(const char *__path);
#elif defined(__MACH__)
int __wrap_mkdir(const char *__path, mode_t __mode);
#else
int __wrap_mkdir(const char *__path, __mode_t __mode);
#endif

#ifdef WIN32
void expect_mkdir(const char *__path, int ret);
#elif defined(__MACH__)
void expect_mkdir(const char *__path, mode_t __mode, int ret);
#else
void expect_mkdir(const char *__path, __mode_t __mode, int ret);
#endif

int __wrap_stat(const char * __file, struct stat * __buf);

mode_t __wrap_umask(mode_t mode);

#endif
