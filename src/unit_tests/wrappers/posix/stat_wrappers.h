/* Copyright (C) Wazuh Inc.
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
#ifdef __linux__
#include <sys/vfs.h>
#endif

int __wrap_chmod(const char *path);
int __wrap_fchmod(int fd, mode_t mode);

int __wrap_chown(const char *__file, int __owner, int __group);

int __wrap_lstat(const char *filename, struct stat *buf);

int __wrap_fstat (int __fd, struct stat *__buf);

/* Queues a __wrap_fstat() call that copies all of *buf (owner, group, mode...), instead of only the
   st_mode and st_size the plain form takes. buf must stay valid until the call happens. */
void expect_fstat_stat(int fd, const struct stat *buf, int ret);

int __wrap_fstatat(int __fd, const char *__file, struct stat *__buf, int __flag);

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

#ifdef __linux__
int __wrap_statfs(const char * __file, struct statfs * __buf);
#endif

mode_t __wrap_umask(mode_t mode);

#endif
