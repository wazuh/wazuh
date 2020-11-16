/* Copyright (C) 2015-2020, Wazuh Inc.
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

int __wrap_chown(const char *__file, int __owner, int __group);

int __wrap_lstat(const char *filename, struct stat *buf);

#ifndef WIN32
int __wrap_mkdir(const char *__path, __mode_t __mode);
#else
int __wrap_mkdir(const char *__path);
#endif

int __wrap_stat(const char * __file, struct stat * __buf);

#endif
