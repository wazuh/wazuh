/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: https://www.gnu.org/licenses/gpl.html
 */

/* Common API for dealing with file system information */

#ifndef OS_FS
#define OS_FS

#ifndef WIN32

#ifdef Linux
#include <sys/vfs.h>
#endif

#ifdef FreeBSD
#include <sys/param.h>
#include <sys/mount.h>
#endif
#endif

struct file_system_type {
    const char *name;
    long f_type;
    int flag;
};

typedef struct fs_set {
    unsigned nfs:1;
    unsigned dev:1;
    unsigned sys:1;
    unsigned proc:1;
} fs_set;

extern const struct file_system_type network_file_systems[];
extern const struct file_system_type skip_file_systems[];

short IsNFS(const char *file)  __attribute__((nonnull));
short skipFS(const char *file)  __attribute__((nonnull));

bool HasFilesystem(const char * path, fs_set set);

#endif /* OS_FS */

/* EOF */
