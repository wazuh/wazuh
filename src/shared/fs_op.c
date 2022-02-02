/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Functions to retrieve information about the filesystem
 */


#include "shared.h"
#ifndef ARGV0
#define ARGV0 "fs_op"
#endif

#ifdef __linux__
#define DEVFS       0x00001373
#define NFS         0x00006969
#define PROCFS      0x00009fa0
#define TMPFS       0x01021994
#define AUFS        0x61756673
#define SYSFS       0x62656572
#define OVERLAYFS   0x794c7630
#define BTRFS       0x9123683E
#define CIFS        0xFF534D42
#define V9FS        0x01021997
#define ST_NODEV    4
#elif defined(__FreeBSD__)
#define NFS         0x3a
#define DEV         0x71
#define CIFS        // ToDo
#elif defined(__MACH__)
#define NFS         0x2
#define DEV         0x13
#define CIFS        0x1c
#endif

const struct file_system_type network_file_systems[] = {
#ifdef __linux__
    {.name="NFS",  .f_type=NFS, .flag=1},
    {.name="CIFS", .f_type=CIFS, .flag=1},
#endif
    /*  The last entry must be name=NULL */
    {.name=NULL, .f_type=0, .flag=0}
};

/* List of filesystem to skip the link count test */
const struct file_system_type skip_file_systems[] = {
#ifdef __linux__
    {.name="BTRFS", .f_type=BTRFS, .flag=1},
    {.name="AUFS", .f_type=AUFS, .flag=1},
    {.name="OVERLAYFS", .f_type=OVERLAYFS, .flag=1},
    {.name="V9FS", .f_type=V9FS, .flag=1},

#endif
    /*  The last entry must be name=NULL */
    {.name=NULL, .f_type=0, .flag=0}
};

short IsNFS(const char *dir_name)
{
#if defined(Linux)
    struct statfs stfs;

    /* ignore NFS (0x6969) or CIFS (0xFF534D42) mounts */
    if ( ! statfs(dir_name, &stfs) )
    {
        int i;
        for ( i=0; network_file_systems[i].name != NULL; i++ ) {
            if(network_file_systems[i].f_type == stfs.f_type ) {
                return network_file_systems[i].flag;
            }
        }
        return(0);
    }
    else
    {
        /* If the file exists, throw an error and retreat! If the file does not exist, there
	 * is no reason to spam the log with these errors. */
	if(errno != ENOENT) {
            merror("statfs('%s') produced error: %s", dir_name, strerror(errno));
	}
        return(-1);
    }
#else
    mdebug2("Attempted to check NFS status for '%s', but we don't know how on this OS.", dir_name);
#endif
    return(0);
}

short skipFS(const char *dir_name)
{
#if defined(Linux)
    struct statfs stfs;

    if ( ! statfs(dir_name, &stfs) )
    {
        int i;
        for ( i=0; skip_file_systems[i].name != NULL; i++ ) {
            if(skip_file_systems[i].f_type == stfs.f_type ) {
                mdebug1("Skipping dir (FS %s): %s ", skip_file_systems[i].name, dir_name);
                return skip_file_systems[i].flag;
            }
        }
        return(0);
    }
    else
    {
        /* If the file exists, throw an error and retreat! If the file does not exist, there
         * is no reason to spam the log with these errors. */
        if(errno != ENOENT) {
            merror("statfs('%s') produced error: %s", dir_name, strerror(errno));
        }
        return(-1);
    }
#else
    mdebug2("Attempted to check FS status for '%s', but we don't know how on this OS.", dir_name);
#endif
    return(0);
}

bool HasFilesystem(__attribute__((unused))const char * path, __attribute__((unused))fs_set set) {
#ifdef __linux__
    struct statfs stfs;

    if (statfs(path, &stfs) == -1) {
        mdebug2("statfs(%s): %s", path, strerror(errno));
        return false;
    }

    switch (stfs.f_type) {
    case DEVFS:
        // Linux 2.6.17 and earlier
        return set.dev;
    case NFS:
         return set.nfs;
    case PROCFS:
        return set.proc;
    case TMPFS:
#ifdef _STATFS_F_FLAGS
        // In modern Linux, /dev is TMPFS and ~ST_NODEV
        return set.dev && (stfs.f_flags & ST_NODEV) == 0;
#else
        return set.dev;
#endif
    case SYSFS:
        return set.sys;
    case CIFS:
        return set.nfs;
    }

#else
    (void)path;
    (void)set;
#endif

    return false;
}


/* EOF */
