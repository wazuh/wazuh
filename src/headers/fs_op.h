/* @(#) $Id: ./src/headers/dirtree_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */

/* Common API for dealing with file system information */


#ifndef _OS_FS
#define _OS_FS

#ifdef Linux
#include <sys/vfs.h>
#endif

#ifdef FreeBSD
#include <sys/param.h>
#include <sys/mount.h>
#endif

struct file_system_type {
    const char *name;
#ifdef WIN32
    const unsigned __int32 f_type;
#else
    const uint32_t f_type;
#endif
    const int flag;
};

extern const struct file_system_type network_file_systems[];

short IsNFS(const char *file)  __attribute__((nonnull));

#endif

/* EOF */
