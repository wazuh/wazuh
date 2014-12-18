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
#define _CAN_CHECK_FS_TYPE
#include <sys/vfs.h>
#endif

short IsNFS(const char *file)  __attribute__((nonnull));

#endif

/* EOF */
