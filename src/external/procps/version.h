#ifndef PROC_VERSION_H
#define PROC_VERSION_H

#include "procps.h"

/* Suite version information for procps utilities
 * Copyright (c) 1995 Martin Schulze <joey@infodrom.north.de>
 * Linux kernel version information for procps utilities
 * Copyright (c) 1996 Charles Blake <cblake@bbn.com>
 * Distributable under the terms of the GNU Library General Public License
 *
 * Copyright 2002 Albert Cahalan
 */

EXTERN_C_BEGIN

extern void display_version(void);	/* display suite version */
extern const char procps_version[];		/* global buf for suite version */

extern int linux_version_code;		/* runtime version of LINUX_VERSION_CODE
					   in /usr/include/linux/version.h */

/* Convenience macros for composing/decomposing version codes */
#define LINUX_VERSION(x,y,z)   (0x10000*(x) + 0x100*(y) + z)
#define LINUX_VERSION_MAJOR(x) (((x)>>16) & 0xFF)
#define LINUX_VERSION_MINOR(x) (((x)>> 8) & 0xFF)
#define LINUX_VERSION_PATCH(x) ( (x)      & 0xFF)

EXTERN_C_END

#endif	/* PROC_VERSION_H */
