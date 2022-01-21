/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef GRP_WRAPPERS_H
#define GRP_WRAPPERS_H

#ifndef WIN32
#include <stddef.h>
#include <sys/types.h>
#include <grp.h>
#include <errno.h>


struct group *__wrap_getgrgid(gid_t gid);

int __wrap_getgrnam_r(const char *name, struct group *grp, char *buf, size_t buflen, struct group **result);

#endif
#endif
