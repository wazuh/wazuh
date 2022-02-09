/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef PRIVSEP_OP_WRAPPERS_H
#define PRIVSEP_OP_WRAPPERS_H

#ifndef WIN32
#include <pwd.h>

struct group *__wrap_w_getgrgid(gid_t gid, struct group *grp,  char *buf, int buflen);
#endif

int __wrap_Privsep_GetUser(const char *name);

int __wrap_Privsep_GetGroup(const char *name);

#endif
