/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions for privilege separation */

#ifndef PRIV_H
#define PRIV_H

#include "shared.h"

#ifdef SOLARIS
#define w_ctime(x,y,z) ctime_r(x,y,z)
#else
#define w_ctime(x,y,z) ctime_r(x,y)
#endif

struct passwd *w_getpwnam(const char *name, struct passwd *pwd, char *buf, size_t buflen);

struct passwd *w_getpwuid(uid_t  uid, struct  passwd  *pwd, char *buf, int  buflen);

struct group  *w_getgrnam(const  char  *name,  struct group *grp, char *buf, int buflen);

struct group *w_getgrgid(gid_t gid, struct group *grp,  char *buf, int buflen);

uid_t Privsep_GetUser(const char *name) __attribute__((nonnull));

gid_t Privsep_GetGroup(const char *name) __attribute__((nonnull));

int Privsep_SetUser(uid_t uid);

int Privsep_SetGroup(gid_t gid);

int Privsep_Chroot(const char *path) __attribute__((nonnull));

#endif /* PRIV_H */
