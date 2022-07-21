/* Copyright (C) 2015, Wazuh Inc.
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

#if defined(SUN_MAJOR_VERSION) && defined(SUN_MINOR_VERSION)  && \
    (SUN_MAJOR_VERSION < 11) || \
    ((SUN_MAJOR_VERSION == 11) && (SUN_MINOR_VERSION < 4))
#define w_ctime(x,y,z) ctime_r(x,y,z)
#else
#define w_ctime(x,y,z) ctime_r(x,y)
#endif

/**
 * @brief Find a user by name
 *
 * This is a wrapper of getpwnam_r().
 *
 * @param name Name of the user.
 * @param pwd Destination password structure.
 * @param buf Context buffer.
 * @param buflen Length of buffer.
 * @return Pointer to pwd, on success.
 * @retval NULL on failure.
 * @post errno is set on failure.
 */
struct passwd *w_getpwnam(const char *name, struct passwd *pwd, char *buf, size_t buflen);

/**
 * @brief Find a user by UID
 *
 * This is a wrapper of getpwid_r().
 *
 * @param name Name of the user.
 * @param pwd Destination password structure.
 * @param buf Context buffer.
 * @param buflen Length of buffer.
 * @return Pointer to pwd, on success.
 * @retval NULL on failure.
 * @post errno is set on failure.
 */
struct passwd *w_getpwuid(uid_t  uid, struct  passwd  *pwd, char *buf, int  buflen);

/**
 * @brief Find a group by name
 *
 * This is a wrapper of getgrnam_r().
 *
 * @param name Name of the group.
 * @param grp Destination group structure.
 * @param buf Context buffer.
 * @param buflen Length of buffer.
 * @return Pointer to grp, on success.
 * @retval NULL on failure.
 * @post errno is set on failure.
 */
struct group  *w_getgrnam(const char *name, struct group *grp, char *buf, int buflen);

/**
 * @brief Find a group by GID
 *
 * This is a wrapper of getgrid_r().
 *
 * @param name Name of the group.
 * @param grp Destination group structure.
 * @param buf Context buffer.
 * @param buflen Length of buffer.
 * @return Pointer to grp, on success.
 * @retval NULL on failure.
 * @post errno is set on failure.
 */
struct group *w_getgrgid(gid_t gid, struct group *grp,  char *buf, int buflen);

/**
 * @brief Find a UID by user name
 * @param name Name of the user.
 * @return UID of the user, if found.
 * @retval -1 user not found.
 */
uid_t Privsep_GetUser(const char *name) __attribute__((nonnull));

/**
 * @brief Find a GID by group name
 * @param name Name of the group.
 * @return GID of the group, if found.
 * @retval -1 group not found.
 */
gid_t Privsep_GetGroup(const char *name) __attribute__((nonnull));

int Privsep_SetUser(uid_t uid);

int Privsep_SetGroup(gid_t gid);

int Privsep_Chroot(const char *path) __attribute__((nonnull));

#endif /* PRIV_H */
