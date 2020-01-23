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

#ifndef WIN32

#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

#include "privsep_op.h"
#include "headers/os_err.h"

struct passwd *w_getpwnam(const char *name, struct passwd *pwd, char *buf, size_t buflen) {
#ifdef SOLARIS
    return getpwnam_r(name, pwd, buf, buflen);
#else
    struct passwd *result = NULL;
    return (getpwnam_r(name, pwd, buf, buflen, &result) == 0 && result != NULL) ? result : NULL;
#endif
}

struct passwd *w_getpwuid(uid_t uid, struct  passwd  *pwd, char *buf, int  buflen) {
#ifdef SOLARIS
    return getpwuid_r(uid, pwd, buf, buflen);
#else
    struct passwd *result = NULL;
    return (getpwuid_r(uid, pwd, buf, buflen, &result) == 0 && result != NULL) ? result : NULL;
#endif
}

struct group *w_getgrnam(const  char  *name,  struct group *grp, char *buf, int buflen) {
#ifdef SOLARIS
    return getgrnam_r(name, grp, buf, buflen);
#else
    struct group *result = NULL;
    return (getgrnam_r(name, grp, buf, buflen, &result) == 0 && result != NULL) ? result : NULL;
#endif
}

struct group *w_getgrgid(gid_t gid, struct group *grp,  char *buf, int buflen) {
#ifdef SOLARIS
    return getgrgid_r(gid, grp, buf, buflen);
#else
    struct group *result = NULL;
    return (getgrgid_r(gid, grp, buf, buflen, &result) == 0 && result != NULL) ? result : NULL;
#endif
}

uid_t Privsep_GetUser(const char *name)
{
    long int len =  sysconf(_SC_GETGR_R_SIZE_MAX);
    len = len > 0 ? len : 1024;
    struct passwd pw = { .pw_name = NULL };
    char *buffer;
    os_malloc(len, buffer);
    struct passwd *result = NULL;
    uid_t pw_uid;

    if (result = w_getpwnam(name, &pw, buffer, len), result) {
        pw_uid = result->pw_uid;
    } else {
        pw_uid = (uid_t) OS_INVALID;
    }
    os_free(buffer);

    return pw_uid;
}

gid_t Privsep_GetGroup(const char *name)
{
    struct group grp = { .gr_name = NULL };
    long int len = sysconf(_SC_GETGR_R_SIZE_MAX);
    len = len > 0 ? len : 1024;
    struct group *result = NULL;
    char *buffer;
    os_malloc(len, buffer);
    gid_t gr_gid;

    if (result = w_getgrnam(name, &grp, buffer, len), result) {
        gr_gid = result->gr_gid;
    } else {
        gr_gid = (gid_t) OS_INVALID;
    }
    os_free(buffer);

    return gr_gid;
}

int Privsep_SetUser(uid_t uid)
{
    if (setuid(uid) < 0) {
        return (OS_INVALID);
    }

#ifndef HPUX
    if (seteuid(uid) < 0) {
        return (OS_INVALID);
    }
#endif

    return (OS_SUCCESS);
}

int Privsep_SetGroup(gid_t gid)
{
    if (setgroups(1, &gid) == -1) {
        return (OS_INVALID);
    }

#ifndef HPUX
    if (setegid(gid) < 0) {
        return (OS_INVALID);
    }
#endif

    if (setgid(gid) < 0) {
        return (OS_INVALID);
    }

    return (OS_SUCCESS);
}

int Privsep_Chroot(const char *path)
{
    if (chdir(path) < 0) {
        return (OS_INVALID);
    }

    if (chroot(path) < 0) {
        return (OS_INVALID);
    }

    if (chdir("/") < 0) {
        return (OS_INVALID);
    }

    nowChroot();
    return (OS_SUCCESS);
}

#endif /* !WIN32 */
