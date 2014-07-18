/*      $OSSEC, privsep_op.h, v0.2, 2004/08/05, Daniel B. Cid$      */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net
 */

/* Functions for privilege separation.
 */

#ifndef WIN32

#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

#include "privsep_op.h"
#include "headers/os_err.h"

int Privsep_GetUser(char * name)
{
    int os_uid = -1;

    struct passwd *pw;
    pw = getpwnam(name);
    if(pw == NULL)
        return(OS_INVALID);

    os_uid = (int)pw->pw_uid;
    endpwent();

    return(os_uid);
}

int Privsep_GetGroup(char * name)
{
    int os_gid = -1;

    struct group *grp;
    grp = getgrnam(name);
    if(grp == NULL)
        return(OS_INVALID);

    os_gid = (int)grp->gr_gid;
    endgrent();

    return(os_gid);
}

int Privsep_SetUser(uid_t uid)
{
    if(setuid(uid) < 0)
        return(OS_INVALID);

    #ifndef HPUX
    if(seteuid(uid) < 0)
        return(OS_INVALID);
    #endif

    return(OS_SUCCESS);
}

int Privsep_SetGroup(gid_t gid)
{
    if (setgroups(1, &gid) == -1)
        return(OS_INVALID);

    #ifndef HPUX
    if(setegid(gid) < 0)
        return(OS_INVALID);
    #endif

    if(setgid(gid) < 0)
        return(OS_INVALID);

    return(OS_SUCCESS);
}

int Privsep_Chroot(char * path)
{
    if(chdir(path) < 0)
        return(OS_INVALID);

    if(chroot(path) < 0)
        return(OS_INVALID);

    chdir("/");

    return(OS_SUCCESS);
}

#endif
/* EOF */
