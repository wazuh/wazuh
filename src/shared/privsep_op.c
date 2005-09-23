/*      $OSSEC, privsep_op.h, v0.2, 2004/08/05, Daniel B. Cid$      */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/ossec/
 */

/* Functions for privilege separation.
 */


#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

#include "headers/os_err.h"

int Privsep_GetUser(char * name)
{
    struct passwd *pw;
    pw = getpwnam(name);
    if(pw == NULL)
        return(OS_INVALID);

    endpwent();    
    return(pw->pw_uid);
}

int Privsep_GetGroup(char * name)
{
    struct group *grp;
    grp = getgrnam(name);
    if(grp == NULL)
        return(OS_INVALID);

    endgrent();    
    return(grp->gr_gid);
}

int Privsep_SetUser(uid_t uid)
{
    if(setuid(uid) < 0)
        return(OS_INVALID);

    if(seteuid(uid) < 0)
        return(OS_INVALID);

    return(OS_SUCESS);
}

int Privsep_SetGroup(gid_t gid)
{
    if (setgroups(1, &gid) == -1)
        return(OS_INVALID);    
        
    if(setegid(gid) < 0)
        return(OS_INVALID);
        
    if(setgid(gid) < 0)
        return(OS_INVALID);
        
    return(OS_SUCESS);
}

int Privsep_Chroot(char * path)
{
    if(chdir(path) < 0)
        return(OS_INVALID);
        
    if(chroot(path) < 0)
        return(OS_INVALID);
        
    chdir("/");
        
    return(OS_SUCESS);
}

/* EOF */
