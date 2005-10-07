/*   $OSSEC, check_rc_sys.c, v0.1, 2005/10/04, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include <stdio.h>       
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"

/** Prototypes **/
int read_sys_dir(char *dir_name);

int read_sys_file(char *file_name)
{
    struct stat statbuf;
    
    if(lstat(file_name, &statbuf) < 0)
    {
        merror("%s: Error accessing '%s'",ARGV0,file_name);
        return(-1);
    }
    
    /* If directory, read the directory */
    else if(S_ISDIR(statbuf.st_mode))
    {
        #ifdef DEBUG
        verbose("%s: Reading dir: %s\n",ARGV0, file_name);
        #endif

        return(read_sys_dir(file_name));
    }
    
    /* If has OTHER write and exec permission, alert */
    if(((statbuf.st_mode & S_IWOTH) == S_IWOTH) && 
         (S_ISREG(statbuf.st_mode)))
    {
        if(strncmp("/dev", file_name, 4) == 0)
        {
        }
        else if(strncmp("/proc", file_name, 5) == 0)
        {
        }
        else if(strcmp("/var/empty/dev/log", file_name) == 0)
        {
        }
        else if((statbuf.st_mode & S_IXUSR) == S_IXUSR)
        {
            printf("file with WRITE and EXEC per: %s\n", file_name);
        }
        else
        {
            printf("file with WRITE per: %s\n", file_name);
        }
    }

    else if((statbuf.st_mode & S_ISUID) == S_ISUID)
    {
        printf("SUID  file: %s\n", file_name);
    }
    
    else if((statbuf.st_mode & S_ISGID) == S_ISGID)
    {
        printf("GID file: %s\n", file_name);
    }
    
    else if(S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
    {
    }
    else
    {
    }

    return(0);
}

/* read_dir v0.1
 *
 */
int read_sys_dir(char *dir_name)
{
    DIR *dp;
    
	struct dirent *entry;
	
    
    if((dir_name == NULL)||(strlen(dir_name) > PATH_MAX))
    {
        merror("%s: Invalid directory given",ARGV0);
        return(-1);
    }
    
    /* Opening the directory given */
    dp = opendir(dir_name);
	if(!dp)
    {
        if((strcmp(dir_name, "") == 0)&&
           (dp = opendir("/"))) 
        {
            /* ok */
        }
        else
        {
            merror("%s: Error opening directory: '%s': %s ",
                                              ARGV0,
                                              dir_name,
                                              strerror(errno));
            return(-1);
        }
    }

    while((entry = readdir(dp)) != NULL)
    {
        char f_name[PATH_MAX +2];

        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
           (strcmp(entry->d_name,"..") == 0))  
            continue;
        
        snprintf(f_name, PATH_MAX +1, "%s/%s",dir_name, entry->d_name);
        
        read_sys_file(f_name);

    }

    closedir(dp);
    
    return(0);
}


/*  check_rc_sys: v0.1
 *  Scan the whole filesystem looking for possible issues
 */
void check_rc_sys(char *basedir)
{
    char file_path[OS_MAXSTR +1];

    snprintf(file_path, OS_MAXSTR, "%s", basedir);

    read_sys_dir(file_path);

    return;
}

/* EOF */
