/*   $OSSEC, check_rc_dev.c, v0.1, 2005/10/03, Daniel B. Cid$   */

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
int read_dir(char *dir_name);

int read_file(char *file_name)
{
    struct stat statbuf;
    
    if(stat(file_name, &statbuf) < 0)
    {
        merror("%s: Error accessing '%s'",ARGV0,file_name);
        return(-1);
    }
    
    if(S_ISDIR(statbuf.st_mode))
    {
        #ifdef DEBUG
        verbose("%s: Reading dir: %s\n",ARGV0, file_name);
        #endif

        return(read_dir(file_name));
    }
        
    else if(S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
    {
        printf("file: %s on /dev\n", file_name);
    }
    else
    {
        #ifdef DEBUG
        verbose("%s: *** IRREG file: '%s'\n",ARGV0,file_name);
        #endif
    }

    return(0);
}

/* read_dir v0.1
 *
 */
int read_dir(char *dir_name)
{
    int i;
    
    DIR *dp;
    
	struct dirent *entry;
	
    char *(ignore_dev[]) = {"MAKEDEV","README.MAKEDEV","MAKEDEV.README"};
    
    if((dir_name == NULL)||(strlen(dir_name) > PATH_MAX))
    {
        merror("%s: Invalid directory given",ARGV0);
        return(-1);
    }
    
    /* Opening the directory given */
    dp = opendir(dir_name);
	if(!dp)
    {
        merror("%s: Error opening directory: '%s': %s ",
                                              ARGV0,
                                              dir_name,
                                              strerror(errno));
        return(-1);
    }

    while((entry = readdir(dp)) != NULL)
    {
        char f_name[PATH_MAX +2];

        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
           (strcmp(entry->d_name,"..") == 0))  
            continue;
        
        /* Do not look for the ignored files */
        for(i = 0;i<=2;i++)
            if(strcmp(ignore_dev[i], entry->d_name) == 0)
                continue;
        
        snprintf(f_name, PATH_MAX +1, "%s/%s",dir_name, entry->d_name);
        
        read_file(f_name);

    }

    closedir(dp);
    
    return(0);
}


/*  check_rc_dev: v0.1
 *
 */
void check_rc_dev(char *basedir)
{
    char file_path[OS_MAXSTR +1];

    snprintf(file_path, OS_MAXSTR, "%s/dev", basedir);

    read_dir(file_path);

    return;
}

/* EOF */
