/*   $OSSEC, common.c, v0.1, 2005/10/01, Daniel B. Cid$   */

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


/** int isfile_ondir(char *file, char *dir)
 * Checks is 'file' is present on 'dir' using readdir
 */
int isfile_ondir(char *file, char *dir)
{
    DIR *dp = NULL;
    struct dirent *entry;
    dp = opendir(dir);
    
    if(!dp)
        return(0);

    while((entry = readdir(dp)) != NULL)
    {
        if(strcmp(entry->d_name, file) == 0)
        {
            closedir(dp);
            return(1);
        }
    }
    
    closedir(dp);
    return(0);
}


/* is_file: Check if the file is present
 * by different attempts (to try to avoid syscall hidding).
 */
int is_file(char *file_name)
{
    int ret = 0;
    struct stat statbuf;
    char curr_dir[1024];
    FILE *fp = NULL;
    DIR *dp = NULL;
    
    curr_dir[1023] = '\0';
    if(!getcwd(curr_dir, 1023))
    {
        return(0);
    }
                                        
    if(chdir(file_name) == 0)
    {
        ret = 1;

        /* Returning to the previous directory */
        chdir(curr_dir);
    }
    
    if((lstat(file_name, &statbuf) < 0) &&
        ((fp = fopen(file_name, "r")) == NULL) &&
        ((dp = opendir(file_name)) == NULL))
    {
        return(ret);
    }

    /* must close it over here */
    if(fp)
        fclose(fp);
    
    if(dp)
        closedir(dp);
        
    return(1);
}



/* EOF */
