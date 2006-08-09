/* @(#) $Id$ */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include "shared.h"

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
    if(!getcwd(curr_dir, 1022))
    {
        return(0);
    }
                                        

    /** chdir test **/
    if(chdir(file_name) == 0)
    {
        ret = 1;

        /* Returning to the previous directory */
        chdir(curr_dir);
    }
    /* Checking errno (if file exists, but it is not
     * a directory.
     */
    else if(errno == ENOTDIR)
    {
        ret = 1;
    }

    
    /** Trying open dir **/
    dp = opendir(file_name);
    if(dp)
    {
        closedir(dp);
        ret = 1;
    }
    /* File exists, but it is not a directory */
    else if(errno == ENOTDIR)
    {
        ret = 1;
    }
    

    /* Trying other calls */
    if( (lstat(file_name, &statbuf) < 0) &&
        (stat(file_name, &statbuf) < 0) &&   
        (access(file_name, F_OK) < 0) &&
        ((fp = fopen(file_name, "r")) == NULL))
    {
        return(ret);
    }

    /* must close it over here */
    if(fp)
        fclose(fp);
    
    return(1);
}



/* EOF */
