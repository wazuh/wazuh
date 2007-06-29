/* @(#) $Id$ */

/* Copyright (C) 2005-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include "shared.h"


/** int pt_matches(char *str, char *pattern)
 * Checks if the specific pattern is present on str.
 * A pattern can be preceeded by:
 *                                =: (for equal) - default - strcasecmp
 *                                r: (for ossec regexes)
 *                                >: (for strcmp greater)
 *                                <: (for strcmp  lower)    
 *
 * Multiple patterns can be specified by using " && " between them.
 * All of them must match for it to return true.
 */
int pt_matches(char *str, char *pattern)
{
    int neg = 0;
    int ret_code = 0;
    char *tmp_pt = pattern;

    /* If string we null, we don't match */
    if(str == NULL)
    {
        return(0);
    }
    
    while(tmp_pt != NULL)
    {
        /* We first look for " && " */
        tmp_pt = strchr(pattern, ' ');
        if(tmp_pt && tmp_pt[1] == '&' && tmp_pt[2] == '&' && tmp_pt[3] == ' ')
        {
            *tmp_pt = '\0';
            tmp_pt += 4;
        }


        /* Checking for negate values */
        neg = 0;
        ret_code = 0;
        if(*pattern == '!')
        {
            pattern++;
            neg = 1;
        }
        

        /* Doing strcasecmp */
        if(strncasecmp(pattern, "=:", 2) == 0)
        {
            pattern += 2;
            if(strcasecmp(pattern, str) == 0)
            {
                ret_code = 1;
            }
        }
        else if(strncasecmp(pattern, "r:", 2) == 0)
        {
            pattern += 2;
            if(OS_Regex(pattern, str))
            {
                ret_code = 1;
            }
        }
        else if(strncasecmp(pattern, "<:", 2) == 0)
        {
            pattern += 2;
            if(strcmp(pattern, str) < 0)
            {
                ret_code = 1;
            }
        }
        else if(strncasecmp(pattern, ">:", 2) == 0)
        {
            pattern += 2;
            if(strcmp(pattern, str) > 0)
            {
                ret_code = 1;
            }
        }
        else
        {
            if(strcasecmp(pattern, str) == 0)
            {
                ret_code = 1;
            }
        }

        /* If we have "!", return true if we don't match */
        if(neg == 1)
        {
            if(ret_code)
            {
                ret_code = 0;
                break;
            }
        }
        else
        {
            if(!ret_code)
            {
                ret_code = 0;
                break;
            }
        }
        
        ret_code = 1;
        pattern = tmp_pt;
    }

    return(ret_code);
}



/** char *normalize_string
 * Normalizes a string, removing white spaces and tabs
 * from the begining and the end of it.
 */
char *normalize_string(char *str)
{
    int str_sz = strlen(str) -1;
    
    while(*str != '\0')
    {
        if(*str == ' ' || *str == '\t')
        {
            str++;
        }
        else
        {
            break;
        }
    }

    while(str[str_sz] == ' ' || str[str_sz] == '\t')
    {
        str[str_sz] = '\0';
        str_sz--;
    }

    return(str);
}



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
    FILE *fp = NULL;
    DIR *dp = NULL;


    #ifndef WIN32
    
    char curr_dir[1024];
    
    char *file_dirname;
    char *file_basename;
    

    curr_dir[1023] = '\0';

    if(!getcwd(curr_dir, 1022))
    {
        return(0);
    }

    /* Getting dir name */
    file_basename = strrchr(file_name, '/');
    if(!file_basename)
    {
        merror("%s: RK: Invalid file name: %s!", ARGV0, file_name);
        return(0);
    }

    
    /* If file_basename == file_name, then the file
     * only has one slash at the beginning.
     */
    if(file_basename != file_name)
    {
        /* Dir name and base name are now set */
        *file_basename = '\0';
        file_basename++;
        file_dirname = file_name;

        /** chdir test **/
        if(chdir(file_dirname) == 0)
        {
            if(chdir(file_basename) == 0)
            {
                ret = 1;
            }
            /* Checking errno (if file exists, but it is not
             * a directory.
             */
            else if(errno == ENOTDIR)
            {
                ret = 1;
            }

            /** Trying open dir **/
            dp = opendir(file_basename);
            if(dp)
            {
                closedir(dp);
                ret = 1;
            }
            else if(errno == ENOTDIR)
            {
                ret = 1;
            }

            /* Returning to the previous directory */
            chdir(curr_dir);
        }


        file_basename--;
        *file_basename = '/';

    }
    else
    {
        if(chdir(file_name) == 0)
        {
            ret = 1;

            /* Returning to the previous directory */
            chdir(curr_dir);
        }
        else if(errno == ENOTDIR)
        {
            ret = 1;
        }
    }
    
    #else
    dp = opendir(file_name);
    if(dp)
    {
        closedir(dp);
        ret = 1;
    }
                                                                                
    #endif /* WIN32 */

    
    /* Trying other calls */
    if( (stat(file_name, &statbuf) < 0) &&
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
