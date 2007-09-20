/* @(#) $Id$ */

/* Copyright (C) 2005-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/main/license/ .
 */

 
#include "shared.h"
#include "rootcheck.h"
#include "os_regex/os_regex.h" 



/** int rk_check_file(char *value, char *pattern)
 */
int rk_check_file(char *file, char *pattern)
{
    char *split_file;
    
    FILE *fp;
    char buf[OS_SIZE_2048 +1];
    
    
    /* If string is null, we don't match */
    if(file == NULL)
    {
        return(0);
    }


    /* Checking if the file is divided */
    split_file = strchr(file, ',');
    if(split_file)
    {
        *split_file = '\0';
        split_file++;
    }


    /* Getting each file */
    do
    {
        

        /* If we don't have a pattern, just check if the file/dir is there */
        if(pattern == NULL)
        {
            if(is_file(file))
            {
                return(1);
            }
        }

        else
        {
            /* Checking for a content in the file */
            fp = fopen(file, "r");
            if(fp)
            {

                buf[OS_SIZE_2048] = '\0';
                while(fgets(buf, OS_SIZE_2048, fp) != NULL)
                {
                    char *nbuf;

                    /* Removing end of line */
                    nbuf = strchr(buf, '\n');
                    if(nbuf)
                    {
                        *nbuf = '\0';
                    }


                    #ifdef WIN32
                    /* Removing end of line */
                    nbuf = strchr(buf, '\r');
                    if(nbuf)
                    {
                        *nbuf = '\0';
                    }
                    #endif


                    /* Matched */
                    if(pt_matches(buf, pattern))
                    {
                        fclose(fp);
                        return(1);
                    }
                }

                fclose(fp);
            }
        }

        if(split_file)
        {
            file = split_file;
            split_file = strchr(split_file, ',');
            if(split_file)
            {
                split_file++;
            }
        }
        
        
    }while(split_file);


    return(0);
}



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
    char *tmp_ret = NULL;


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
            /* Marking pointer to clean it up */        
            tmp_ret = tmp_pt;
                    
            *tmp_pt = '\0';
            tmp_pt += 4;
        }
        else
        {
            tmp_pt = NULL;
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
            #ifdef WIN32
            char final_file[2048 +1];
            
            /* Try to get Windows variable */
            if(*pattern == '%')
            {
                final_file[0] = '\0';
                final_file[2048] = '\0';

                ExpandEnvironmentStrings(pattern, final_file, 2047);
            }
            else
            {
                strncpy(final_file, pattern, 2047);
            }

            /* Comparing against the expanded variable */
            if(strcasecmp(final_file, str) == 0)
            {
                ret_code = 1;
            }
            
            #else
            if(strcasecmp(pattern, str) == 0)
            {
                ret_code = 1;
            }

            #endif
        }

        /* Fixing tmp_ret entry */
        if(tmp_ret != NULL)
        {
            *tmp_ret = ' ';
            tmp_ret = NULL;
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



/*  del_plist:. Deletes the process list
 */
int del_plist(void *p_list_p)
{
    OSList *p_list = (OSList *)p_list_p;
    OSListNode *l_node;
    OSListNode *p_node = NULL;

    if(p_list == NULL)
    {
        return(0);
    }

    l_node = OSList_GetFirstNode(p_list);
    while(l_node)
    {
        Proc_Info *pinfo;

        pinfo = (Proc_Info *)l_node->data;

        if(pinfo->p_name)
        {
            free(pinfo->p_name);
        }

        if(pinfo->p_path)
        {
            free(pinfo->p_path);
        }
        
        free(l_node->data);

        if(p_node)
        {
            free(p_node);
            p_node = NULL;
        }
        p_node = l_node;

        l_node = OSList_GetNextNode(p_list);
    }

    if(p_node)
    {
        free(p_node);
        p_node = NULL;
    }

    free(p_list);

    return(1);
}



/* is_process: Check is a process is running.
 */
int is_process(char *value, void *p_list_p)
{
    OSList *p_list = (OSList *)p_list_p;
    OSListNode *l_node;
    if(p_list == NULL)
    {
        return(0);
    }
    if(!value)
    {
        return(0);
    }


    l_node = OSList_GetFirstNode(p_list);
    while(l_node)
    {
        Proc_Info *pinfo;

        pinfo = (Proc_Info *)l_node->data;

        /* Checking if value matches */
        if(pt_matches(pinfo->p_path, value))
        {
            return(1);
        }

        l_node = OSList_GetNextNode(p_list);
    }

    return(0);

}
 
 

/* EOF */
