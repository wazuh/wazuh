/* @(#) $Id: ./src/rootcheck/common.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/main/license/ .
 */


#include "shared.h"
#include "rootcheck.h"
#include "os_regex/os_regex.h"

static int _is_str_in_array(char *const *ar, const char *str);

/** Checks if the specified string is already in the array.
 */
static int _is_str_in_array(char *const *ar, const char *str)
{
    while(*ar)
    {
        if(strcmp(*ar, str) == 0)
        {
            return(1);
        }
        ar++;
    }
    return(0);
}



/** int rk_check_dir(char *dir, char *file, char *pattern)
 */
int rk_check_dir(const char *dir, const char *file, char *pattern)
{
    int ret_code = 0;
    char f_name[PATH_MAX +2];
    struct dirent *entry;
    struct stat statbuf_local;
    DIR *dp = NULL;


    f_name[PATH_MAX +1] = '\0';


    dp = opendir(dir);
    if(!dp)
        return(0);


    while((entry = readdir(dp)) != NULL)
    {
        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
           (strcmp(entry->d_name,"..") == 0))
        {
            continue;
        }


        /* Creating new file + path string */
        snprintf(f_name, PATH_MAX +1, "%s/%s",dir, entry->d_name);


        /* Checking if the read entry, matches the provided file name. */
        if(strncasecmp(file, "r:", 2) == 0)
        {
            if(OS_Regex(file +2, entry->d_name))
            {
                if(rk_check_file(f_name, pattern))
                {
                    ret_code = 1;
                }
            }
        }

        /* Trying without regex. */
        else
        {
            if(OS_Match2(file, entry->d_name))
            {
                if(rk_check_file(f_name, pattern))
                {
                    ret_code = 1;
                }
            }
        }


        /* Checking if file is a directory */
        if(lstat(f_name, &statbuf_local) == 0)
        {
            if(S_ISDIR(statbuf_local.st_mode))
            {
                if(rk_check_dir(f_name, file, pattern))
                {
                    ret_code = 1;
                }
            }
        }
    }

    closedir(dp);
    return(ret_code);

}



/** int rk_check_file(char *value, char *pattern)
 */
int rk_check_file(char *file, char *pattern)
{
    char *split_file;
    int full_negate = 0;
    int pt_result = 0;

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
                int i = 0;
                char _b_msg[OS_SIZE_1024 +1];

                _b_msg[OS_SIZE_1024] = '\0';
                snprintf(_b_msg, OS_SIZE_1024, " File: %s.",
                         file);

                /* Already present. */
                if(_is_str_in_array(rootcheck.alert_msg, _b_msg))
                {
                    return(1);
                }

                while(rootcheck.alert_msg[i] && (i < 255))
                    i++;

                if(!rootcheck.alert_msg[i])
                    os_strdup(_b_msg, rootcheck.alert_msg[i]);

                return(1);
            }
        }

        else
        {
            full_negate = pt_check_negate(pattern);
            /* Checking for a content in the file */
            debug1("checking file: %s", file);
            fp = fopen(file, "r");
            if(fp)
            {

                debug1(" starting new file: %s", file);
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
                    pt_result = pt_matches(buf, pattern);
                    debug1("Buf == \"%s\"", buf);
                    debug1("Pattern == \"%s\"", pattern);
                    debug1("pt_result == %d and full_negate == %d", pt_result, full_negate);
                    if((pt_result == 1 && full_negate == 0) )
                    {
                        debug1("alerting file %s on line %s", file, buf);
                        int i = 0;
                        char _b_msg[OS_SIZE_1024 +1];


                        /* Closing the file before dealing with the alert. */
                        fclose(fp);

                        /* Generating the alert itself. */
                        _b_msg[OS_SIZE_1024] = '\0';
                        snprintf(_b_msg, OS_SIZE_1024, " File: %s.",
                                 file);

                        /* Already present. */
                        if(_is_str_in_array(rootcheck.alert_msg, _b_msg))
                        {
                            return(1);
                        }

                        while(rootcheck.alert_msg[i] && (i < 255))
                            i++;

                        if(!rootcheck.alert_msg[i])
                        os_strdup(_b_msg, rootcheck.alert_msg[i]);

                        return(1);
                    }
                    else if((pt_result == 0 && full_negate == 1) )
                    {
                        /* found a full+negate match so no longer need to search
                         * break out of loop and amke sure the full negate does
                         * not alertin
                         */
                        debug1("found a complete match for full_negate");
                        full_negate = 0;
                        break;
                    }
                }

                fclose(fp);

                if(full_negate == 1)
                {
                    debug1("full_negate alerting - file %s",file);
                    int i = 0;
                    char _b_msg[OS_SIZE_1024 +1];

                    /* Generating the alert itself. */
                    _b_msg[OS_SIZE_1024] = '\0';
                    snprintf(_b_msg, OS_SIZE_1024, " File: %s.",
                             file);

                    /* Already present. */
                    if(_is_str_in_array(rootcheck.alert_msg, _b_msg))
                    {
                        return(1);
                    }

                    while(rootcheck.alert_msg[i] && (i < 255))
                        i++;

                    if(!rootcheck.alert_msg[i])
                    os_strdup(_b_msg, rootcheck.alert_msg[i]);

                    return(1);
                }
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


/** int pt_check_negate(char *pattern)
 * Checks if the patterns is all negate values and if so returns 1
 * else return 0
 */
int pt_check_negate(const char *pattern)
{
    char *mypattern = NULL;
    os_strdup(pattern, mypattern);
    char *tmp_pt = mypattern;
    char *tmp_pattern = mypattern;


    while(tmp_pt != NULL)
    {
        /* We first look for " && " */
        tmp_pt = strchr(tmp_pattern, ' ');
        if(tmp_pt && tmp_pt[1] == '&' && tmp_pt[2] == '&' && tmp_pt[3] == ' ')
        {
            *tmp_pt = '\0';
            tmp_pt += 4;
        }
        else
        {
            tmp_pt = NULL;
        }

        if(*tmp_pattern != '!')
        {
            free(mypattern);
            return 0;
        }

        tmp_pattern = tmp_pt;
    }

    debug1("pattern: %s is fill_negate",pattern);
    free(mypattern);
    return(1);
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
int pt_matches(const char *str, char *pattern)
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
                debug1("pattern: %s matches %s.",pattern, str);
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
    size_t str_sz = strlen(str);
    // return zero-length str as is
    if (str_sz == 0) {
       return str;
    } else {
        str_sz--;
    }
    // remove trailing spaces
    while(str[str_sz] == ' ' || str[str_sz] == '\t')
    {
        if(str_sz == 0)
            break;

        str[str_sz--] = '\0';
    }
    // ignore leading spaces
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

    return(str);
}





/** int isfile_ondir(char *file, char *dir)
 * Checks is 'file' is present on 'dir' using readdir
 */
int isfile_ondir(const char *file, const char *dir)
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
            if(chdir(curr_dir) == -1)
            {
                merror(CHDIR_ERROR, ARGV0, curr_dir, errno, strerror(errno));
                return (0);
            }
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
            if(chdir(curr_dir) == -1)
            {
                merror(CHDIR_ERROR, ARGV0, curr_dir, errno, strerror(errno));
                return (0);
            }
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
        #ifndef WIN32
        (access(file_name, F_OK) < 0) &&
        #endif
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
int del_plist(OSList *p_list)
{
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
int is_process(char *value, OSList *p_list)
{
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
            int i = 0;
            char _b_msg[OS_SIZE_1024 +1];

            _b_msg[OS_SIZE_1024] = '\0';

            snprintf(_b_msg, OS_SIZE_1024, " Process: %s.",
                     pinfo->p_path);

            /* Already present. */
            if(_is_str_in_array(rootcheck.alert_msg, _b_msg))
            {
                return(1);
            }

            while(rootcheck.alert_msg[i] && (i< 255))
                i++;

            if(!rootcheck.alert_msg[i])
                os_strdup(_b_msg, rootcheck.alert_msg[i]);

            return(1);
        }

        l_node = OSList_GetNextNode(p_list);
    }

    return(0);

}



/* EOF */
