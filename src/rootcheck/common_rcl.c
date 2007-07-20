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
#include "rootcheck.h"


/* Types of values */
#define RKCL_TYPE_FILE      1
#define RKCL_TYPE_REGISTRY  2
#define RKCL_TYPE_PROCESS   3

#define RKCL_COND_ALL       1
#define RKCL_COND_ANY       2
#define RKCL_COND_INV       -1


/** char *_rkcl_getrootdir()
 */
char *_rkcl_getrootdir(char *root_dir, int dir_size)
{
    #ifdef WIN32
    char final_file[2048 +1];
    char *tmp;

    final_file[0] = '\0';
    final_file[2048] = '\0';
    
    ExpandEnvironmentStrings("%WINDIR%", final_file, 2047);

    tmp = strchr(final_file, '\\');
    if(tmp)
    {
        *tmp = '\0';
        strncpy(root_dir, final_file, dir_size);
        return(root_dir);
    }
    
    return(NULL);

    #endif

    return(NULL);
}



/** char *_rkcl_getfp: Get next available buffer in file.
 */
char *_rkcl_getfp(FILE *fp, char *buf)
{
    while(fgets(buf, OS_SIZE_1024, fp) != NULL)
    {
        char *nbuf;

        /* Removing end of line */
        nbuf = strchr(buf, '\n');
        if(nbuf)
        {
            *nbuf = '\0';
        }

        /* Assigning buf to be used */
        nbuf = buf;


        /* Excluding commented lines or blanked ones */
        while(*nbuf != '\0')
        {
            if(*nbuf == ' ' || *nbuf == '\t')
            {
                nbuf++;
                continue;
            }
            else if(*nbuf == '#')
            {
                *nbuf = '\0';
                continue;
            }
            else
            {
                break;
            }
        }

        /* Going to next line if empty */
        if(*nbuf == '\0')
        {
            continue;
        }

        return(nbuf);
    }

    return(NULL);
}



/** int _rkcl_is_name
 */
int _rkcl_is_name(char *buf)
{
    if(*buf == '[' && buf[strlen(buf) -1] == ']')
    {
        return(1);
    }
    return(0);
}



/** int _rkcl_get_name
 */
char *_rkcl_get_name(char *buf, char *ref, int *condition)
{
    char *tmp_location;
    char *tmp_location2;
    
    *condition = 0;

    /* Checking if name is valid */
    if(!_rkcl_is_name(buf))
    {
        return(NULL);
    }

    /* Setting name */
    buf++;
    tmp_location = strchr(buf, ']');
    if(!tmp_location)
    {
        return(NULL);
    }
    *tmp_location = '\0';
    
    
    /* Getting condition */
    tmp_location++;
    if(*tmp_location != ' ' && tmp_location[1] != '[')
    {
        return(NULL);
    }
    tmp_location+=2;

    tmp_location2 = strchr(tmp_location, ']');
    if(!tmp_location2)
    {
        return(NULL);
    }
    *tmp_location2 = '\0';
    tmp_location2++;
    
    
    /* Getting condition */
    if(strcmp(tmp_location,"all") == 0)
    {
        *condition = RKCL_COND_ALL;
    }
    else if(strcmp(tmp_location,"any") == 0)
    {
        *condition = RKCL_COND_ANY;
    }
    else
    {
        *condition = RKCL_COND_INV;
        return(NULL);
    }


    /* Getting reference */
    if(*tmp_location2 != ' ' && tmp_location2[1] != '[')
    {
        return(NULL);
    }

    tmp_location2+=2;
    tmp_location = strchr(tmp_location2, ']');
    if(!tmp_location)
    {
        return(NULL);
    }
    *tmp_location = '\0';

    /* Copying reference */
    strncpy(ref, tmp_location2, 255);    

    return(strdup(buf));
}



/** char *_rkcl_get_pattern(char *value)
 */
char *_rkcl_get_pattern(char *value)
{
    while(*value != '\0')
    {
        if((*value == ' ') && (value[1] == '-') &&
           (value[2] == '>') && (value[3] == ' '))
        {
            *value = '\0';
            value+=4;

            return(value);
        }
        value++;
    }

    return(NULL);
}



/** char *_rkcl_get_value
 */
char *_rkcl_get_value(char *buf, int *type)
{
    char *tmp_str;
    char *value;

    /* Zeroing type before using it  --make sure return is valid
     * in case of error.
     */
    *type = 0;

    value = strchr(buf, ':');
    if(value == NULL)
    {
        return(NULL);
    }

    *value = '\0';
    value++;
    
    tmp_str = strchr(value, ';');
    if(tmp_str == NULL)
    {
        return(NULL);
    }
    *tmp_str = '\0';
    

    /* Getting types - removing negate flag (using later) */
    if(*buf == '!')
    {
        buf++;
    }
    
    if(strcmp(buf, "f") == 0)
    {
        *type = RKCL_TYPE_FILE;
    }
    else if(strcmp(buf, "r") == 0)
    {
        *type = RKCL_TYPE_REGISTRY;
    }
    else if(strcmp(buf, "p") == 0)
    {
        *type = RKCL_TYPE_PROCESS;
    }
    else
    {
        return(NULL);
    }

    return(value);
}



/** int rkcl_get_entry:
 */
int rkcl_get_entry(FILE *fp, char *msg, void *p_list_p)
{
    int type = 0, condition = 0, root_dir_len;
    char *nbuf;
    char buf[OS_SIZE_1024 +2];
    char root_dir[OS_SIZE_1024 +2];
    char final_file[2048 +1];
    char ref[255 +1];

    char *value;
    char *name = NULL;
    char *tmp_str;

    OSList *p_list = (OSList *)p_list_p;

    memset(buf, '\0', sizeof(buf));
    memset(root_dir, '\0', sizeof(root_dir));
    memset(final_file, '\0', sizeof(final_file));
    memset(ref, '\0', sizeof(ref));
    
    root_dir_len = sizeof(root_dir) -1;

    /* Getting Windows rootdir */
    _rkcl_getrootdir(root_dir, root_dir_len);
    if(root_dir[0] == '\0')
    {
        merror(INVALID_ROOTDIR, ARGV0);    
    }
    

    do
    {
        int g_found = 0;
        
        /* Getting entry name */
        if(name == NULL)
        {
            nbuf = _rkcl_getfp(fp, buf);
            if(nbuf == NULL)
            {
                return(0);
            }

            /* Veryfying that the name is valid */
            name = _rkcl_get_name(nbuf, ref, &condition);

            if(name == NULL)
            {
                if(condition == RKCL_COND_INV)
                {
                    merror(INVALID_RKCL_NAME, ARGV0);
                }
                
                merror(INVALID_RKCL_NAME, ARGV0, nbuf);
                return(0);
            }
        }

        debug2("%s: DEBUG: Checking entry: '%s'.", ARGV0, name);

        /* Getting each value */
        do
        {
            int found = 0;
            
            nbuf = _rkcl_getfp(fp, buf);
            if(nbuf == NULL)
            {
                break;
            }

            
            /* We first try to get the name, looking for new entries */
            if(_rkcl_is_name(nbuf))
            {
                break;
            }
            
            
            /* Getting value to look for */
            value = _rkcl_get_value(nbuf, &type);
            if(value == NULL)
            {
                if(name)
                {
                    free(name);
                    name = NULL;
                }
                merror(INVALID_RKCL_VALUE, ARGV0, nbuf);
                return(0);
            }

            /* Checking for a file. */
            if(type == RKCL_TYPE_FILE)
            {
                char *pattern = NULL;

                pattern = _rkcl_get_pattern(value);

                #ifdef WIN32
                final_file[0] = '\0';
                final_file[2048] = '\0';
                
                if(value[0] == '\\')
                {
                    snprintf(final_file, 2047, "%s%s", root_dir, value);
                }
                else
                {
                    ExpandEnvironmentStrings(value, final_file, 2047);
                }


                debug2("%s: DEBUG: Checking file: '%s'.", ARGV0, final_file);
                if(rk_check_file(final_file, pattern))
                {
                    debug2("%s: DEBUG: found file.", ARGV0);
                    found = 1;
                }

                value = final_file;
                #else
                
                debug2("%s: DEBUG: Checking file: '%s'.", ARGV0, value);
                if(rk_check_file(value, pattern))
                {
                    found = 1;
                }
                
                #endif
            }
            else if(type == RKCL_TYPE_REGISTRY)
            {
                char *entry = NULL;
                char *pattern = NULL;
                
                /* Looking for additional entries in the registry
                 * and a pattern to match.
                 */
                entry = _rkcl_get_pattern(value);
                if(entry)
                {
                    pattern = _rkcl_get_pattern(entry);
                }
                
                debug2("%s: DEBUG: Checking registry: '%s'.", ARGV0, value);
                if(is_registry(value, entry, pattern))
                {
                    debug2("%s: DEBUG: found registry.", ARGV0);
                    found = 1;
                }
            }
            else if(type == RKCL_TYPE_PROCESS)
            {
                debug2("%s: DEBUG: Checking process: '%s'.", ARGV0, value);
                if(is_process(value, p_list))
                {
                    debug2("%s: DEBUG: found process.", ARGV0);
                    found = 1;
                }
            }

            if(condition == RKCL_COND_ANY)
            {
                debug2("%s: DEBUG: Condition ANY.", ARGV0);
                if(found)
                {
                    g_found = 1;
                }
            }
            /* Condition for ALL */
            else
            {
                debug2("%s: DEBUG: Condition ALL.", ARGV0);
                if(found && (g_found != -1))
                {
                    g_found = 1;
                }
                else
                {
                    g_found = -1;
                }
            }
        }while(value != NULL);
        
        /* Alerting if necessary */
        if(g_found == 1)
        {
            char op_msg[OS_SIZE_1024 +1];
            if(ref[0] != '\0')
            {
                snprintf(op_msg, OS_SIZE_1024, "%s %s. "
                                 "Reference: %s .",msg, name, ref);
            }
            else
            {
                snprintf(op_msg, OS_SIZE_1024, "%s %s.",msg, name);
            }
            notify_rk(ALERT_POLICY_VIOLATION, op_msg);
        }

        /* Ending if we don't have anything else. */
        if(!nbuf)
        {
            if(name)
            {
                free(name);
                name = NULL;
            }
            return(0);
        }

        /* Getting name already read */
        if(_rkcl_is_name(nbuf))
        {
            tmp_str = _rkcl_get_name(nbuf, ref, &condition);
            if(tmp_str)
            {
                if(name)
                {
                    free(name);
                }
                name = tmp_str;
            }
            else
            {
                if(condition == RKCL_COND_INV)
                {
                    merror(INVALID_RKCL_NAME, ARGV0);
                }

                merror(INVALID_RKCL_NAME, ARGV0, nbuf);
                return(0);
            }
        }
    }while(nbuf != NULL);

    return(1);
}


/* EOF */
