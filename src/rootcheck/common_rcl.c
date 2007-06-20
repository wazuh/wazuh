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
char *_rkcl_get_name(char *buf)
{
    if(*buf == '[' && buf[strlen(buf) -1] == ']')
    {
        buf[strlen(buf) -1] = '\0';
        buf++;
        return(strdup(buf));
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
    

    /* Getting types */
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
int rkcl_get_entry(FILE *fp, char *msg)
{
    int type = 0;
    char *nbuf;
    char buf[OS_SIZE_1024 +2];

    char *value;
    char *name = NULL;
    char *tmp_str;


    memset(buf, '\0', sizeof(buf));

    do
    {
        /* Getting entry name */
        if(name == NULL)
        {
            nbuf = _rkcl_getfp(fp, buf);
            if(nbuf == NULL)
            {
                return(0);
            }

            /* Veryfying that the name is valid */
            name = _rkcl_get_name(nbuf);

            if(name == NULL)
            {
                merror(INVALID_RKCL_NAME, ARGV0, nbuf);
                return(0);
            }
        }


        /* Getting each value */
        do
        {
            int found = 0;
            
            nbuf = _rkcl_getfp(fp, buf);
            if(nbuf == NULL)
            {
                if(name) 
                {
                    free(name);
                }
                return(0);
            }
            
            /* We first try to get the name, looking for new entries */
            tmp_str = _rkcl_get_name(nbuf);
            if(tmp_str)
            {
                if(name)
                {
                    free(name);
                }
                name = tmp_str;
                break;
            }
            
            value = _rkcl_get_value(nbuf, &type);
            if(value == NULL)
            {
                if(name)
                {
                    free(name);
                }
                merror(INVALID_RKCL_VALUE, ARGV0, nbuf);
                return(0);
            }

            if(type == RKCL_TYPE_FILE)
            {
                #ifdef WIN32
                char final_file[2048 +1];

                final_file[0] = '\0';
                final_file[2048] = '\0';
                ExpandEnvironmentStrings(value, final_file, 2047);
                if(is_file(final_file))
                {
                    found = 1;
                }
                #else
                
                if(is_file(value))
                {
                }
                
                #endif
            }
            else if(type == RKCL_TYPE_REGISTRY)
            {
                if(is_registry(value))
                {
                    found = 1;
                }
            }

            if(found)
            {
                char op_msg[OS_SIZE_1024 +1];

                snprintf(op_msg, OS_SIZE_1024, "%s: %s",
                        msg, name);

                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);

            }
            
            /* Checking if the specified entry is present on the system */
        }while(value != NULL);
        
        
    }while(nbuf != NULL);

    return(1);
}


/* EOF */
