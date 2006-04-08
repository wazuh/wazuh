/*   $OSSEC, config.c, v0.2, 2005/07/14, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"

#include "syscheck-config.h"

int read_attr(config *syscheck, char *dirs, char **g_attrs, char **g_values)
{
    char *xml_check_all = "check_all";
    char *xml_check_sum = "check_sum";
    char *xml_check_size = "check_size";
    char *xml_check_owner = "check_owner";
    char *xml_check_group = "check_group";
    char *xml_check_perm = "check_perm";

    char **dir;
    char *tmp_str;
    dir = OS_StrBreak(',', dirs, MAX_DIR_SIZE); /* Max number */

    /* Dir can not be null */
    if(dir == NULL)
    {
        merror(SK_NO_DIR, ARGV0);
        return(0);
    }

    /* Doing it for each directory */
    while(*dir)
    {
        int i = 0;
        int opts = 0;
        char *tmp_dir;

        char **attrs = NULL;
        char **values = NULL;
        
        tmp_dir = *dir;

        /* Removing spaces at the beginning */
        while(*tmp_dir == ' ')
        {
            tmp_dir++;
        }

        /* Removing spaces at the end */
        tmp_str = strchr(tmp_dir, ' ');
        if(tmp_str)
            *tmp_str = '\0';


        /* Getting the options */
        if(!g_attrs || !g_values)
        {
            merror(SYSCHECK_NO_OPT, ARGV0, dirs);
            return(0);
        }

        attrs = g_attrs;
        values = g_values;

        while(*attrs && *values)
        {
            /* Checking all */
            if(strcmp(*attrs, xml_check_all) == 0)
            {
                if(strcmp(*values, "yes") == 0)
                {
                    opts|=CHECK_SUM;
                    opts|=CHECK_PERM;
                    opts|=CHECK_SIZE;
                    opts|=CHECK_OWNER;
                    opts|=CHECK_GROUP;
                }
                else if(strcmp(*values, "no") == 0)
                {
                }
                else
                {
                    merror(SK_INV_OPT, ARGV0, *values, *attrs);
                    return(0);
                }
            }
            /* Checking sum */
            else if(strcmp(*attrs, xml_check_sum) == 0)
            {
                if(strcmp(*values, "yes") == 0)
                {
                    opts|=CHECK_SUM;
                }
                else if(strcmp(*values, "no") == 0)
                {
                }
                else
                {
                    merror(SK_INV_OPT, ARGV0, *values, *attrs);
                    return(0);
                }
            }
            /* Checking permission */
            else if(strcmp(*attrs, xml_check_perm) == 0)
            {
                if(strcmp(*values, "yes") == 0)
                {
                    opts|=CHECK_PERM;
                }
                else if(strcmp(*values, "no") == 0)
                {
                }
                else
                {
                    merror(SK_INV_OPT, ARGV0, *values, *attrs);
                    return(0);
                }
            }
            /* Checking size */
            else if(strcmp(*attrs, xml_check_size) == 0)
            {
                if(strcmp(*values, "yes") == 0)
                {
                    opts|=CHECK_SIZE;
                }
                else if(strcmp(*values, "no") == 0)
                {
                }
                else
                {
                    merror(SK_INV_OPT, ARGV0, *values, *attrs);
                    return(0);
                }
            }
            /* Checking owner */
            else if(strcmp(*attrs, xml_check_owner) == 0)
            {
                if(strcmp(*values, "yes") == 0)
                {
                    opts|=CHECK_OWNER;
                }
                else if(strcmp(*values, "no") == 0)
                {
                }
                else
                {
                    merror(SK_INV_OPT, ARGV0, *values, *attrs);
                    return(0);
                }
            }
            /* Checking group */
            else if(strcmp(*attrs, xml_check_group) == 0)
            {
                if(strcmp(*values, "yes") == 0)
                {
                    opts|=CHECK_GROUP;
                }
                else if(strcmp(*values, "no") == 0)
                {
                }
                else
                {
                    merror(SK_INV_OPT, ARGV0, *values, *attrs);
                    return(0);
                }
            }
            else
            {
                merror(SK_INV_ATTR, ARGV0, *attrs);
                return(0);
            }
            attrs++; values++;
        }

        /* You must have something set */
        if(opts == 0)
        {
            merror(SYSCHECK_NO_OPT, ARGV0, dirs);
            return(0);
        }
        
        /* Adding directory - looking for the last available */
        for(i = 0; i< MAX_DIR_ENTRY; i++)
        {
            if(syscheck->dir[i] == NULL)
                break;
        }
        
        os_strdup(tmp_dir, syscheck->dir[i]);
        syscheck->opts[i] = opts;
        
        
        /* Next entry */
        dir++;    
    }
    
    return(1);
}


int Read_Syscheck(XML_NODE node, void *configp, void *mailp)
{
    int i = 0;

    /* XML Definitions */
    char *xml_directories = "directories";
    char *xml_time = "frequency";
    char *xml_ignore = "ignore";

    /* Configuration example 
    <directories check_all="yes">/etc,/usr/bin</directories>
    <directories check_owner="yes" check_group="yes" check_perm="yes" 
    check_sum="yes">/var/log</directories>
    */

    config *syscheck;

    syscheck = (config *)configp;
    
    syscheck->rootcheck = 0;
    syscheck->time = SYSCHECK_WAIT*2;
    syscheck->notify = SYSLOG;


    /* Cleaning up the dirs */
    for(i = 0; i<= MAX_DIR_ENTRY; i++)
    {
        syscheck->dir[i] = NULL;
        syscheck->opts[i] = 0;
    }
    i = 0;


    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            return(OS_INVALID);
        }

        /* Getting directories */
        else if(strcmp(node[i]->element,xml_directories) == 0)
        {
            if(!read_attr(syscheck,
                        node[i]->content, 
                        node[i]->attributes, 
                        node[i]->values))
            {
                return(OS_INVALID);
            }
        }
        /* Getting frequency */
        else if(strcmp(node[i]->element,xml_time) == 0)
        {        
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }

            syscheck->time = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element,xml_ignore) == 0)
        {
            /* Ignore is valid, but not get in here */
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    } 
    
    
    /* We must have at least one directory to check */
    if(syscheck->dir[0] == NULL)
    {
        merror(SK_NO_DIR, ARGV0);
        return(OS_INVALID);
    }
    
    return(0);
}
