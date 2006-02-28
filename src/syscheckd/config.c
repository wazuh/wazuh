/*   $OSSEC, config.c, v0.2, 2005/07/14, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "syscheck.h"

int read_attr(char *dirs, char **g_attrs, char **g_values)
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
            if(syscheck.dir[i] == NULL)
                break;
        }
        
        os_strdup(tmp_dir, syscheck.dir[i]);
        syscheck.opts[i] = opts;
        
        
        /* Next entry */
        dir++;    
    }
    
    return(1);
}


int Read_Syscheck_Config(char * cfgfile)
{
    OS_XML xml;
    XML_NODE node;
    int i = 0;

    /* XML Definitions */
    char *xml_daemon = "daemon";
    char *xml_directories = "directories";
    char *xml_notify = "notify";
    char *xml_workdir = "work_directory";
    char *xml_time = "frequency";

    /* Configuration example 
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
      <directories check_owner="yes" check_group="yes" check_perm="yes" check_size="yes" check_sum="yes">/var/log</directories>
    */

    syscheck.rootcheck = 0;
    syscheck.time = SYSCHECK_WAIT*2;
    syscheck.notify = SYSLOG;

    /* Reading the xml config */
    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        merror("config_op: XML error: %s",xml.err);
        return(OS_INVALID);
    }

    if(!OS_RootElementExist(&xml,xml_syscheck))
    {
        OS_ClearXML(&xml);
        merror("%s: Configuration not found. Exiting..",ARGV0);
        exit(0);
    }

    
    /* Reading everything */
    node = OS_GetElementsbyNode(&xml,NULL);
    if(!node)
    {
        merror(CONFIG_ERROR, ARGV0);
        OS_ClearXML(&xml);
        return(-1);
    }

    /* Cleaning up the dirs */
    for(i = 0; i<= MAX_DIR_ENTRY; i++)
    {
        syscheck.dir[i] = NULL;
        syscheck.opts[i] = 0;
    }
    i = 0;


    while(node[i])
    {
        int j = 0;
        XML_NODE s_node;
        if(!node[i]->element || strcmp(node[i]->element,xml_syscheck) != 0)
        {
            i++;
            continue;
        }

        s_node = OS_GetElementsbyNode(&xml,node[i]);
        
        /* Reading the config elements */
        while(s_node[j])
        {
            if(!s_node[j]->element || !s_node[j]->content)
            {
                merror(CONFIG_ERROR, ARGV0);
                OS_ClearXML(&xml);
                return(-1);
            }
            /* Getting daemon flag */
            else if(strcmp(s_node[j]->element,xml_daemon) == 0)
            {
                if(s_node[j]->content[0] == 'n')
                    syscheck.daemon = 0;
            }
            /* Getting directories */
            else if(strcmp(s_node[j]->element,xml_directories) == 0)
            {
                if(!read_attr(s_node[j]->content, 
                          s_node[j]->attributes, 
                          s_node[j]->values))
                {
                    return(-1);
                }
            }
            /* Getting notify */
            else if(strcmp(s_node[j]->element,xml_notify) == 0)
            {
                if(strcasecmp(s_node[j]->content,"queue") == 0)
                    syscheck.notify = QUEUE;
                else if(strcasecmp(s_node[j]->content,"syslog") == 0)
                    syscheck.notify = SYSLOG;
                else
                {
                    ErrorExit("%s: Invalid notification option. Only "
                            "'syslog' or 'queue' are allowed.",ARGV0);
                }
            }
            /* Getting frequency */
            else if(strcmp(s_node[j]->element,xml_time) == 0)
            {        
                if(!OS_StrIsNum(s_node[j]->content))
                {
                    merror("Invalid frequency time '%s' for the integrity "
                            "checking (must be int).", s_node[j]->content);
                    return(OS_INVALID);
                }

                syscheck.time = atoi(s_node[j]->content);
            }
            /* Getting work dir */
            else if(strcmp(s_node[j]->element,xml_workdir) == 0)
            {
                if(!syscheck.workdir)
                    os_strdup(s_node[j]->content, syscheck.workdir);
            }

            j++;
        }

        i++;
    } 
    
    /* We must have at least one directory to check */
    if(syscheck.dir[0] == NULL)
    {
        merror(SK_NO_DIR, ARGV0);
        return(-1);
    }
    
    OS_ClearXML(&xml);
    return(0);
}
