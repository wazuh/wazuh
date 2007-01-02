/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"

#include "syscheck-config.h"

/* Read Windows registry configuration */
#ifdef WIN32
int read_reg(config *syscheck, char *entries)
{
    int i;
    char **entry;
    char *tmp_str;

    
    /* Getting each entry separately */
    entry = OS_StrBreak(',', entries, MAX_DIR_SIZE); /* Max number */


    /* entry can not be null */
    if(entry == NULL)
    {
        merror(SK_NO_DIR, ARGV0);
        return(0);
    }


    /* Doing it for each Entry */
    while(*entry)
    {
        char *tmp_entry;

        tmp_entry = *entry;

        /* Removing spaces at the beginning */
        while(*tmp_entry == ' ')
        {
            tmp_entry++;
        }

        /* Removing spaces at the end */
        tmp_str = strchr(tmp_entry, ' ');
        if(tmp_str)
        {
            tmp_str++;

            /* Checking if it is really at the end */
            if((*tmp_str == '\0') || (*tmp_str == ' '))
            {
                tmp_str--;
                *tmp_str = '\0';
            }
        }


        /* Adding entries - looking for the last available */
        for(i = 0; i< MAX_DIR_ENTRY; i++)
        {
            int str_len_i;
            int str_len_dir;
            
            if(syscheck->registry[i] == NULL)
                break;

            str_len_dir = strlen(tmp_entry);
            str_len_i = strlen(syscheck->registry[i]);
            
            if(str_len_dir > str_len_i)
            {
                str_len_dir = str_len_i;
            }

            /* Duplicated entry */
            if(strncmp(syscheck->registry[i], tmp_entry, str_len_dir) == 0)
            {
                merror(SK_DUP, ARGV0, tmp_entry);
                return(1);
            }
        }
        
        /* Adding new entry */
        os_strdup(tmp_entry, syscheck->registry[i]);
        
        
        /* Next entry */
        entry++;    
    }
    
    return(1);
}
#endif /* For read_reg */


/* Read directories attributes */            
int read_attr(config *syscheck, char *dirs, char **g_attrs, char **g_values)
{
    char *xml_check_all = "check_all";
    char *xml_check_sum = "check_sum";
    char *xml_check_sha1sum = "check_sha1sum";
    char *xml_check_md5sum = "check_md5sum";
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
        {
            tmp_str++;

            /* Checking if it is really at the end */
            if((*tmp_str == '\0') || (*tmp_str == ' '))
            {
                tmp_str--;
                *tmp_str = '\0';
            }
        }


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
                    opts|=CHECK_MD5SUM;
                    opts|=CHECK_SHA1SUM;
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
                    opts|=CHECK_MD5SUM;
                    opts|=CHECK_SHA1SUM;
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
            /* Checking md5sum */
            else if(strcmp(*attrs, xml_check_md5sum) == 0)
            {
                if(strcmp(*values, "yes") == 0)
                {
                    opts|=CHECK_MD5SUM;
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
            /* Checking sha1sum */
            else if(strcmp(*attrs, xml_check_sha1sum) == 0)
            {
                if(strcmp(*values, "yes") == 0)
                {
                    opts|=CHECK_SHA1SUM;
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
            int str_len_i;
            int str_len_dir;
            
            if(syscheck->dir[i] == NULL)
                break;

            str_len_dir = strlen(tmp_dir);
            str_len_i = strlen(syscheck->dir[i]);
            
            if(str_len_dir < str_len_i)
            {
                str_len_dir = str_len_i;
            }

            /* Duplicated entry */
            if(strncmp(syscheck->dir[i], tmp_dir, str_len_dir) == 0)
            {
                merror(SK_DUP, ARGV0, tmp_dir);
                return(1);
            }
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
    char *xml_registry = "windows_registry";
    char *xml_time = "frequency";
    char *xml_ignore = "ignore";
    char *xml_registry_ignore = "registry_ignore";
    char *xml_auto_ignore = "auto_ignore";
    char *xml_alert_new_files = "alert_new_files";

    /* Configuration example 
    <directories check_all="yes">/etc,/usr/bin</directories>
    <directories check_owner="yes" check_group="yes" check_perm="yes" 
    check_sum="yes">/var/log</directories>
    */

    config *syscheck;

    syscheck = (config *)configp;
    
    
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
        /* Getting windows registry */
        else if(strcmp(node[i]->element,xml_registry) == 0)
        {
            #ifdef WIN32
            if(!read_reg(syscheck, node[i]->content))
            {
                return(OS_INVALID);
            }
            #endif
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
        /* Getting file/dir ignore */
        else if(strcmp(node[i]->element,xml_ignore) == 0)
        {
            int ign_size = 0;

            if(!syscheck->ignore)
            {
                os_calloc(2, sizeof(char *), syscheck->ignore);
                syscheck->ignore[0] = NULL;
                syscheck->ignore[1] = NULL;
            }
            else
            {
                while(syscheck->ignore[ign_size] != NULL)
                    ign_size++;
                
                os_realloc(syscheck->ignore, 
                           sizeof(char *)*(ign_size +2),
                           syscheck->ignore);
                syscheck->ignore[ign_size +1] = NULL;
            }
            os_strdup(node[i]->content,syscheck->ignore[ign_size]);
        }
        /* Getting registry ignore list */
        else if(strcmp(node[i]->element,xml_registry_ignore) == 0)
        {
            #ifdef WIN32
            int ign_size = 0;

            if(!syscheck->registry_ignore)
            {
                os_calloc(2, sizeof(char *), syscheck->registry_ignore);
                syscheck->registry_ignore[0] = NULL;
                syscheck->registry_ignore[1] = NULL;
            }
            else
            {
                while(syscheck->registry_ignore[ign_size] != NULL)
                    ign_size++;

                os_realloc(syscheck->registry_ignore,
                        sizeof(char *)*(ign_size +2),
                        syscheck->registry_ignore);
                syscheck->registry_ignore[ign_size +1] = NULL;
            }
            os_strdup(node[i]->content,syscheck->registry_ignore[ign_size]);
            
            #endif
        }
        else if(strcmp(node[i]->element,xml_auto_ignore) == 0)
        {
            /* auto_ignore is not read here. */
        }
        else if(strcmp(node[i]->element,xml_alert_new_files) == 0)
        {
            /* alert_new_files option is not read here. */
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    } 
    
    return(0);
}
