/*   $OSSEC, rootcheck-config.c, v0.1, 2005/09/30, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "rootcheck-config.h"


/* Read_Rootcheck: Reads the rootcheck config
 */
int Read_Rootcheck(XML_NODE node, void *configp, void *mailp) 
{
    int i = 0;
    
    rkconfig *rootcheck;
    
    /* XML Definitions */
    char *xml_rootkit_files = "rootkit_files";
    char *xml_rootkit_trojans = "rootkit_trojans";
    char *xml_winaudit = "windows_audit";
    char *xml_unixaudit = "system_audit";
    char *xml_winapps = "windows_apps";
    char *xml_winmalware = "windows_malware";
    char *xml_scanall = "scanall";
    char *xml_readall = "readall";
    char *xml_time = "frequency";
    char *xml_disabled = "disabled";
    char *xml_base_dir = "base_directory";
    char *xml_ignore = "ignore";


    rootcheck = (rkconfig *)configp;
    
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

        /* Getting frequency */
        else if(strcmp(node[i]->element,xml_time) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }

            rootcheck->time = atoi(node[i]->content);
        }
        /* getting scan all */
        else if(strcmp(node[i]->element,xml_scanall) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                rootcheck->scanall = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                rootcheck->scanall = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_disabled) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                rootcheck->disabled = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                rootcheck->disabled = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_readall) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                rootcheck->readall = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                rootcheck->readall = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_rootkit_files) == 0)
        {
            os_strdup(node[i]->content, rootcheck->rootkit_files);
        }
        else if(strcmp(node[i]->element,xml_rootkit_trojans) == 0)
        {
            os_strdup(node[i]->content, rootcheck->rootkit_trojans);
        }
        else if(strcmp(node[i]->element, xml_winaudit) == 0)
        {
            os_strdup(node[i]->content, rootcheck->winaudit);
        }
        else if(strcmp(node[i]->element, xml_unixaudit) == 0)
        {
            int j = 0;
            while(rootcheck->unixaudit && rootcheck->unixaudit[j])
                j++;
            
            os_realloc(rootcheck->unixaudit, sizeof(char *)*(j+2), 
                       rootcheck->unixaudit);
            rootcheck->unixaudit[j] = NULL;
            rootcheck->unixaudit[j + 1] = NULL;
                
            os_strdup(node[i]->content, rootcheck->unixaudit[j]);
        }
        else if(strcmp(node[i]->element, xml_ignore) == 0)
        {
            int j = 0;
            while(rootcheck->ignore && rootcheck->ignore[j])
                j++;
            
            os_realloc(rootcheck->ignore, sizeof(char *)*(j+2), 
                       rootcheck->ignore);
            rootcheck->ignore[j] = NULL;
            rootcheck->ignore[j + 1] = NULL;
                
            os_strdup(node[i]->content, rootcheck->ignore[j]);
        }
        else if(strcmp(node[i]->element, xml_winmalware) == 0)
        {
            os_strdup(node[i]->content, rootcheck->winmalware);
        }
        else if(strcmp(node[i]->element, xml_winapps) == 0)
        {
            os_strdup(node[i]->content, rootcheck->winapps);
        }
        else if(strcmp(node[i]->element, xml_base_dir) == 0)
        {
            os_strdup(node[i]->content, rootcheck->basedir);
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

/* EOF */
