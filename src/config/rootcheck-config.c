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


short eval_bool(char *str)
{
    if (str == NULL)
        return(OS_INVALID);
    else if (strcmp(str, "yes") == 0)
        return(1);
    else if (strcmp(str, "no") == 0)
        return(0);
    else
        return(OS_INVALID);
}

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

    char *xml_check_dev = "check_dev";
    char *xml_check_files = "check_files";
    char *xml_check_if = "check_if";
    char *xml_check_pids = "check_pids";
    char *xml_check_ports = "check_ports";
    char *xml_check_sys = "check_sys";
    char *xml_check_trojans = "check_trojans";
    char *xml_check_unixaudit = "check_unixaudit";
    char *xml_check_winapps = "check_winapps";
    char *xml_check_winaudit = "check_winaudit";
    char *xml_check_winmalware = "check_winmalware";

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
            rootcheck->scanall = eval_bool(node[i]->content);
            if (rootcheck->scanall == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_disabled) == 0)
        {
            rootcheck->disabled = eval_bool(node[i]->content);
            if (rootcheck->disabled == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_readall) == 0)
        {
            rootcheck->readall = eval_bool(node[i]->content);
            if (rootcheck->readall == OS_INVALID)
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
        else if (strcmp(node[i]->element, xml_check_dev) == 0)
        {
            rootcheck->checks.rc_dev = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_dev == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if (strcmp(node[i]->element, xml_check_files) == 0)
        {
            rootcheck->checks.rc_files = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_files == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if (strcmp(node[i]->element, xml_check_if) == 0)
        {
            rootcheck->checks.rc_if = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_if == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if (strcmp(node[i]->element, xml_check_pids) == 0)
        {
            rootcheck->checks.rc_pids = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_pids == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if (strcmp(node[i]->element, xml_check_ports) == 0)
        {
            rootcheck->checks.rc_ports = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_ports == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if (strcmp(node[i]->element, xml_check_sys) == 0)
        {
            rootcheck->checks.rc_sys = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_sys == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if (strcmp(node[i]->element, xml_check_trojans) == 0)
        {
            rootcheck->checks.rc_trojans = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_trojans == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if (strcmp(node[i]->element, xml_check_unixaudit) == 0)
        {
            #ifndef WIN32
            rootcheck->checks.rc_unixaudit = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_unixaudit == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            #endif
        }
        else if (strcmp(node[i]->element, xml_check_winapps) == 0)
        {
            #ifdef WIN32
            rootcheck->checks.rc_winapps = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_winapps == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            #endif
        }
        else if (strcmp(node[i]->element, xml_check_winaudit) == 0)
        {
            #ifdef WIN32
            rootcheck->checks.rc_winaudit = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_winaudit == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            #endif
        }
        else if (strcmp(node[i]->element, xml_check_winmalware) == 0)
        {
            #ifdef WIN32
            rootcheck->checks.rc_winmalware = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_winmalware == OS_INVALID)
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            #endif
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
