/* @(#) $Id: ./src/rootcheck/rootcheck-config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef OSSECHIDS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"

#include "os_xml/os_xml.h"

#include "rootcheck.h"


/* Read_Rootcheck_Config: Reads the rootcheck config
 */
int Read_Rootcheck_Config(char * cfgfile)
{
    OS_XML xml;

    char *str = NULL;


    /* XML Definitions */
    char *(xml_daemon[])={xml_rootcheck,"daemon", NULL};
    char *(xml_notify[])={xml_rootcheck, "notify", NULL};
    char *(xml_base_dir[])={xml_rootcheck, "base_directory", NULL};
    char *(xml_workdir[])={xml_rootcheck, "work_directory", NULL};
    char *(xml_rootkit_files[])={xml_rootcheck, "rootkit_files", NULL};
    char *(xml_rootkit_trojans[])={xml_rootcheck, "rootkit_trojans", NULL};
    char *(xml_rootkit_unixaudit[])={xml_rootcheck, "system_audit", NULL};
    char *(xml_rootkit_winaudit[])={xml_rootcheck, "windows_audit", NULL};
    char *(xml_rootkit_winapps[])={xml_rootcheck, "windows_apps", NULL};
    char *(xml_rootkit_winmalware[])={xml_rootcheck, "windows_malware", NULL};
    char *(xml_scanall[])={xml_rootcheck, "scanall", NULL};
    char *(xml_readall[])={xml_rootcheck, "readall", NULL};
    char *(xml_time[])={xml_rootcheck, "frequency", NULL};

    /* :) */
    xml_time[2] = NULL;
    
    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        merror("config_op: XML error: %s",xml.err);
        return(OS_INVALID);
    }

    if(!OS_RootElementExist(&xml,xml_rootcheck))
    {
        OS_ClearXML(&xml);
        merror("%s: Rootcheck configuration not found. ",ARGV0);
        return(-1);
    }


    /* run as a daemon */
    str = OS_GetOneContentforElement(&xml,xml_daemon);
    if(str)
    {
        if(str[0] == 'n')
            rootcheck.daemon = 0;
        free(str);
        str = NULL;    
    }

    /* time  */
    #ifdef OSSECHIDS
    str = OS_GetOneContentforElement(&xml,xml_time);
    if(str)
    {
        if(!OS_StrIsNum(str))
        {
            merror("Invalid frequency time '%s' for the rootkit "
                    "detection (must be int).", str);
            return(OS_INVALID);
        }

        rootcheck.time = atoi(str);

        free(str);
        str = NULL;
    }
    #endif
                                                                                                            
    
    /* Scan all flag */
    if(!rootcheck.scanall)
    {
        str = OS_GetOneContentforElement(&xml,xml_scanall);
        if(str)
        {
            if(str[0] == 'y')
                rootcheck.scanall = 1;
            free(str);
            str = NULL;
        }
    }


    /* read all flag */
    if(!rootcheck.readall)
    {
        str = OS_GetOneContentforElement(&xml,xml_readall);
        if(str)
        {
            if(str[0] == 'y')
                rootcheck.readall = 1;
            free(str);
            str = NULL;
        }
    }
    
    
    /* Notifications type */
    str  = OS_GetOneContentforElement(&xml,xml_notify);
    if(str)
    {
        if(strcasecmp(str,"queue") == 0)
            rootcheck.notify = QUEUE;
        else if(strcasecmp(str,"syslog") == 0)
            rootcheck.notify = SYSLOG;
        else
        {
            merror("%s: Invalid notification option. Only "
                      "'syslog' or 'queue' are allowed.",ARGV0);
            return(-1);
        }
        
        free(str);
        str = NULL;           
    }
    else
    {
        /* Default to SYSLOG */
        rootcheck.notify = SYSLOG;
    }

    /* Getting work directory */
    if(!rootcheck.workdir)
        rootcheck.workdir  = OS_GetOneContentforElement(&xml,xml_workdir);    
    
    
    rootcheck.rootkit_files  = OS_GetOneContentforElement
                               (&xml,xml_rootkit_files);
    rootcheck.rootkit_trojans  = OS_GetOneContentforElement
                               (&xml,xml_rootkit_trojans);
    
    rootcheck.unixaudit = OS_GetContents 
                                (&xml,xml_rootkit_unixaudit);

    rootcheck.winaudit  = OS_GetOneContentforElement
                                (&xml,xml_rootkit_winaudit);

    rootcheck.winapps  = OS_GetOneContentforElement
                                (&xml,xml_rootkit_winapps);

    rootcheck.winmalware  = OS_GetOneContentforElement
                                (&xml,xml_rootkit_winmalware);
                                
    rootcheck.basedir  = OS_GetOneContentforElement(&xml, xml_base_dir);


    OS_ClearXML(&xml);
 
    debug1("%s: DEBUG: Daemon set to '%d'",ARGV0, rootcheck.daemon);
    debug1("%s: DEBUG: alert set to '%d'",ARGV0, rootcheck.notify);
       
    return(0);
}

/* EOF */
#endif
