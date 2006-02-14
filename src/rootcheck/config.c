/*   $OSSEC, config.c, v0.1, 2005/09/30, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
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

#include "rootcheck.h"

extern short int dbg_flag;


/* Read_Rootcheck_Config: Reads the rootcheck config
 */
int Read_Rootcheck_Config(char * cfgfile)
{
    OS_XML xml;

    char *str = NULL;


    /* XML Definitions */
    char *(xml_daemon[])={xml_rootcheck,"daemon", NULL};
    char *(xml_notify[])={xml_rootcheck, "notify", NULL};
    char *(xml_workdir[])={xml_rootcheck, "work_directory", NULL};
    char *(xml_rootkit_files[])={xml_rootcheck, "rootkit_files", NULL};
    char *(xml_rootkit_trojans[])={xml_rootcheck, "rootkit_trojans", NULL};
    char *(xml_scanall[])={xml_rootcheck, "scanall", NULL};
    char *(xml_time[])={xml_rootcheck, "frequency", NULL};


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
    
    
    rootcheck.rootkit_files  = OS_GetOneContentforElement(&xml,xml_rootkit_files);
    rootcheck.rootkit_trojans  = OS_GetOneContentforElement(&xml,xml_rootkit_trojans);


    OS_ClearXML(&xml);
 
    debug1("%s: DEBUG: Daemon set to '%d'",ARGV0, rootcheck.daemon);
    debug1("%s: DEBUG: alert set to '%d'",ARGV0, rootcheck.notify);
       
    return(0);
}

/* EOF */
