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

#include "headers/defs.h"
#include "headers/os_err.h"

#include "headers/file_op.h"
#include "headers/config_op.h"
#include "headers/debug_op.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "syscheck.h"

extern short int dbg_flag;


/* FilesConf v0.3, 2005/03/03
 * Read the config file (the localfiles)
 * v0.3: Changed for the new OS_XML
 */
int Read_Syscheck_Config(char * cfgfile)
{
    OS_XML xml;

    char *str = NULL;

    /* XML Definitions */
    char *(xml_daemon[])={xml_syscheck,"daemon",NULL};
    char *(xml_directories[])={xml_syscheck, "directories",NULL};
    char *(xml_remote_db[])={xml_syscheck, "remote_db",NULL};
    char *(xml_notify[])={xml_syscheck, "notify",NULL};
    char *(xml_workdir[])={xml_syscheck, "work_directory",NULL};

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

    /* Directories to check */
    str = OS_GetOneContentforElement(&xml, xml_directories);	
    if(str == NULL)
    {
        merror("%s: You must set the directories to check",ARGV0);
        OS_ClearXML(&xml);	
        return(OS_NOTFOUND);
    }
    
    /* Breaking the directories by line */
    syscheck.dir = OS_StrBreak(',',str, MAX_DIR_SIZE); /* Max number */
    
    if(syscheck.dir == NULL)
    {
        merror("%s: You must set the directories to check",ARGV0);
        OS_ClearXML(&xml);
        return(OS_NOTFOUND);    
    }

    /* run as a daemon */
    str = OS_GetOneContentforElement(&xml,xml_daemon);
    if(str)
    {
        if(str[0] == 'n')
            syscheck.daemon = 0;
        free(str);
        str = NULL;    
    }

    /* Notifications type */
    str  = OS_GetOneContentforElement(&xml,xml_notify);
    if(str)
    {
        if(strcasecmp(str,"queue") == 0)
            syscheck.notify = QUEUE;
        else if(strcasecmp(str,"syslog") == 0)
            syscheck.notify = SYSLOG;
        else
        {
            ErrorExit("%s: Invalid notification option. Only "
                      "'syslog' or 'queue' are allowed.",ARGV0);
        }
        
        free(str);
        str = NULL;           
    }
    else
    {
        syscheck.notify = SYSLOG;
    }

    /* Getting work directory */
    if(!syscheck.workdir)
        syscheck.workdir  = OS_GetOneContentforElement(&xml,xml_workdir);    
    
    syscheck.remote_db  = OS_GetOneContentforElement(&xml,xml_remote_db);


    OS_ClearXML(&xml);
    return(0);
}
