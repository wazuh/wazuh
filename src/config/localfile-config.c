/*   $OSSEC, config.c, v0.3, 2005/08/23, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.3 (2005/08/23): Using the new OS_XML syntax and changing some usage 
 * v0.2 (2005/01/17)
 */
 

#include "shared.h" 

#include "localfile-config.h"


int Read_Localfile(XML_NODE node, void *d1, void *d2)
{
    int pl = 0;
    int i = 0;

    /* XML Definitions */
    char *xml_localfile_location = "location";
    char *xml_localfile_logformat = "log_format";

    logreader *log;

    log = (logreader *)d1;
    
    log[MAX_READ_FILE].file = NULL;
    log[MAX_READ_FILE].logformat = NULL;
    
    while(log[pl].file != NULL)
        pl++;

    if(pl >= MAX_READ_FILE)
    {
        merror(XML_MAXREACHED, ARGV0, "localfile");
        return(OS_INVALID);     
    }
    
    log[pl].file = NULL;
    log[pl].logformat = NULL;
    log[pl].fp = NULL;
    
    /* Searching for entries related to files */
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
        else if(strcmp(node[i]->element,xml_localfile_location) == 0)
        {
            os_strdup(node[i]->content, log[pl].file);                
        }

        else if(strcasecmp(node[i]->element,xml_localfile_logformat) == 0)
        {
            os_strdup(node[i]->content, log[pl].logformat);

            if(strcmp(log[pl].logformat, "syslog") == 0)
            {
            }
            else if(strcmp(log[pl].logformat, "snort-full") == 0)
            {
            }
            else if(strcmp(log[pl].logformat, "snort-fast") == 0)
            {
            }
            else if(strcmp(log[pl].logformat, "apache") == 0)
            {
            }
            else if(strcmp(log[pl].logformat, "squid") == 0)
            {
            }
            else if(strcmp(log[pl].logformat, EVENTLOG) == 0)
            {
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);

        }

        i++;
    }

    /* Missing log format */
    if(!log[pl].logformat)
    {
        merror(MISS_LOG_FORMAT, ARGV0);
        return(OS_INVALID);
    }

    /* Missing file */
    if(!log[pl].file)
    {
        merror(MISS_FILE, ARGV0);
        return(OS_INVALID);
    }
    
    /* Verifying a valid event log config */
    if(strcmp(log[pl].logformat, EVENTLOG) == 0)
    {
        if((strcmp(log[pl].file, "Application") != 0)&&
           (strcmp(log[pl].file, "System") != 0)&&
           (strcmp(log[pl].file, "Security") != 0))
         {
             /* Invalid event log */
             merror(INV_EVTLOG, ARGV0, log[pl].file);
             return(OS_INVALID);
         }
    }
    return(0);
}

/* EOF */
