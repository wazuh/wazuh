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

    logreader *logf;

    logf = (logreader *)d1;
    
    logf[MAX_READ_FILE].file = NULL;
    logf[MAX_READ_FILE].logformat = NULL;
    
    while(logf[pl].file != NULL)
        pl++;

    if(pl >= MAX_READ_FILE)
    {
        merror(XML_MAXREACHED, ARGV0, "localfile");
        return(OS_INVALID);     
    }
    
    logf[pl].file = NULL;
    logf[pl].logformat = NULL;
    logf[pl].fp = NULL;
    logf[pl].ffile = NULL;
    
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
            /* We need the format file */
            if(strchr(node[i]->content, '%'))
            {
                struct tm *p;
                int l_time = time(0);
                char lfile[OS_FLSIZE + 1];
                size_t ret;

                p = localtime(&l_time);

                lfile[OS_FLSIZE] = '\0';
                ret = strftime(lfile, OS_FLSIZE, node[i]->content, p);
                if(ret == 0)
                {
                    merror(PARSE_ERROR, ARGV0, logf[i].ffile);
                    return(OS_INVALID);
                }

                os_strdup(node[i]->content, logf[pl].ffile);
            }
            os_strdup(node[i]->content, logf[pl].file);
        }

        else if(strcasecmp(node[i]->element,xml_localfile_logformat) == 0)
        {
            os_strdup(node[i]->content, logf[pl].logformat);

            if(strcmp(logf[pl].logformat, "syslog") == 0)
            {
            }
            else if(strcmp(logf[pl].logformat, "snort-full") == 0)
            {
            }
            else if(strcmp(logf[pl].logformat, "snort-fast") == 0)
            {
            }
            else if(strcmp(logf[pl].logformat, "apache") == 0)
            {
            }
            else if(strcmp(logf[pl].logformat, "iis") == 0)
            {
            }
            else if(strcmp(logf[pl].logformat, "squid") == 0)
            {
            }
            else if(strcmp(logf[pl].logformat, EVENTLOG) == 0)
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
    if(!logf[pl].logformat)
    {
        merror(MISS_LOG_FORMAT, ARGV0);
        return(OS_INVALID);
    }

    /* Missing file */
    if(!logf[pl].file)
    {
        merror(MISS_FILE, ARGV0);
        return(OS_INVALID);
    }
    
    /* Verifying a valid event log config */
    if(strcmp(logf[pl].logformat, EVENTLOG) == 0)
    {
        if((strcmp(logf[pl].file, "Application") != 0)&&
           (strcmp(logf[pl].file, "System") != 0)&&
           (strcmp(logf[pl].file, "Security") != 0))
         {
             /* Invalid event log */
             merror(INV_EVTLOG, ARGV0, logf[pl].file);
             return(OS_INVALID);
         }
    }
    return(0);
}

/* EOF */
