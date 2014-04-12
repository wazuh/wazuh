/* @(#) $Id: ./src/os_execd/config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "execd.h"


/* ExecdConfig v0.1, 2006/03/24
 * Read the config file
 */
int ExecdConfig(char * cfgfile)
{
    extern int repeated_offenders_timeout[];
    #ifdef WIN32
    int is_disabled = 1;
    #else
    int is_disabled = 0;
    #endif
    const char *(xmlf[]) = {"ossec_config", "active-response", "disabled", NULL};
    const char *(blocks[]) = {"ossec_config", "active-response", "repeated_offenders", NULL};
    char *disable_entry;
    char *repeated_t;
    char **repeated_a;

    OS_XML xml;


    /* Reading XML file */
    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        ErrorExit(XML_ERROR, ARGV0, cfgfile, xml.err, xml.err_line);
    }

    /* We do not validate the xml in here. It is done by other processes */
    disable_entry = OS_GetOneContentforElement(&xml, xmlf);
    if(disable_entry)
    {
        if(strcmp(disable_entry, "yes") == 0)
        {
            is_disabled = 1;
        }
        else if(strcmp(disable_entry, "no") == 0)
        {
            is_disabled = 0;
        }
        else
        {
            merror(XML_VALUEERR, ARGV0,
                    "disabled",
                    disable_entry);
            return(-1);
        }
    }

    repeated_t = OS_GetOneContentforElement(&xml, blocks);
    if(repeated_t)
    {
        int i = 0;
        int j = 0;
        repeated_a = OS_StrBreak(',', repeated_t, 5);
        if(!repeated_a)
        {
            merror(XML_VALUEERR, ARGV0,
                    "repeated_offenders",
                    disable_entry);
            return(-1);
        }

        while(repeated_a[i] != NULL)
        {
            char *tmpt = repeated_a[i];
            while(*tmpt != '\0')
            {
                if(*tmpt == ' ' || *tmpt == '\t')
                   tmpt++;
    	        else
                   break;
            }

            if(*tmpt == '\0')
            {
                i++;
                continue;
            }

            repeated_offenders_timeout[j] = atoi(tmpt);
            verbose("%s: INFO: Adding offenders timeout: %d (for #%d)",
                    ARGV0, repeated_offenders_timeout[j], j+1);
            j++;
            repeated_offenders_timeout[j] = 0;
            if(j >= 6) break;
            i++;
        }
    }


    OS_ClearXML(&xml);
    return(is_disabled);
}

/* EOF */
