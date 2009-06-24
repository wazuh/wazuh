/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h" 


/* ExecdConfig v0.1, 2006/03/24
 * Read the config file
 */
int ExecdConfig(char * cfgfile)
{
    #ifdef WIN32
    int is_disabled = 1;
    #else
    int is_disabled = 0;
    #endif
    char *(xmlf[]) = {"ossec_config", "active-response", "disabled", NULL};
    char *disable_entry;

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
    
    OS_ClearXML(&xml);
    return(is_disabled);
}

/* EOF */
