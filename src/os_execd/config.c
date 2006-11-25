/* @(#) $Id$ */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h" 


/* ExecdConfig v0.1, 2006/03/24
 * Read the config file
 */
int ExecdConfig(char * cfgfile)
{
    char *(xmlf[]) = {"ossec_config", "active_response", "disabled", NULL};
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
            return(1);
        }
        else if(strcmp(disable_entry, "no") == 0)
        {
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
    return(0);
}

/* EOF */
