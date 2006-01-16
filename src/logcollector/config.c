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

#include "logcollector.h"


/* LogCollectorConfig v0.3, 2005/03/03
 * Read the config file (the localfiles)
 * v0.3: Changed for the new OS_XML
 */
int LogCollectorConfig(char * cfgfile)
{
    int i = 0,j = 0;
    int rentries = 0, fentries = 0;
    OS_XML xml;
    XML_NODE node = NULL;

    /* XML Definitions */
    char *xml_localfile_location = "location";
    char *xml_localfile_logformat = "log_format";

    /* Reading XML file */
    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        merror("config_op: XML error: %s",xml.err);
        return(OS_INVALID);
    }

    /* Getting total number of entries */
    if((rentries = OS_RootElementExist(&xml,xml_localfile)) <= 0)
    {
        OS_ClearXML(&xml);
        return(OS_NOTFOUND);
    }

    node = OS_GetElementsbyNode(&xml,NULL);
    if(node == NULL)
    {
        merror("remoted: Error reading the XML.");
        OS_ClearXML(&xml);
        return(OS_CFGERR);
    }

    /* Allocating memory for the file structure */
    os_calloc(rentries+1, sizeof(logreader), logr);
    
    logr[rentries].file = NULL;
    logr[rentries].logformat = NULL;
    
    
    /* Searching for entries related to files */
    i = 0;
    while(node[i])
    {
        if(node[i]->element)
        {
            if(strcmp(node[i]->element,xml_localfile) == 0)
            {
                XML_NODE chld_node = NULL;
                
                j = 0;
 
                if(fentries >= rentries)
                {
                    merror("%s: Error reading XML nodes",ARGV0);
                    OS_ClearXML(&xml);
                    return(OS_CFGERR);
                }

                logr[fentries].file = NULL;
                logr[fentries].logformat = NULL;
                logr[fentries].fp = NULL;
                
                chld_node = OS_GetElementsbyNode(&xml,node[i]);

                while(chld_node[j])
                {
                    if((!chld_node[j]->element)||(!chld_node[j]->content))
                    {
                        merror("%s: Error reading XML child nodes",ARGV0);
                        OS_ClearXML(&xml);
                        return(OS_CFGERR);
                    }

                    else if(strcmp(chld_node[j]->element,
                            xml_localfile_location) == 0)
                    {
                        os_strdup(chld_node[j]->content, logr[fentries].file);                
                    }
                    
                    else if(strcasecmp(chld_node[j]->element,
                            xml_localfile_logformat) == 0)
                    {
                        os_strdup(chld_node[j]->content, 
                                logr[fentries].logformat);
                        
                        if(strcmp(logr[fentries].logformat, "syslog") == 0)
                        {
                        }
                        else if(strcmp(logr[fentries].logformat, "snort-full") == 0)
                        {
                        }
                        else if(strcmp(logr[fentries].logformat, "snort-fast") == 0)
                        {
                        }
                        else if(strcmp(logr[fentries].logformat, "apache") == 0)
                        {
                        }
                        else
                        {
                            ErrorExit("%s: Invalid log format '%s'. "
                                      "Only 'syslog', 'snort-full', 'snort-fast'"
                                      " and 'apache' are allowed.", 
                                      ARGV0, 
                                      logr[fentries].logformat);
                        }
                    }
                    else
                    {
                        ErrorExit("%s: Invalid element '%s' in the %s config",
                                ARGV0,chld_node[j]->element, xml_localfile);
                    }

                    if(!logr[fentries].logformat)
                    {
                        /* default log format is syslog compatible */
                        os_strdup("syslog", logr[fentries].logformat);
                    }
                    
                    j++;
                }
               
                fentries++;
            }
        }
        i++;
    }                    
                        
    OS_ClearXML(&xml);
    return(rentries);
}

/* EOF */
