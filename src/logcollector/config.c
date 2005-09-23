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
#include "os_net/os_net.h"

#include "logcollector.h"
#include "error_messages/error_messages.h"


/* FilesConf v0.3, 2005/03/03
 * Read the config file (the localfiles)
 * v0.3: Changed for the new OS_XML
 */
int FilesConf(char * cfgfile)
{
    int i = 0,j = 0;
    int rentries = 0, fentries = 0;
    OS_XML xml;
    XML_NODE node = NULL;

    /* XML Definitions */
    char *xml_localfile_location = "location";
    char *xml_localfile_group = "group";

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
    logr = (logreader *)calloc(rentries+1, sizeof(logreader));
    if(logr == NULL)
        ErrorExit(MEM_ERROR,ARGV0);
    logr[rentries].file = NULL;
    logr[rentries].group = NULL;
    
    
    /* Searching for entries related to files */
    i = 0;
    while(node[i])
    {
        if(node[i]->element)
        {
            if(strcasecmp(node[i]->element,xml_localfile) == 0)
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
                logr[fentries].group = NULL;
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

                    else if(strcasecmp(chld_node[j]->element,
                            xml_localfile_location) == 0)
                    {
                        logr[fentries].file = 
                                strdup(chld_node[j]->content);                
                    }
                    
                    else if(strcasecmp(chld_node[j]->element,
                            xml_localfile_group) == 0)
                    {
                        logr[fentries].group = 
                                strdup(chld_node[j]->content);
                    }
                    else
                    {
                        merror("%s: Invalid element '%s' in the %s config",
                                ARGV0,chld_node[j]->element, xml_localfile);
                    }

                    j++;
                }
               
                /* Returning if invalid the config */ 
                if(!logr[fentries].file || !logr[fentries].group)
                {
                    merror("%s: Each file must have an associated group. "
                           "Config Error.",ARGV0);
                    OS_ClearXML(&xml);
                    return(OS_INVALID);
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
