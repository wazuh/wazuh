/*   $OSSEC, config.c, v0.1, 2005/04/01, Daniel B. Cid$   */

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

#include "headers/defs.h"
#include "headers/os_err.h"

#include "headers/file_op.h"
#include "headers/config_op.h"
#include "headers/debug_op.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "error_messages/error_messages.h"

#include "execd.h"

extern short int dbg_flag;

/* ExecConf v0.1: 2005/04/06
 * Reads the Execd configuration
 */
int ExecConf(char *cfgfile, execd_config *execd)
{
    OS_XML xml;
    XML_NODE node=NULL;
    int k=0,i=0;

    char *xml_execd_command="command"; /* xml */
        
    execd = calloc(1,sizeof(execd_config));
    if(execd == NULL)
    {
        merror("execd_config: Memory errors. Exiting");
        return(-1);
    }

    /* Default values for the structure */
    execd->name=NULL;
    execd->cmd=NULL;
   
   
    /* Reading XML */
   	if(OS_ReadXML(cfgfile,&xml) < 0)
		{
		merror("config_op: XML Error: %s",xml.err);
		return(OS_INVALID);
		}

    /* Getting the root elements */
    node = OS_GetElementsbyNode(&xml,NULL);
    if(!node)
    {
        merror("execd_config: Bad configuration file syntax");
        OS_ClearXML(&xml);
        return(-1);    
    }
   
    /* Checking if there is any configuration for execd */
    while(node[i])
    {
        if(node[i]->element)
        {
            if(strcasecmp(node[i]->element,xml_execd) == 0)
            {
                XML_NODE child_node=NULL;
                int j=0;
                if((child_node = OS_GetElementsbyNode(&xml,node[i])) == NULL)
                {
                    merror("config: Execd element with no command configured");
                    continue;
                    i++;
                }
                while(child_node[j])
                {
                    if((child_node[j]->element)&&
                        (strcasecmp(child_node[j]->element,
                        xml_execd_command) == 0))
                    {
                        if((child_node[j]->attributes[0] == NULL)||
                            (strcasecmp(child_node[j]->attributes[0],"name")
                            != 0)||
                            (child_node[j]->values[0] == NULL))
                        {
                            merror("execd_config: You need to specify a name "
                                   "for your command");
                            OS_ClearXML(&xml);
                            return(-1);
                        }
                        if(child_node[j]->content == NULL)
                        {
                            merror("execd_config: You need to specify a "
                                   "command for the execd name: \"%s\"",
                                   child_node[j]->values[0]);
                            OS_ClearXML(&xml);
                            return(-1);
                        }
                        execd->name = (char**)realloc(execd->name,(k+1)*
                                        sizeof(char *));
                        execd->cmd = (char **)realloc(execd->name,(k+1)*
                                        sizeof(char *));
                        if((execd->name == NULL)||(execd->cmd == NULL))
                        {
                            merror(MEM_ERROR,ARGV0);
                            return(-1);
                        }
                        execd->name[k]=strdup(child_node[j]->values[0]);
                        execd->cmd[k]=strdup(child_node[j]->content);
                        if((execd->name[k] == NULL)||(execd->cmd[k] == NULL))
                        {
                            merror(MEM_ERROR,ARGV0);
                            return(-1);
                        }
                        k++;
                    }
                    else
                    {
                        merror("execd_config: Invalid configuration for execd."
                               " You can only have a \"command\" sub element");
                        OS_ClearXML(&xml);
                        return(-1);
                    }
                }
                OS_ClearNode(child_node);
            }
        }
        else
        {
            merror("execd_config: Invalid root element. Unknown location");
            OS_ClearXML(&xml);
            return(-1);
        }
        i++;
    }
    
    /* Freeing the node memory */
    OS_ClearNode(node);

    if(k == 0)
    {
        merror("execd_config: No configuration found for execd. Exiting.");
        return(OS_NOTFOUND);
    }
    execd->name = (char**)realloc(execd->name,(k+1)*sizeof(char *));
    execd->cmd = (char **)realloc(execd->name,(k+1)*sizeof(char *));
    if((execd->name == NULL)||(execd->cmd == NULL))
    {
        merror(MEM_ERROR,ARGV0);
        return(-1);
    }
    execd->name[k]=NULL;
    execd->cmd[k]=NULL;
    return(0);
}
