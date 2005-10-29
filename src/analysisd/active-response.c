/*   $OSSEC, active-response.c, v0.1, 2005/10/28, Daniel B. Cid$   */

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

#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"

#include "shared.h"

#include "rules.h"
#include "config.h"


/* Initiatiating active response */
void AS_Init()
{
    ar_commands = NULL;
    active-responses = NULL;
}

int AS_GetActiveResponseCommands(char * config_file)
{
    OS_XML xml;
    XML_NODE node = NULL;

    int i = 0;

    char *command_name = "name";
    char *command_expect = "expect";
    char *command_executable = "executable";

    /* Reading the XML */       
    if(OS_ReadXML(config_file, &xml) < 0)
    {
        merror(XML_ERROR, ARGV0, xml.err);
        return(-1);	
    }

    
    /* Applying any variable found */
    if(OS_ApplyVariables(&xml) != 0)
    {
        merror(XML_ERROR_VAR, ARGV0);
        OS_ClearXML(&xml);
        return(-1);
    }


    /* Getting the root elements */
    node = OS_GetElementsbyNode(&xml,NULL);
    if(!node)
    {
        merror(CONFIG_ERROR, ARGV0);
        OS_ClearXML(&xml);
        return(-1);    
    }

    /* Searching for the commands */ 
    while(node[i])
    {
        XML_NODE elements = NULL;
        ar_command **tmp_commands = ar_commands;

        int j = 0;
        
        if(strcmp(node[i]->element, xml_command) != 0)
        {
            continue;
        }
        
        /* Getting all options for command */        
        elements = OS_GetElementsbyNode(&xml, node[i]);
        if(elements == NULL)
        {
            merror(XML_NO_ELEM, ARGV0, node[i]->element);
            i++;
            continue;
        }


        /* Allocating for the active-response */
        while(*tmp_commands)
        {
            tmp_commands++;
        }
        ar_command **ar_commands;

        
        while(elements[j])
        {
            if(!elements[j]->element) 
                break;
            
            if(strcmp(elements[j]->element, command_name) == 0)    
            {
            }
            else if(strcmp(elements[j]->element, command_expect) == 0)    
            {
            }
            else if(strcmp(elements[j]->element, command_executable) == 0)
            {
            }
            else
            {
                merror(XML_INVALID, ARGV0, elements[j]->element, 
                                           node[i]->element);
                OS_ClearXML(&xml);
                return(-1);
            }
            

            j++; /* next rule */

        } 
        
        OS_ClearNode(elements);
        
        i++;
    } 

    /* Cleaning global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);


    /* Done over here */
    return(0);
}


/* EOF */
