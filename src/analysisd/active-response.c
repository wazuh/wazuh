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
    ar_commands = OS_CreateList();
    active_responses = OS_CreateList();

    if(!ar_commands || !active_responses)
    {
        ErrorExit(LIST_ERROR, ARGV0);
    }
}



/* get the list of all active responses */
int AS_GetActiveResponses(char * config_file)
{
    OS_XML xml;
    XML_NODE node = NULL;

    int i = 0;

    char *ar_command = "command";
    char *ar_location = "location";
    char *ar_rules_id = "rules_id";
    char *ar_rules_group = "rules_group";
    char *ar_level = "level";


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
        active_response *tmp_ar;

        int j = 0;
        
        if(strcmp(node[i]->element, xml_ar) != 0)
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
        tmp_ar = calloc(1, sizeof(active_response));
        if(!tmp_ar)
        {
            merror(MEM_ERROR, ARGV0);
            return(-1);
        }
        
        
        while(elements[j])
        {
            if(!elements[j]->element || !elements[j]->content) 
                break;
            
            if(strcmp(elements[j]->element, ar_command) == 0)    
            {
                tmp_ar->command = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, ar_location) == 0)    
            {
                tmp_ar->location = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, ar_rules_id) == 0)
            {
                tmp_ar->rules_id = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, ar_rules_group) == 0)
            {
                tmp_ar->rules_group = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, ar_level) == 0)
            {
                tmp_ar->level = strdup(elements[j]->content);
            }
            else
            {
                merror(XML_INVALID, ARGV0, elements[j]->element, 
                                           node[i]->element);
                OS_ClearXML(&xml);
                return(-1);
            }
            

            j++; /* next element */
        } 
        
        OS_ClearNode(elements);

        if(!tmp_ar->command || !tmp_ar->location)
        {
            merror(AR_MISS, ARGV0);
            OS_ClearXML(&xml);
            return(-1);
        }
       
        if(!OSList_AddData(active_responses, (void *)tmp_ar))
        {
            merror(LIST_ADD_ERROR, ARGV0);
            OS_ClearXML(&xml);
            return(-1);
        }
        
        i++;
    } 

    /* Cleaning global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);


    /* Done over here */
    return(0);
}



/* get the list of active response commands */
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
        ar_command *tmp_command;

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
        tmp_command = calloc(1, sizeof(ar_command));
        if(!tmp_command)
        {
            merror(MEM_ERROR, ARGV0);
            return(-1);
        }
        
        
        while(elements[j])
        {
            if(!elements[j]->element || !elements[j]->content) 
                break;
            
            if(strcmp(elements[j]->element, command_name) == 0)    
            {
                tmp_command->name = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, command_expect) == 0)    
            {
                tmp_command->expect = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, command_executable) == 0)
            {
                tmp_command->executable = strdup(elements[j]->content);
            }
            else
            {
                merror(XML_INVALID, ARGV0, elements[j]->element, 
                                           node[i]->element);
                OS_ClearXML(&xml);
                return(-1);
            }
            

            j++; /* next element */
        } 
        
        OS_ClearNode(elements);

        if(!tmp_command->name || !tmp_command->expect
            || !tmp_command->executable)
        {
            merror(AR_CMD_MISS, ARGV0);
            OS_ClearXML(&xml);
            return(-1);
        }
       
        if(!OSList_AddData(ar_commands, (void *)tmp_command))
        {
            merror(LIST_ADD_ERROR, ARGV0);
            OS_ClearXML(&xml);
            return(-1);
        }
        
        i++;
    } 

    /* Cleaning global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);


    /* Done over here */
    return(0);
}


/* EOF */
