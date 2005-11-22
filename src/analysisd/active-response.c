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

#include "active-response.h"

#include "config.h"

/* Initiatiating active response */
void AS_Init()
{
    ar_commands = OSList_Create();
    active_responses = OSList_Create();

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

    FILE *fp;
    int i = 0;
    int j = 0;
    int snort_sz = 1;
    
    char *xml_ar_command = "command";
    char *xml_ar_location = "location";
    char *xml_ar_agent_id = "agent_id";
    char *xml_ar_rules_id = "rules_id";
    char *xml_ar_rules_group = "rules_group";
    char *xml_ar_level = "level";
    char *xml_ar_timeout = "timeout";


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

    
    /* Openning shared ar file */
    fp = fopen(DEFAULTARPATH, "w");
    if(!fp)
    {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH);
        return(-1);
    }

    
    /* Searching for the commands */ 
    while(node[i])
    {
        char *tmp_location;
        XML_NODE elements = NULL;
        active_response *tmp_ar;

        j = 0;
        
        if(strcmp(node[i]->element, xml_ar) != 0)
        {
            i++;
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
        
        /* Initializing variables */
        tmp_ar->name = NULL;
        tmp_ar->command = NULL;
        tmp_ar->location = '\0';

        tmp_ar->timeout = 0;
        
        tmp_ar->agent_id = NULL;
        tmp_ar->rules_id = NULL;
        tmp_ar->rules_group = NULL;
        tmp_ar->level = NULL;
        tmp_ar->ar_cmd = NULL;
        
        tmp_location = NULL;
        
        while(elements[j])
        {
            if(!elements[j]->element || !elements[j]->content) 
                break;
            
            if(strcmp(elements[j]->element, xml_ar_command) == 0)    
            {
                tmp_ar->command = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, xml_ar_location) == 0)    
            {
                tmp_location = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, xml_ar_agent_id) == 0)
            {
                tmp_ar->agent_id = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, xml_ar_rules_id) == 0)
            {
                tmp_ar->rules_id = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, xml_ar_rules_group) == 0)
            {
                tmp_ar->rules_group = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, xml_ar_level) == 0)
            {
                tmp_ar->level = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, xml_ar_timeout) == 0)
            {
                tmp_ar->timeout = atoi(elements[j]->content);
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

        if(!tmp_ar->command || !tmp_location)
        {
            merror(AR_MISS, ARGV0);
            OS_ClearXML(&xml);
            return(-1);
        }
     
        if(OS_Regex("AS|analysis", tmp_location))
        {
            tmp_ar->location = AS_ONLY;
        }
        
        else if(OS_Regex("local", tmp_location))
        {

            tmp_ar->location = REMOTE_AGENT;

        }
        
        else if(OS_Regex("defined-agent", tmp_location))
        {
            if(!tmp_ar->agent_id)
            {
                merror(AR_DEF_AGENT);
                return(-1);
            }
            
            tmp_ar->location = SPECIFIC_AGENT;
            
        }
        else if(OS_Regex("all", tmp_location))
        {
            tmp_ar->location = ALL_AGENTS;
        }
        
        else
        {
            merror(AR_INV_LOC, ARGV0, tmp_location);
            OS_ClearXML(&xml);
            return(-1);
        }
         
        
        /* cleaning tmp_location */ 
        free(tmp_location);
        tmp_location = NULL;
        
        
        /* Checking if command name is valid */
        {
            OSListNode *my_commands_node;

            my_commands_node = OSList_GetFirstNode(ar_commands);
            while(my_commands_node)
            {
                ar_command *my_command;
                my_command = (ar_command *)my_commands_node->data;

                if(strcmp(my_command->name, tmp_ar->command) == 0)
                {
                    tmp_ar->ar_cmd = my_command;
                    break;
                }
                
                my_commands_node = OSList_GetNextNode(ar_commands);
            }

            if(tmp_ar->ar_cmd == NULL)
            {
                merror(AR_INV_CMD, ARGV0, tmp_ar->command);
                OS_ClearXML(&xml);
                return(-1);
            }
        }
       
        /* Checking if timeout is allowed */
        if(tmp_ar->timeout && !tmp_ar->ar_cmd->timeout_allowed)
        {
            merror("%s: Timeout not allowed for command: '%s'", 
                                                          ARGV0, 
                                                          tmp_ar->ar_cmd->name);        
            return(-1);
        }
        
        /* If snort active response, add to the Snort ar */
        if(tmp_ar->rules_group && OS_Regex("snort", tmp_ar->rules_group))
        {
            Config.snort_ar = realloc(Config.snort_ar, (snort_sz + 1) *
                    sizeof(active_response *)); 
            if(!Config.snort_ar)
            {
                ErrorExit(MEM_ERROR, ARGV0);
            }

            Config.snort_ar[snort_sz -1] = tmp_ar;
            Config.snort_ar[snort_sz] = NULL;

            snort_sz++;
        }
        
        
        if(!OSList_AddData(active_responses, (void *)tmp_ar))
        {
            merror(LIST_ADD_ERROR, ARGV0);
            OS_ClearXML(&xml);
            return(-1);
        }
       

        /* Setting a unique active response name */
        tmp_ar->name = calloc(OS_MAXSTR +1, sizeof(char));
        if(!tmp_ar->name)
        {
            ErrorExit(MEM_ERROR, ARGV0);
        }
        snprintf(tmp_ar->name, OS_MAXSTR, "%s%d", tmp_ar->ar_cmd->name,
                                                  tmp_ar->timeout);  
        
        
        /* Adding to shared file */
        fprintf(fp, "%s - %s - %d\n", tmp_ar->name,
                                      tmp_ar->ar_cmd->executable,
                                      tmp_ar->timeout);

        
        /* Settin the configs to start the right queues */ 
        if(tmp_ar->location == AS_ONLY)
        {
            Config.local_ar = 1;
        }
        else if(tmp_ar->location == ALL_AGENTS)
        {
            Config.local_ar = 1;
            Config.remote_ar = 1;
        }
        else if(tmp_ar->location == REMOTE_AGENT)
        {
            Config.local_ar = 1;
            Config.remote_ar = 1;
        }
        else
        {
            Config.remote_ar = 1;
        }
        
        Config.ar = 1;
            
        i++;
    } 

    /* Cleaning global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    
    /* Closing shared file for active response */
    fclose(fp);
    
    
    /* Done over here */
    return(0);
}



/* get the list of active response commands */
int AS_GetActiveResponseCommands(char * config_file)
{
    OS_XML xml;
    XML_NODE node = NULL;

    int i = 0;

    char *tmp_str = NULL;

    char *command_name = "name";
    char *command_expect = "expect";
    char *command_executable = "executable";
    char *timeout_allowed = "timeout_allowed";
    
    
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
            i++;
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
        
        tmp_command->name = NULL; 
        tmp_command->expect= 0;
        tmp_command->executable = NULL; 
        tmp_command->timeout_allowed = 0;
        
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
                tmp_str = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, command_executable) == 0)
            {
                tmp_command->executable = strdup(elements[j]->content);
            }
            else if(strcmp(elements[j]->element, timeout_allowed) == 0)
            {
                if(elements[j]->content[0] == 'y')
                {
                    tmp_command->timeout_allowed = 1;
                }
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

        if(!tmp_command->name || !tmp_str
            || !tmp_command->executable)
        {
            merror(AR_CMD_MISS, ARGV0);
            OS_ClearXML(&xml);
            return(-1);
        }
       
       
        /* Getting the expect */
        if(OS_Regex("user", tmp_str))
            tmp_command->expect |= USERNAME;
        if(OS_Regex("srcip", tmp_str))
            tmp_command->expect |= SRCIP;
        
        free(tmp_str);
        tmp_str = NULL;
        
                
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
