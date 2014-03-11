/* @(#) $Id: ./src/config/active-response.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32
#include <sys/types.h>
#include <grp.h>
#endif
#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "active-response.h"


/** int ReadActiveResponses(XML_NODE node, void *d1, void *d2)
 * Generates a list with all active responses.
 */
int ReadActiveResponses(XML_NODE node, void *d1, void *d2)
{
    FILE *fp;
    int i = 0;
    int r_ar = 0;
    int l_ar = 0;
    int rpt = 0;


    /* Xml options */
    char *xml_ar_command = "command";
    char *xml_ar_location = "location";
    char *xml_ar_agent_id = "agent_id";
    char *xml_ar_rules_id = "rules_id";
    char *xml_ar_rules_group = "rules_group";
    char *xml_ar_level = "level";
    char *xml_ar_timeout = "timeout";
    char *xml_ar_disabled = "disabled";
    char *xml_ar_repeated = "repeated_offenders";

    char *tmp_location;


    /* Currently active response */
    active_response *tmp_ar;


    /* Opening shared ar file */
    fp = fopen(DEFAULTARPATH, "a");
    if(!fp)
    {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH);
        return(-1);
    }

#ifndef WIN32
    struct group *os_group;
    if((os_group = getgrnam(USER)) == NULL)
    {
      merror("Could not get ossec gid.");
      fclose(fp);
      return(-1);
    }

    if((chown(DEFAULTARPATH, -1, os_group->gr_gid)) == -1)
    {
      merror("Could not change the group to ossec: %d", errno);
      fclose(fp);
      return(-1);
    }
#endif

    if((chmod(DEFAULTARPATH, 0440)) == -1)
    {
      merror("Could not chmod to 0440: %d", errno);
      fclose(fp);
      return(-1);
    }


    /* Allocating for the active-response */
    tmp_ar = calloc(1, sizeof(active_response));
    if(!tmp_ar)
    {
        merror(MEM_ERROR, ARGV0);
        fclose(fp);
        return(-1);
    }

    /* Initializing variables */
    tmp_ar->name = NULL;
    tmp_ar->command = NULL;
    tmp_ar->location = 0;
    tmp_ar->timeout = 0;
    tmp_ar->level = 0;
    tmp_ar->agent_id = NULL;
    tmp_ar->rules_id = NULL;
    tmp_ar->rules_group = NULL;
    tmp_ar->ar_cmd = NULL;
    tmp_location = NULL;



    /* Searching for the commands */
    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            goto error_invalid;
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            goto error_invalid;
        }

        /* Command */
        if(strcmp(node[i]->element, xml_ar_command) == 0)
        {
            tmp_ar->command = strdup(node[i]->content);
        }
        /* Target */
        else if(strcmp(node[i]->element, xml_ar_location) == 0)
        {
            tmp_location = strdup(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_ar_agent_id) == 0)
        {
            tmp_ar->agent_id = strdup(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_ar_rules_id) == 0)
        {
            tmp_ar->rules_id = strdup(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_ar_rules_group) == 0)
        {
            tmp_ar->rules_group = strdup(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_ar_level) == 0)
        {
            /* Level must be numeric */
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                goto error_invalid;
            }

            tmp_ar->level = atoi(node[i]->content);

            /* Making sure the level is valid */
            if((tmp_ar->level < 0) || (tmp_ar->level > 20))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                goto error_invalid;
            }
        }
        else if(strcmp(node[i]->element, xml_ar_timeout) == 0)
        {
            tmp_ar->timeout = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_ar_disabled) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
            {
                ar_flag = -1;
            }
            else if(strcmp(node[i]->content, "no") == 0)
            {
                /* Don't do anything if disabled is set to "no" */
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                goto error_invalid;
            }
        }
        else if(strcmp(node[i]->element, xml_ar_repeated) == 0)
        {
            /* Nothing - we deal with it on execd. */
            rpt = 1;
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            goto error_invalid;
        }
        i++;
    }

    /* Checking if ar is disabled */
    if(ar_flag == -1)
    {
        fclose(fp);
        free(tmp_ar);
        return(0);
    }

    /* Command and location must be there */
    if(!tmp_ar->command || !tmp_location)
    {
        if(rpt == 1)
        {
            fclose(fp);
            free(tmp_ar);
            return(0);
        }
        merror(AR_MISS, ARGV0);
        fclose(fp);
        free(tmp_ar);
        return(-1);
    }

    /* analysisd */
    if(OS_Regex("AS|analysisd|analysis-server|server", tmp_location))
    {
        tmp_ar->location|= AS_ONLY;
    }

    if(OS_Regex("local", tmp_location))
    {
        tmp_ar->location|= REMOTE_AGENT;
    }

    if(OS_Regex("defined-agent", tmp_location))
    {
        if(!tmp_ar->agent_id)
        {
            merror(AR_DEF_AGENT, ARGV0);
            fclose(fp);
            free(tmp_ar);
            free(tmp_location);
            return(-1);
        }

        tmp_ar->location|= SPECIFIC_AGENT;

    }
    if(OS_Regex("all|any", tmp_location))
    {
        tmp_ar->location|=ALL_AGENTS;
    }

    /* If we didn't set any value for the location */
    if(tmp_ar->location == 0)
    {
        merror(AR_INV_LOC, ARGV0, tmp_location);
        fclose(fp);
        free(tmp_ar);
        free(tmp_location);
        return(-1);
    }


    /* cleaning tmp_location */
    free(tmp_location);
    tmp_location = NULL;


    /* Checking if command name is valid */
    {
        OSListNode *my_commands_node;

        my_commands_node = OSList_GetFirstNode(d1);
        while(my_commands_node)
        {
            ar_command *my_command;
            my_command = (ar_command *)my_commands_node->data;

            if(strcmp(my_command->name, tmp_ar->command) == 0)
            {
                tmp_ar->ar_cmd = my_command;
                break;
            }

            my_commands_node = OSList_GetNextNode(d1);
        }

        /* Didn't find a valid command */
        if(tmp_ar->ar_cmd == NULL)
        {
            merror(AR_INV_CMD, ARGV0, tmp_ar->command);
            fclose(fp);
            free(tmp_ar);
            return(-1);
        }
    }

    /* Checking if timeout is allowed */
    if(tmp_ar->timeout && !tmp_ar->ar_cmd->timeout_allowed)
    {
        merror(AR_NO_TIMEOUT, ARGV0, tmp_ar->ar_cmd->name);
        fclose(fp);
        free(tmp_ar);
        return(-1);
    }

    /* d1 is the active response list */
    if(!OSList_AddData(d2, (void *)tmp_ar))
    {
        merror(LIST_ADD_ERROR, ARGV0);
        fclose(fp);
        free(tmp_ar);
        return(-1);
    }


    /* Setting a unique active response name */
    tmp_ar->name = calloc(OS_FLSIZE +1, sizeof(char));
    if(!tmp_ar->name)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }
    snprintf(tmp_ar->name, OS_FLSIZE, "%s%d",
            tmp_ar->ar_cmd->name,
            tmp_ar->timeout);


    /* Adding to shared file */
    fprintf(fp, "%s - %s - %d\n",
            tmp_ar->name,
            tmp_ar->ar_cmd->executable,
            tmp_ar->timeout);


    /* Setting the configs to start the right queues */
    if(tmp_ar->location & AS_ONLY)
    {
        l_ar = 1;
    }
    if(tmp_ar->location & ALL_AGENTS)
    {
        r_ar = 1;
    }
    if(tmp_ar->location & REMOTE_AGENT)
    {
        r_ar = 1;
        l_ar = 1;
    }
    if(tmp_ar->location & SPECIFIC_AGENT)
    {
        r_ar = 1;
    }

    /* Setting the configuration for the active response */
    if(r_ar && (!(ar_flag & REMOTE_AR)))
    {
        ar_flag|= REMOTE_AR;
    }
    if(l_ar && (!(ar_flag & LOCAL_AR)))
    {
        ar_flag|= LOCAL_AR;
    }

    /* Closing shared file for active response */
    fclose(fp);

    /* Done over here */
    return(0);

    /* in case of an error clean up first*/
    error_invalid:
    fclose(fp);
    free(tmp_ar);
    return(OS_INVALID);
}



/** int ReadActiveCommands(XML_NODE node, void *d1, void *d2)
 */
int ReadActiveCommands(XML_NODE node, void *d1, void *d2)
{
    int i = 0;

    char *tmp_str = NULL;

    /* Xml values */
    char *command_name = "name";
    char *command_expect = "expect";
    char *command_executable = "executable";
    char *timeout_allowed = "timeout_allowed";

    ar_command *tmp_command;


    /* Allocating the active-response command */
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


    /* Searching for the commands */
    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            free(tmp_command);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            free(tmp_command);
            return(OS_INVALID);
        }
        if(strcmp(node[i]->element, command_name) == 0)
        {
            tmp_command->name = strdup(node[i]->content);
        }
        else if(strcmp(node[i]->element, command_expect) == 0)
        {
            tmp_str = strdup(node[i]->content);
        }
        else if(strcmp(node[i]->element, command_executable) == 0)
        {
            tmp_command->executable = strdup(node[i]->content);
        }
        else if(strcmp(node[i]->element, timeout_allowed) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                tmp_command->timeout_allowed = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                tmp_command->timeout_allowed = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                free(tmp_command);
                return(OS_INVALID);
            }
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            free(tmp_command);
            return(OS_INVALID);
        }
        i++;
    }

    if(!tmp_command->name || !tmp_str || !tmp_command->executable)
    {
        merror(AR_CMD_MISS, ARGV0);
        free(tmp_command);
        return(-1);
    }


    /* Getting the expect */
    if(strlen(tmp_str) >= 4)
    {
        if(OS_Regex("user", tmp_str))
            tmp_command->expect |= USERNAME;
        if(OS_Regex("srcip", tmp_str))
            tmp_command->expect |= SRCIP;
        if(OS_Regex("filename", tmp_str))
            tmp_command->expect |= FILENAME;
    }

    free(tmp_str);
    tmp_str = NULL;


    /* Adding command to the list */
    if(!OSList_AddData(d1, (void *)tmp_command))
    {
        merror(LIST_ADD_ERROR, ARGV0);
        free(tmp_command);
        return(-1);
    }

    /* Done over here */
    return(0);
}


/* EOF */
