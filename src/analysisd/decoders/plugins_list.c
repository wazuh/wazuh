/*   $OSSEC, plugins_list.c, v0.1, 2005/06/21, Daniel B. Cid$   */

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

#include "headers/debug_op.h"
#include "decoder.h"

#include "error_messages/error_messages.h"

PluginNode *pluginnode;


/* Create the Event List */
void OS_CreatePluginList()
{
    pluginnode = NULL;

    return;
}

/* Get first plugin */
PluginNode *OS_GetFirstPlugin()
{
    PluginNode *pluginnode_pt = pluginnode;

    return(pluginnode_pt);    
}


/* Add a plugin to the list */
PluginNode *_OS_AddPlugin(PluginNode *s_node, PluginInfo *pi)
{
    PluginNode *tmp_node = s_node;
    
    if(tmp_node)
    {
        PluginNode *new_node;
        
        new_node = (PluginNode *)calloc(1,sizeof(PluginNode));
        if(new_node == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        /* Going to the last node */
        while(tmp_node->next)
        {
            tmp_node = tmp_node->next;
        }
        
        tmp_node->next = new_node;
        
        new_node->next = NULL;
        new_node->plugin = pi; 
        new_node->child = NULL;
    }
    
    else
    {
        tmp_node = (PluginNode *)calloc(1, sizeof(PluginNode));
        
        if(tmp_node == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        tmp_node->child = NULL;
        tmp_node->next = NULL;
        tmp_node->plugin = pi;

        s_node = tmp_node;
    }

    return (s_node);
}

void OS_AddPlugin(PluginInfo *pi)
{
    /* Search for parent */
    if(pi->parent)
    {
        PluginNode *tmp_node = pluginnode;

        while(tmp_node)
        {
            if(strcmp(tmp_node->plugin->name, pi->parent) == 0)
            {
                tmp_node->child = _OS_AddPlugin(tmp_node->child, pi);
                return;
            }
            tmp_node = tmp_node->next;
        }
        merror("%s: Parent plugin '%s' not found", ARGV0,
                                                   pi->parent);

        return; 
    }
    else
    {
        pluginnode = _OS_AddPlugin(pluginnode, pi);
    }
}

/* EOF */
