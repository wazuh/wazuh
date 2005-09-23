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
void OS_AddPlugin(PluginInfo *pi)
{
    PluginNode *tmp_node = pluginnode;
        
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
    }
    
    else
    {
        pluginnode = (PluginNode *)calloc(1,sizeof(PluginNode));
        
        if(pluginnode == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        pluginnode->next = NULL;
        pluginnode->plugin = pi;
    }

    return;
}

/* EOF */
