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
    int rm_f = 0;
    
    if(tmp_node)
    {
        PluginNode *new_node;
        
        new_node = (PluginNode *)calloc(1,sizeof(PluginNode));
        if(new_node == NULL)
        {
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }

        /* Going to the last node */
        do
        {
            /* Checking for common names */
            if(strcmp(tmp_node->plugin->name,pi->name) == 0)
            {
                if(tmp_node->plugin->prematch && pi->regex_offset)
                {
                    rm_f = 1;                    
                }
                
                /* Multi-regexes patterns cannot have prematch */
                if(pi->prematch)
                {
                    merror(PDUP_INV, ARGV0,pi->name);
                    return(NULL);
                }

                /* Multi-regex patterns cannot have fts set */
                if(pi->fts)
                {
                    merror(PDUPFTS_INV, ARGV0,pi->name);
                    return(NULL);
                }

                if(tmp_node->plugin->regex && pi->regex)
                {
                    tmp_node->plugin->get_next = 1;
                }
                else
                {
                    merror(DUP_INV, ARGV0,pi->name);
                    return(NULL);
                }
            }
            
        }while(tmp_node->next && (tmp_node = tmp_node->next));
        
        /* Must have a prematch set */
        if(!rm_f && (pi->regex_offset & AFTER_PREVREGEX))
        {
            merror(INV_OFFSET, ARGV0, pi->name);
            return(NULL);
        }
        
        tmp_node->next = new_node;
        
        new_node->next = NULL;
        new_node->plugin = pi; 
        new_node->child = NULL;
    }
    
    else
    {
        /* Must have a previous regex set */
        if(pi->regex_offset & AFTER_PREVREGEX)
        {
            merror(INV_OFFSET, ARGV0, pi->name);
            return(NULL);
        }

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

int OS_AddPlugin(PluginInfo *pi)
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
                if(!tmp_node->child)
                {
                    merror(DEC_PLUGIN_ERR, ARGV0);
                    return(0);
                }
                return(1);
            }
            tmp_node = tmp_node->next;
        }
        merror(PPLUGIN_INV, ARGV0, pi->parent);
        return(0); 
    }
    else
    {
        pluginnode = _OS_AddPlugin(pluginnode, pi);
        if(!pluginnode)
        {
            merror(DEC_PLUGIN_ERR, ARGV0);
            return(0);
        }
    }
    return(1);
}

/* EOF */
