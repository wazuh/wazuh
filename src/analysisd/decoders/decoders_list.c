/*   $OSSEC, osdecoders_list.c, v0.1, 2005/06/21, Daniel B. Cid$   */

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

OSDecoderNode *osdecodernode;


/* Create the Event List */
void OS_CreateOSDecoderList()
{
    osdecodernode = NULL;

    return;
}

/* Get first osdecoder */
OSDecoderNode *OS_GetFirstOSDecoder()
{
    OSDecoderNode *osdecodernode_pt = osdecodernode;

    return(osdecodernode_pt);    
}


/* Add a osdecoder to the list */
OSDecoderNode *_OS_AddOSDecoder(OSDecoderNode *s_node, OSDecoderInfo *pi)
{
    OSDecoderNode *tmp_node = s_node;
    int rm_f = 0;
    
    if(tmp_node)
    {
        OSDecoderNode *new_node;
        
        new_node = (OSDecoderNode *)calloc(1,sizeof(OSDecoderNode));
        if(new_node == NULL)
        {
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }

        /* Going to the last node */
        do
        {
            /* Checking for common names */
            if((strcmp(tmp_node->osdecoder->name,pi->name) == 0) &&
               (pi->parent != NULL))
            {
                if(tmp_node->osdecoder->prematch && pi->regex_offset)
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

                if(tmp_node->osdecoder->regex && pi->regex)
                {
                    tmp_node->osdecoder->get_next = 1;
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
        new_node->osdecoder = pi; 
        new_node->child = NULL;
    }
    
    else
    {
        /* Must not have a previous regex set */
        if(pi->regex_offset & AFTER_PREVREGEX)
        {
            merror(INV_OFFSET, ARGV0, pi->name);
            return(NULL);
        }

        tmp_node = (OSDecoderNode *)calloc(1, sizeof(OSDecoderNode));

        if(tmp_node == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        tmp_node->child = NULL;
        tmp_node->next = NULL;
        tmp_node->osdecoder = pi;

        s_node = tmp_node;
    }

    return (s_node);
}


int OS_AddOSDecoder(OSDecoderInfo *pi)
{
    int added = 0;

    
    /* Search for parent */
    if(pi->parent)
    {
        OSDecoderNode *tmp_node = osdecodernode;

        while(tmp_node)
        {
            if(strcmp(tmp_node->osdecoder->name, pi->parent) == 0)
            {
                tmp_node->child = _OS_AddOSDecoder(tmp_node->child, pi);
                if(!tmp_node->child)
                {
                    merror(DEC_PLUGIN_ERR, ARGV0);
                    return(0);
                }
                added = 1;
            }
            tmp_node = tmp_node->next;
        }

        /* OSDecoder was added correctly */
        if(added == 1)
        {
            return(1);
        }
        
        merror(PPLUGIN_INV, ARGV0, pi->parent);
        return(0); 
    }
    else
    {
        osdecodernode = _OS_AddOSDecoder(osdecodernode, pi);
        if(!osdecodernode)
        {
            merror(DEC_PLUGIN_ERR, ARGV0);
            return(0);
        }
    }
    return(1);
}

/* EOF */
