/* @(#) $Id: ./src/analysisd/decoders/decoders_list.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers/debug_op.h"
#include "decoder.h"

#include "error_messages/error_messages.h"


/* We have two internal lists. One with the program_name
 * and one without. This is going to improve greatly the
 * performance of our decoder matching.
 */
OSDecoderNode *osdecodernode_forpname;
OSDecoderNode *osdecodernode_nopname;


/* Create the Event List */
void OS_CreateOSDecoderList()
{
    osdecodernode_forpname = NULL;
    osdecodernode_nopname = NULL;

    return;
}


/* Get first osdecoder */
OSDecoderNode *OS_GetFirstOSDecoder(char *p_name)
{
    /* If program name is set, we return the forpname list.
     */
    if(p_name)
    {
        return(osdecodernode_forpname);
    }

    return(osdecodernode_nopname);
}


/* Add a osdecoder to the list */
OSDecoderNode *_OS_AddOSDecoder(OSDecoderNode *s_node, OSDecoderInfo *pi)
{
    OSDecoderNode *tmp_node = s_node;
    OSDecoderNode *new_node;
    int rm_f = 0;

    if(tmp_node)
    {
        new_node = (OSDecoderNode *)calloc(1,sizeof(OSDecoderNode));
        if(new_node == NULL)
        {
            merror(MEM_ERROR,ARGV0, errno, strerror(errno));
            return(NULL);
        }

        /* Going to the last node */
        do
        {
            /* Checking for common names */
            if((strcmp(tmp_node->osdecoder->name,pi->name) == 0) &&
               (pi->parent != NULL))
            {
                if((tmp_node->osdecoder->prematch ||
                    tmp_node->osdecoder->regex) && pi->regex_offset)
                {
                    rm_f = 1;
                }

                /* Multi-regexes patterns cannot have prematch */
                if(pi->prematch)
                {
                    merror(PDUP_INV, ARGV0,pi->name);
                    goto error;
                }

                /* Multi-regex patterns cannot have fts set */
                if(pi->fts)
                {
                    merror(PDUPFTS_INV, ARGV0,pi->name);
                    goto error;
                }

                if(tmp_node->osdecoder->regex && pi->regex)
                {
                    tmp_node->osdecoder->get_next = 1;
                }
                else
                {
                    merror(DUP_INV, ARGV0,pi->name);
                    goto error;
                }
            }

        }while(tmp_node->next && (tmp_node = tmp_node->next));


        /* Must have a prematch set */
        if(!rm_f && (pi->regex_offset & AFTER_PREVREGEX))
        {
            merror(INV_OFFSET, ARGV0, pi->name);
            goto error; 
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
            ErrorExit(MEM_ERROR,ARGV0, errno, strerror(errno));
        }

        tmp_node->child = NULL;
        tmp_node->next = NULL;
        tmp_node->osdecoder = pi;

        s_node = tmp_node;
    }

    return (s_node);

error:
    if(new_node) free(new_node); 
    return(NULL);
}


int OS_AddOSDecoder(OSDecoderInfo *pi)
{
    int added = 0;
    OSDecoderNode *osdecodernode;


    /* We can actually have two lists. One with program
     * name and the other without.
     */
    if(pi->program_name)
    {
        osdecodernode = osdecodernode_forpname;
    }
    else
    {
        osdecodernode = osdecodernode_nopname;
    }


    /* Search for parent on both lists */
    if(pi->parent)
    {
        OSDecoderNode *tmp_node = osdecodernode_forpname;

        /* List with p_name */
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


        /* List without p name */
        tmp_node = osdecodernode_nopname;
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

        /* Updating global decoders pointers */
        if(pi->program_name)
        {
            osdecodernode_forpname = osdecodernode;
        }
        else
        {
            osdecodernode_nopname = osdecodernode;
        }
    }
    return(1);
}

/* EOF */
