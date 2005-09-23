/*   $OSSEC, eventinfo_list.c, v0.1, 2005/05/30, Daniel B. Cid$   */

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
#include "eventinfo.h"

#include "error_messages/error_messages.h"

EventNode *eventnode;
EventNode *lastnode;

int _memoryused = 0;
int _memorymaxsize = 0;

/* Create the Event List */
void OS_CreateEventList(int maxsize)
{
    eventnode = NULL;

    _memorymaxsize = maxsize;

    _memoryused = 0;
    return;
}

/* Get the last event -- or first node */
EventNode *OS_GetLastEvent()
{
    EventNode *eventnode_pt = eventnode;

    return(eventnode_pt);    
}

/* Add an event to the list -- always to the begining */
void OS_AddEvent(Eventinfo *lf)
{
    EventNode *tmp_node = eventnode;
        
    if(tmp_node)
    {
        EventNode *new_node;
        new_node = (EventNode *)calloc(1,sizeof(EventNode));
        
        if(new_node == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        /* Always adding to the beginning of the list 
         * The new node will become the first node and
         * new_node->next will be the previous first node
         */
        new_node->next = tmp_node;
        new_node->prev = NULL;
        tmp_node->prev = new_node;
        
        eventnode = new_node;

        /* Adding the event to the node */
        new_node->event = lf;

        _memoryused++;
        
        /* Need to remove the last node */
        if(_memoryused > _memorymaxsize)
        {
            EventNode *oldlast;

            oldlast = lastnode;
            lastnode = lastnode->prev;
            lastnode->next = NULL;
            
            /* free event info */
            Free_Eventinfo(oldlast->event);
            free(oldlast);

            _memoryused--;
        }
    }
    
    else
    {
        /* Adding first node */
        eventnode = (EventNode *)calloc(1,sizeof(EventNode));
        if(eventnode == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        eventnode->prev = NULL;
        eventnode->next = NULL;
        eventnode->event = lf;
        
        lastnode = eventnode; 
    }

    return;
}

/* EOF */
