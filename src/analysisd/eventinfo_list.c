/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "eventinfo.h"

/* Global variables */
EventNode *eventnode;
EventNode *lastnode;

int _memoryused = 0;
int _memorymaxsize = 0;
int _max_freq = 0;


/* Create the Event List */
void OS_CreateEventList(int maxsize)
{
    eventnode = NULL;
    _memorymaxsize = maxsize;
    _memoryused = 0;

    debug1("%s: OS_CreateEventList completed.", ARGV0);
    return;
}

/* Get the last event -- or first node */
EventNode *OS_GetLastEvent()
{
    EventNode *eventnode_pt = eventnode;

    return (eventnode_pt);
}

/* Add an event to the list -- always to the begining */
void OS_AddEvent(Eventinfo *lf)
{
    EventNode *tmp_node = eventnode;

    if (tmp_node) {
        EventNode *new_node;
        new_node = (EventNode *)calloc(1, sizeof(EventNode));

        if (new_node == NULL) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        /* Always add to the beginning of the list
         * The new node will become the first node and
         * new_node->next will be the previous first node
         */
        new_node->next = tmp_node;
        new_node->prev = NULL;
        tmp_node->prev = new_node;

        eventnode = new_node;

        /* Add the event to the node */
        new_node->event = lf;

        _memoryused++;

        /* Need to remove the last nodes */
        if (_memoryused > _memorymaxsize) {
            int i = 0;
            EventNode *oldlast;

            /* Remove at least the last 10 events
             * or the events that will not match anymore
             * (higher than max frequency)
             */
            while ((i < 10) || ((lf->time - lastnode->event->time) > _max_freq)) {
                oldlast = lastnode;
                lastnode = lastnode->prev;
                lastnode->next = NULL;

                /* Free event info */
                Free_Eventinfo(oldlast->event);
                free(oldlast);

                _memoryused--;
                i++;
            }
        }
    }

    else {
        /* Add first node */
        eventnode = (EventNode *)calloc(1, sizeof(EventNode));
        if (eventnode == NULL) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        eventnode->prev = NULL;
        eventnode->next = NULL;
        eventnode->event = lf;

        lastnode = eventnode;
    }

    return;
}

