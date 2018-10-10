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
#include "rules.h"

/* Local variables */
static EventNode *first_node;
static EventNode *last_node;
static EventNode *last_added_node;

static int _memoryused = 0;
static int _memorymaxsize = 0;
int _max_freq = 0;

static pthread_mutex_t event_mutex = PTHREAD_MUTEX_INITIALIZER;


/* Create the Event List */
void OS_CreateEventList(int maxsize)
{
    first_node = NULL;
    last_added_node = NULL;
    _memorymaxsize = maxsize;
    _memoryused = 0;

    mdebug1("OS_CreateEventList completed.");
    return;
}

/* Get the first node */
EventNode *OS_GetFirstEvent() {
    EventNode *node;
    w_mutex_lock(&event_mutex);
    node = first_node;
    w_mutex_unlock(&event_mutex);
    return node;
}

/* Add an event to the list -- always to the beginning */
void OS_AddEvent(Eventinfo *lf)
{
    w_mutex_lock(&event_mutex);

    if (last_added_node) {
        EventNode *new_node;
        new_node = (EventNode *)calloc(1, sizeof(EventNode));

        if (new_node == NULL) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }

        // Always add after the first node, which must be empty
        new_node->next = last_added_node;
        new_node->prev = first_node;
        last_added_node->prev = new_node;
        first_node->next = new_node;

        last_added_node = new_node;

        _memoryused++;

        /* Need to remove the last nodes */
        if (_memoryused > _memorymaxsize) {
            int i = 0;
            EventNode *oldlast;

            /* Remove at least the last 10 events
             * or the events that will not match anymore
             * (higher than max frequency)
             */
            while (last_node != last_added_node && ((i < 10) || ((lf->time.tv_sec - last_node->event->time.tv_sec) > _max_freq))) {
                oldlast = last_node;
                last_node = last_node->prev;
                last_node->next = NULL;

                /* Free event info */
                Free_Eventinfo(oldlast->event);
                free(oldlast);

                _memoryused--;
                i++;
            }
        }
    } else {
        // Add the first and second node
        // The first node is always empty
        EventNode *second_node;

        os_calloc(1, sizeof(EventNode), second_node);
        if (!first_node) {
            os_calloc(1, sizeof(EventNode), first_node);
            first_node->prev = NULL;
            first_node->event = NULL;
            first_node->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
        }
        _memoryused++;
        first_node->next = second_node;

        second_node->prev = first_node;
        second_node->next = NULL;

        last_node = second_node;
        last_added_node = second_node;
    }

    last_added_node->event = lf;
    lf->node = last_added_node;
    last_added_node->count = 0;
    last_added_node->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    w_mutex_unlock(&event_mutex);

    return;
}
