/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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

/* Create the Event List */
void OS_CreateEventList(int maxsize, EventList *list)
{
    list->first_node = NULL;
    list->last_added_node = NULL;
    list->_memorymaxsize = maxsize;
    list->_memoryused = 0;
    list->_max_freq = 0;
    list->event_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
}

/* Get the first node */
EventNode *OS_GetFirstEvent(EventList *list) {
    EventNode *node;
    w_mutex_lock(&list->event_mutex);
    node = list->first_node;
    w_mutex_unlock(&list->event_mutex);
    return node;
}

/* Add an event to the list -- always to the beginning */
void OS_AddEvent(Eventinfo *lf, EventList *list)
{
    w_mutex_lock(&list->event_mutex);

    if (list->last_added_node) {
        EventNode *new_node;
        new_node = (EventNode *)calloc(1, sizeof(EventNode));

        if (new_node == NULL) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }

        // Always add after the first node, which must be empty
        new_node->next = list->last_added_node;
        new_node->prev = list->first_node;
        list->last_added_node->prev = new_node;
        list->first_node->next = new_node;

        list->last_added_node = new_node;

        list->_memoryused++;

        /* Need to remove the last nodes */
        if (list->_memoryused > list->_memorymaxsize) {
            int i = 0;
            EventNode *oldlast;

            /* Remove at least the last 10 events
             * or the events that will not match anymore
             * (higher than max frequency)
             */
            while (list->last_node != list->last_added_node && ((i < 10) ||
                   ((lf->time.tv_sec - list->last_node->event->time.tv_sec) > list->_max_freq))) {
                oldlast = list->last_node;
                list->last_node = list->last_node->prev;
                list->last_node->next = NULL;

                /* Free event info */
                Free_Eventinfo(oldlast->event);
                free(oldlast);

                list->_memoryused--;
                i++;
            }
        }
    } else {
        // Add the first and second node
        // The first node is always empty
        EventNode *second_node;

        os_calloc(1, sizeof(EventNode), second_node);
        if (!list->first_node) {
            os_calloc(1, sizeof(EventNode), list->first_node);
            list->first_node->prev = NULL;
            list->first_node->event = NULL;
            list->first_node->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
        }
        list->_memoryused++;
        list->first_node->next = second_node;

        second_node->prev = list->first_node;
        second_node->next = NULL;

        list->last_node = second_node;
        list->last_added_node = second_node;
    }

    list->last_added_node->event = lf;
    lf->node = list->last_added_node;
    list->last_added_node->count = 0;
    list->last_added_node->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    w_mutex_unlock(&list->event_mutex);

    return;
}
