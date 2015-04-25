/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Common API for dealing with lists */

#include "shared.h"


/* Create the list
 * Returns NULL on error
 */
OSList *OSList_Create()
{
    OSList *my_list;

    my_list = (OSList *) calloc(1, sizeof(OSList));
    if (!my_list) {
        return (NULL);
    }

    my_list->first_node = NULL;
    my_list->last_node = NULL;
    my_list->cur_node = NULL;
    my_list->currently_size = 0;
    my_list->max_size = 0;
    my_list->free_data_function = NULL;

    return (my_list);
}

/* Set the maximum number of elements in the list
 * Returns 0 on error or 1 on success
 */
int OSList_SetMaxSize(OSList *list, int max_size)
{
    if (!list) {
        return (0);
    }

    /* Minimum size is 1 */
    if (max_size <= 1) {
        return (0);
    }

    list->max_size = max_size;

    return (1);
}

/* Set the pointer to the function to free the memory data */
int OSList_SetFreeDataPointer(OSList *list, void (free_data_function)(void *))
{
    if (!list) {
        return (0);
    }

    list->free_data_function = free_data_function;
    return (1);
}

/* Get first node from list
 * Returns null on invalid list
 */
OSListNode *OSList_GetFirstNode(OSList *list)
{
    list->cur_node = list->first_node;
    return (list->first_node);
}

/* Get last node from list
 * Returns null on invalid list
 */
OSListNode *OSList_GetLastNode(OSList *list)
{
    list->cur_node = list->last_node;
    return (list->last_node);
}

/* Get next node from list
 * Returns null on invalid list or at the end of the list
 */
OSListNode *OSList_GetNextNode(OSList *list)
{
    if (list->cur_node == NULL) {
        return (NULL);
    }

    list->cur_node = list->cur_node->next;

    return (list->cur_node);
}

/* Get the prev node from the list
 * Returns NULL at the beginning
 */
OSListNode *OSList_GetPrevNode(OSList *list)
{
    if (list->cur_node == NULL) {
        return (NULL);
    }

    list->cur_node = list->cur_node->prev;

    return (list->cur_node);
}

/* Get the currently node
 * Returns null when no currently node is available
 */
OSListNode *OSList_GetCurrentlyNode(OSList *list)
{
    return (list->cur_node);
}

/* Delete first node from list */
void OSList_DeleteOldestNode(OSList *list)
{
    OSListNode *next;

    if (list->first_node) {
        next = list->first_node->next;
        if (next) {
            next->prev = NULL;
        } else {
            list->last_node = next;
        }

        free(list->first_node);
        list->first_node = next;
    } else {
        merror("%s: No Oldest node to delete", __local_name);
    }

    return;
}

/* Delete this node from list
 * Pointer goes to the next node available
 */
void OSList_DeleteThisNode(OSList *list, OSListNode *thisnode)
{
    OSListNode *prev;
    OSListNode *next;

    if (thisnode == NULL) {
        return;
    }

    prev = thisnode->prev;
    next = thisnode->next;

    /* Setting the previous node of the next one
     * and the next node of the previous one.. :)
     */
    if (prev && next) {
        prev->next = next;
        next->prev = prev;
    } else if (prev) {
        prev->next = NULL;
        list->last_node = prev;
    } else if (next) {
        next->prev = NULL;
        list->first_node = next;
    } else {
        list->last_node = NULL;
        list->first_node = NULL;
    }

    /* Free the node memory */
    free(thisnode);

    /* Set the currently node to the next one */
    list->cur_node = next;

    list->currently_size--;
}

/* Delete current node from list
 * Pointer goes to the next node available
 */
void OSList_DeleteCurrentlyNode(OSList *list)
{
    OSListNode *prev;
    OSListNode *next;

    if (list->cur_node == NULL) {
        return;
    }

    prev = list->cur_node->prev;
    next = list->cur_node->next;

    /* Setting the previous node of the next one
     * and the next node of the previous one.. :)
     */
    if (prev && next) {
        prev->next = next;
        next->prev = prev;
    } else if (prev) {
        prev->next = NULL;
        list->last_node = prev;
    } else if (next) {
        next->prev = NULL;
        list->first_node = next;
    } else {
        list->last_node = NULL;
        list->first_node = NULL;
    }

    /* Free the node memory */
    free(list->cur_node);

    /* Set the current node to the next one */
    list->cur_node = next;

    list->currently_size--;
}

/* Add data to the list
 * Returns 1 on success and 0 on failure
 */
int OSList_AddData(OSList *list, void *data)
{
    OSListNode *newnode;

    /* Allocate memory for new node */
    newnode = (OSListNode *) calloc(1, sizeof(OSListNode));
    if (!newnode) {
        merror(MEM_ERROR, __local_name, errno, strerror(errno));
        return (0);
    }

    newnode->prev = list->last_node;
    newnode->next = NULL;
    newnode->data = data;

    /* If we don't havea first node, assign it */
    if (!list->first_node) {
        list->first_node = newnode;
    }

    /* If we have a last node, set the next to new node */
    if (list->last_node) {
        list->last_node->next = newnode;
    }

    /* newnode becomes last node */
    list->last_node = newnode;

    /* Increment list size */
    list->currently_size++;

    /* Ff currently_size higher than the maximum size, remove the
     * oldest node (first one)
     */
    if (list->max_size) {
        if (list->currently_size > list->max_size && list->first_node->next) {
            /* Remove first node */
            newnode = list->first_node->next;

            newnode->prev = NULL;

            /* Clear any internal memory using the pointer */
            if (list->free_data_function) {
                list->free_data_function(list->first_node->data);
            }

            /* Clear the memory */
            free(list->first_node);

            /* First node become the ex first->next */
            list->first_node = newnode;

            /* Reduce list size */
            list->currently_size--;
        }
    }

    return (1);
}

