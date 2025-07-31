/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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
    my_list->count = 0;
    my_list->pending_remove = 0;
    my_list->free_data_function = NULL;
    w_rwlock_init(&my_list->wr_mutex, NULL);
    w_mutex_init(&my_list->mutex, NULL);

    return (my_list);
}

void OSList_Destroy(OSList *list) {
    if (!list) {
        return;
    }

    OSList_CleanNodes(list);

    w_rwlock_destroy(&list->wr_mutex);
    w_mutex_destroy(&list->mutex);
    free(list);

    return;
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
    OSListNode *node;
    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    list->cur_node = list->first_node;
    node = list->first_node;
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
    return node;
}

/* Get last node from list
 * Returns null on invalid list
 */
OSListNode *OSList_GetLastNode(OSList *list)
{
    OSListNode *node;
    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    list->cur_node = list->last_node;
    node = list->last_node;
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
    return node;
}

/* Get last node from list
 * Returns null on invalid list
 */
OSListNode *OSList_GetLastNode_group(OSList *list)
{
    OSListNode *node;
    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    list->cur_node = list->last_node;
    node = list->last_node;
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
    return node;
}

/* Get next node from list
 * Returns null on invalid list or at the end of the list
 */
OSListNode *OSList_GetNextNode(OSList *list)
{
    OSListNode *node;
    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    if (list->cur_node == NULL) {
        w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
        return (NULL);
    }

    list->cur_node = list->cur_node->next;
    node = list->cur_node;
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
    return node;
}

/* Get the prev node from the list
 * Returns NULL at the beginning
 */
OSListNode *OSList_GetPrevNode(OSList *list)
{
    OSListNode *node;
    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    if (list->cur_node == NULL) {
        w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
        return (NULL);
    }

    list->cur_node = list->cur_node->prev;
    node = list->cur_node;
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
    return node;
}

/* Get the currently node
 * Returns null when no currently node is available
 */
OSListNode *OSList_GetCurrentlyNode(OSList *list)
{
    OSListNode *node;
    w_rwlock_rdlock((pthread_rwlock_t *)&list->wr_mutex);
    node = list->cur_node;
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
    return node;
}

/* Delete first node from list */
void OSList_DeleteOldestNode(OSList *list)
{
    OSListNode *next;

    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);
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
        merror("No Oldest node to delete");
    }
    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);

    return;
}

/* Delete this node from list
 * Pointer goes to the next node available
 */
void OSList_DeleteThisNode(OSList *list, OSListNode *thisnode)
{
    OSListNode *prev;
    OSListNode *next;

    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);
    if (thisnode == NULL) {
        w_mutex_unlock((pthread_mutex_t *)&list->mutex);
        w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
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
    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
}

/* Delete current node from list
 * Pointer goes to the next node available
 */
void OSList_DeleteCurrentlyNode(OSList *list)
{
    OSListNode *prev;
    OSListNode *next;

    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);
    if (list->cur_node == NULL) {
        w_mutex_unlock((pthread_mutex_t *)&list->mutex);
        w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
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

    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
}

/* Add data to the list
 * Returns 1 on success and 0 on failure
 */
void *OSList_AddData(OSList *list, void *data)
{
    OSListNode *newnode;
    OSListNode *ret;

    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);

    /* Allocate memory for new node */
    newnode = (OSListNode *) calloc(1, sizeof(OSListNode));
    if (!newnode) {
        merror(MEM_ERROR, errno, strerror(errno));
        w_mutex_unlock((pthread_mutex_t *)&list->mutex);
        w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
        return NULL;
    }

    newnode->prev = list->last_node;
    newnode->next = NULL;
    newnode->data = data;

    /* If we don't have a first node, assign it */
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
    ret = list->last_node;
    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);

    return ret;
}

void OSList_CleanNodes(OSList *list) {
    if (list == NULL) {
        return;
    }

    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);

    OSListNode *aux_node = NULL;

    while(list->first_node != NULL) {
        aux_node = list->first_node;
        list->first_node = aux_node->next;
        if (list->free_data_function != NULL) {
            list->free_data_function(aux_node->data);
        }
        free(aux_node);
    }

    list->last_node = NULL;
    list->cur_node = NULL;
    list->first_node = NULL;

    list->currently_size = 0;

    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
}

void OSList_CleanOnlyNodes(OSList *list) {
    if (list == NULL) {
        return;
    }

    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);

    OSListNode *aux_node = NULL;

    while(list->first_node != NULL) {
        aux_node = list->first_node;
        list->first_node = aux_node->next;
        os_free(aux_node);
    }

    list->last_node = NULL;
    list->cur_node = NULL;
    list->first_node = NULL;

    list->currently_size = 0;

    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
}

OSListNode *OSList_GetNext(OSList *list, OSListNode *node) {
    OSListNode *next;

    w_rwlock_rdlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);
    if (node == NULL) {
        w_mutex_unlock((pthread_mutex_t *)&list->mutex);
        w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
        return (NULL);
    }

    next = node->next;

    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);

    return (next);
}

void *OSList_GetDataFromIndex(OSList *list, int index) {
    int count = 0;
    OSListNode *current;

    w_rwlock_rdlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);

    current = list->first_node;

    while (current != NULL) {
        if (count == index) {
            w_mutex_unlock((pthread_mutex_t *)&list->mutex);
            w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);
            return (current->data);
        }
        count++;
        current = current->next;
    }

    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);

    return NULL;
}

/* Add data to the list
 * Returns 0 on success and 1 on failure
 */
static int _OSList_InsertData(OSList *list, OSListNode *node, void *data) {
    OSListNode *newnode;

    /* Allocate memory for new node */
    newnode = (OSListNode *) calloc(1, sizeof(OSListNode));
    if (newnode == NULL) {
        // LCOV_EXCL_START
        merror(MEM_ERROR, errno, strerror(errno));
        return 1;
        // LCOV_EXCL_STOP
    }

    newnode->data = data;

    /* If we don't have a first node, assign it */
    if (!list->first_node) {
        list->first_node = newnode;
        list->last_node = newnode;
        newnode->prev = NULL;
        newnode->next = NULL;
    } else if (node == NULL) {
        newnode->prev = list->last_node;
        newnode->prev->next = newnode;
        newnode->next = NULL;
        list->last_node = newnode;
    } else {
        if (node->prev == NULL) {
            newnode->prev = NULL;
            list->first_node = newnode;
        } else {
            node->prev->next = newnode;
            newnode->prev = node->prev;
        }
        newnode->next = node;
        node->prev = newnode;
    }

    /* Increment list size */
    list->currently_size++;

    return 0;
}

int OSList_InsertData(OSList *list, OSListNode *node, void *data) {
    int retval;

    assert(list != NULL);

    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);

    retval = _OSList_InsertData(list, node, data);

    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);

    return retval;
}

/**
 * Add data to the begging of the list
 */
int OSList_PushData(OSList *list, void *data) {
    int retval;

    assert(list != NULL);

    w_rwlock_wrlock((pthread_rwlock_t *)&list->wr_mutex);
    w_mutex_lock((pthread_mutex_t *)&list->mutex);

    retval = _OSList_InsertData(list, list->first_node, data);

    w_mutex_unlock((pthread_mutex_t *)&list->mutex);
    w_rwlock_unlock((pthread_rwlock_t *)&list->wr_mutex);

    return retval;
}
