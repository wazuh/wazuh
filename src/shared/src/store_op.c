/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Common API for dealing with ordered lists
 * Provides a fast search on average (n/2)
 */

#include "shared.h"


/* Create the list storage
 * Returns NULL on error
 */
OSStore *OSStore_Create()
{
    OSStore *my_list;

    my_list = (OSStore *) calloc(1, sizeof(OSStore));
    if (!my_list) {
        return (NULL);
    }

    my_list->first_node = NULL;
    my_list->last_node = NULL;
    my_list->cur_node = NULL;
    my_list->currently_size = 0;
    my_list->max_size = 0;
    my_list->free_data_function = NULL;

    w_rwlock_init(&my_list->wr_mutex, NULL);

    return (my_list);
}

/* Delete the list storage
 * Returns NULL on error
 */
OSStore *OSStore_Free(OSStore *list)
{
    OSStoreNode *delnode;
    list->cur_node = list->first_node;

    while (list->cur_node) {
        if (list->cur_node->key) {
            free(list->cur_node->key);
            list->cur_node->key = NULL;
        }
        if (list->cur_node->data) {
            free(list->cur_node->data);
            list->cur_node->data = NULL;
        }

        /* Delete each node */
        delnode = list->cur_node;
        list->cur_node = list->cur_node->next;
        free(delnode);
    }

    list->first_node = NULL;
    list->last_node = NULL;

    w_rwlock_destroy(&list->wr_mutex);

    free(list);
    list = NULL;

    return (list);
}

/* Get key position from storage
 * Returns 0 if not present or the key if available
 * (position may change after each PUT)
 */
int OSStore_GetPosition(OSStore *list, const char *key)
{
    int chk_rc, pos = 1;
    list->cur_node = list->first_node;

    while (list->cur_node) {
        if ((chk_rc = strcmp(list->cur_node->key, key)) >= 0) {
            /* Found */
            if (chk_rc == 0) {
                return (pos);
            }

            /* Not found */
            return (0);
        }

        list->cur_node = list->cur_node->next;
        pos++;
    }
    return (0);
}

/* Get first node from storage
 * Returns NULL if not present
 */
OSStoreNode *OSStore_GetFirstNode(OSStore *list)
{
    return (list->first_node);
}

/* Get data from storage
 * Returns NULL if not present
 */
void *OSStore_Get(OSStore *list, const char *key)
{
    int chk_rc;
    list->cur_node = list->first_node;

    while (list->cur_node) {
        if ((chk_rc = strcmp(list->cur_node->key, key)) >= 0) {
            /* Found */
            if (chk_rc == 0) {
                return (list->cur_node->data);
            }

            /* Not found */
            return (NULL);
        }

        list->cur_node = list->cur_node->next;
    }
    return (NULL);
}

/* Add data to the list
 * Returns 1 on success and 0 on failure
 */
int OSStore_Put(OSStore *list, const char *key, void *data)
{
    int chk_rc;
    OSStoreNode *newnode;

    /* Allocate memory for new node */
    newnode = (OSStoreNode *) calloc(1, sizeof(OSStoreNode));
    if (!newnode) {
        merror(MEM_ERROR, errno, strerror(errno));
        return (0);
    }

    newnode->prev = NULL;
    newnode->next = NULL;
    newnode->data = data;
    newnode->key = strdup(key);
    if (!newnode->key) {
        free(newnode);
        merror(MEM_ERROR, errno, strerror(errno));
        return (0);
    }
    newnode->key_size = strlen(key);

    /* If we don't have first node, assign it */
    if (!list->first_node) {
        list->first_node = newnode;
        list->last_node = newnode;
    }

    /* Store the data in order */
    else {
        list->cur_node = list->first_node;
        while (list->cur_node) {
            if ((chk_rc = strcmp(list->cur_node->key, key)) >= 0) {
                /* Duplicate entry */
                if (chk_rc == 0) {
                    free(newnode->key);
                    free(newnode);
                    return (1);
                }

                /* If there is no prev node, this is the first node */
                if (list->cur_node->prev) {
                    list->cur_node->prev->next = newnode;
                } else {
                    list->first_node = newnode;
                }

                newnode->prev = list->cur_node->prev;

                list->cur_node->prev = newnode;
                newnode->next = list->cur_node;
                break;
            }

            list->cur_node = list->cur_node->next;
        }

        /* New node is the higher key */
        if (!newnode->next) {
            list->last_node->next = newnode;
            newnode->prev = list->last_node;
            list->last_node = newnode;
        }
    }

    /* Increment list size */
    list->currently_size++;

    return (1);
}
