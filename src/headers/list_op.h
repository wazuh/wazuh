/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Common list API */

#ifndef OS_LIST
#define OS_LIST

#include <pthread.h>

#define OSList_foreach(node_it, list)                                                  \
    for (node_it = (list != NULL) ? OSList_GetFirstNode(list) : NULL; node_it != NULL; \
         node_it = OSList_GetNext(list, node_it))

typedef struct _OSListNode {
    struct _OSListNode *next;
    struct _OSListNode *prev;
    void *data;
} OSListNode;

typedef struct _OSList {
    OSListNode *first_node;
    OSListNode *last_node;
    OSListNode *cur_node;

    int currently_size;
    int max_size;
    volatile int count;
    volatile int pending_remove;

    void (*free_data_function)(void *data);
    pthread_rwlock_t wr_mutex;
    pthread_mutex_t mutex;
} OSList;

OSList *OSList_Create(void);

/**
 * @brief Frees all resources associated with a list.
 *
 * @param list List to be destroyed.
*/
void OSList_Destroy(OSList *);

int OSList_SetMaxSize(OSList *list, int max_size);
int OSList_SetFreeDataPointer(OSList *list, void (free_data_function)(void *));

OSListNode *OSList_GetFirstNode(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetLastNode(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetLastNode_group(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetPrevNode(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetNextNode(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetCurrentlyNode(OSList *list) __attribute__((nonnull));

void OSList_DeleteCurrentlyNode(OSList *list) __attribute__((nonnull));
void OSList_DeleteThisNode(OSList *list, OSListNode *thisnode) __attribute__((nonnull(1)));
void OSList_DeleteOldestNode(OSList *list) __attribute__((nonnull));

void *OSList_AddData(OSList *list, void *data) __attribute__((nonnull(1)));

/**
 * @brief Clears all the nodes from a list and frees the referenced data
 *
 * @param list List to delete
 */
void OSList_CleanNodes(OSList *list);

/**
 * @brief Clears all the nodes from a list without freeing the referenced data
 *
 * @param list List to delete nodes
 */
void OSList_CleanOnlyNodes(OSList *list);

/**
 * @brief Get the next node to a given node
 *
 * @param list List where to get the node from
 * @param node Node reference to get next
 */
OSListNode *OSList_GetNext(OSList *list, OSListNode *node);

/**
 * @brief Insert data in the place of a given node
 *
 * @param list List where to get the node from
 * @param node Node reference to insert new node with data
 * @param data Data to be insert
 */
int OSList_InsertData(OSList *list, OSListNode *node, void *data);

/**
 * @brief Get the pointer to data from the node placed in index position
 *
 * @param list List where to get the node from
 * @param index Index that indicate the position of the node required
 */
void *OSList_GetDataFromIndex(OSList *list, int index);

/**
 * @brief Insert data at the beggining of a list
 *
 * @param list List where the node will be inserted into
 * @param data Data to be inserted
 */
int OSList_PushData(OSList *list, void *data);

#endif /* OS_LIST */
