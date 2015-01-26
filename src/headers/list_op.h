/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Common list API */

#ifndef _OS_LIST
#define _OS_LIST

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

    void (*free_data_function)(void *data);
} OSList;

OSList *OSList_Create(void);

int OSList_SetMaxSize(OSList *list, int max_size);
int OSList_SetFreeDataPointer(OSList *list, void (free_data_function)(void *));

OSListNode *OSList_GetFirstNode(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetLastNode(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetPrevNode(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetNextNode(OSList *) __attribute__((nonnull));
OSListNode *OSList_GetCurrentlyNode(OSList *list) __attribute__((nonnull));

void OSList_DeleteCurrentlyNode(OSList *list) __attribute__((nonnull));
void OSList_DeleteThisNode(OSList *list, OSListNode *thisnode) __attribute__((nonnull(1)));
void OSList_DeleteOldestNode(OSList *list) __attribute__((nonnull));

int OSList_AddData(OSList *list, void *data) __attribute__((nonnull(1)));

#endif

