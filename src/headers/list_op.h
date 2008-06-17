/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* Common list API */


#ifndef _OS_LIST
#define _OS_LIST

typedef struct _OSListNode
{
    struct _OSListNode *next;
    struct _OSListNode *prev;
    void *data;
}OSListNode;


typedef struct _OSList
{
    OSListNode *first_node;
    OSListNode *last_node;
    OSListNode *cur_node;
    
    int currently_size;
    int max_size;

    void (*free_data_function)(void *data);
}OSList;


OSList *OSList_Create();

int OSList_SetMaxSize(OSList *list, int max_size);
int OSList_SetFreeDataPointer(OSList *list, void *free_data_function);

OSListNode *OSList_GetFirstNode(OSList *);
OSListNode *OSList_GetLastNode(OSList *);
OSListNode *OSList_GetPrevNode(OSList *);
OSListNode *OSList_GetNextNode(OSList *);
OSListNode *OSList_GetCurrentlyNode(OSList *list);

void OSList_DeleteCurrentlyNode(OSList *list);
void OSList_DeleteThisNode(OSList *list, OSListNode *thisnode);
void OSList_DeleteOldestNode(OSList *list);

int OSList_AddData(OSList *list, void *data);

#endif

/* EOF */
