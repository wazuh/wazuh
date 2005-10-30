/*   $OSSEC, list_op.h, v0.1, 2005/10/28, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
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

    void *free_data_function;
}OSList;


OSList *OS_CreateList();
OSListNode *OS_GetFirstNode(OSList *);
OSListNode *OS_GetLastNode(OSList *);
OSListNode *OS_GetNextNode(OSList *);

int OSList_AddData(OSList *list, void *data);

#endif

/* EOF */
