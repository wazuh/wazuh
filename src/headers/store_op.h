/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Common list API */


#ifndef _OS_STORE
#define _OS_STORE

/* Store node */
typedef struct _OSStoreNode
{
    struct _OSStoreNode *next;
    struct _OSStoreNode *prev;
    void *data;
    char *key;
    int key_size;
}OSStoreNode;

/* Store list */
typedef struct _OSStore
{
    OSStoreNode *first_node;
    OSStoreNode *last_node;
    OSStoreNode *cur_node;

    int currently_size;
    int max_size;

    void (*free_data_function)(void *data);
}OSStore;


OSStore *OSStore_Create();
int OSStore_Put(OSStore *list, char *key, void *data);
int OSStore_Check(OSStore *list, char *key);
int OSStore_NCheck(OSStore *list, char *key);
int OSStore_NCaseCheck(OSStore *list, char *key);
int OSStore_GetPosition(OSStore *list, char *key);
   


#endif

/* EOF */
