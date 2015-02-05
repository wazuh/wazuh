/* Copyright (C) 2009 Trend Micro Inc.
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
typedef struct _OSStoreNode {
    struct _OSStoreNode *next;
    struct _OSStoreNode *prev;
    void *data;
    char *key;
    size_t key_size;
} OSStoreNode;

/* Store list */
typedef struct _OSStore {
    OSStoreNode *first_node;
    OSStoreNode *last_node;
    OSStoreNode *cur_node;

    int currently_size;
    int max_size;

    void (*free_data_function)(void *data);
} OSStore;

OSStore *OSStore_Create(void);
OSStore *OSStore_Free(OSStore *list) __attribute__((nonnull));

int OSStore_Put(OSStore *list, const char *key, void *data) __attribute__((nonnull(1, 2)));
int OSStore_Check(OSStore *list, const char *key) __attribute__((nonnull));
int OSStore_NCheck(OSStore *list, const char *key) __attribute__((nonnull));
int OSStore_NCaseCheck(OSStore *list, const char *key) __attribute__((nonnull));
int OSStore_GetPosition(OSStore *list, const char *key) __attribute__((nonnull));
void *OSStore_Get(OSStore *list, const char *key) __attribute__((nonnull));
OSStoreNode *OSStore_GetFirstNode(OSStore *list) __attribute__((nonnull));
int OSStore_Sort(OSStore *list, void *(sort_data_function)(void *d1, void *d2)) __attribute__((nonnull));

int OSStore_SetMaxSize(OSStore *list, int max_size);
int OSStore_SetFreeDataPointer(OSStore *list, void (free_data_function)(void *));

#endif

