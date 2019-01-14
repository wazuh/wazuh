/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common API for dealing with hash operations */

#ifndef _OS_HASHOP
#define _OS_HASHOP
#include <pthread.h>

/* Node structure */
typedef struct _OSHashNode {
    struct _OSHashNode *next;

    char *key;
    void *data;
} OSHashNode;

typedef struct _OSHash {
    unsigned int rows;
    unsigned int initial_seed;
    unsigned int constant;
    pthread_rwlock_t mutex;
    
    void (*free_data_function)(void *data);
    OSHashNode **table;
} OSHash;

/* Prototypes */

/* Create and initialize hash */
OSHash *OSHash_Create(void);

/* Free the memory used by the hash */
int OSHash_SetFreeDataPointer(OSHash *self, void (free_data_function)(void *)) __attribute__((nonnull));
void *OSHash_Free(OSHash *self) __attribute__((nonnull));

/* Returns 0 on error
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL
 */
int OSHash_Add(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1, 2)));
int OSHash_Numeric_Add_ex(OSHash *hash, int key, void *data) __attribute__((nonnull(1, 3)));
int OSHash_Add_ex(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1, 2)));
int OSHash_Add_ins(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1, 2)));
int OSHash_Update(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1, 2)));
int OSHash_Update_ex(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1, 2)));
int OSHash_Set(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1, 2)));
int OSHash_Set_ex(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1, 2)));
void *OSHash_Delete(OSHash *self, const char *key) __attribute__((nonnull));
void *OSHash_Numeric_Delete_ex(OSHash *self, int key) __attribute__((nonnull(1)));
void *OSHash_Delete_ex(OSHash *self, const char *key) __attribute__((nonnull));
void *OSHash_Delete_ins(OSHash *self, const char *key) __attribute__((nonnull));

/* Returns NULL on error (key not found)
 * Returns the key otherwise
 * Key must not be NULL
 */
void *OSHash_Get(const OSHash *self, const char *key) __attribute__((nonnull));
void *OSHash_Numeric_Get_ex(const OSHash *self, int key) __attribute__((nonnull(1)));
void *OSHash_Get_ex(const OSHash *self, const char *key) __attribute__((nonnull));
void *OSHash_Get_ins(const OSHash *self, const char *key) __attribute__((nonnull));

int OSHash_setSize(OSHash *self, unsigned int new_size) __attribute__((nonnull));
int OSHash_setSize_ex(OSHash *self, unsigned int new_size) __attribute__((nonnull));

OSHash *OSHash_Duplicate(const OSHash *hash) __attribute__((nonnull));
OSHash *OSHash_Duplicate_ex(const OSHash *hash) __attribute__((nonnull));

OSHashNode *OSHash_Begin(const OSHash *self, unsigned int *i);
OSHashNode *OSHash_Next(const OSHash *self, unsigned int *i, OSHashNode *current);
void *OSHash_Clean(OSHash *self, void (*cleaner)(void*));

#endif
