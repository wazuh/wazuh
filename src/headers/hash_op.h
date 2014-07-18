/* @(#) $Id: ./src/headers/hash_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */

/* Common API for dealing with directory trees */


#ifndef _OS_HASHOP
#define _OS_HASHOP


/* Node structure */
typedef struct _OSHashNode
{
    struct _OSHashNode *next;

    void *key;
    void *data;
}OSHashNode;


typedef struct _OSHash
{
    unsigned int rows;
    unsigned int initial_seed;
    unsigned int constant;

    OSHashNode **table;
}OSHash;



/** Prototypes **/


/** OSHash *OSHash_Create();
 * Creates and initializes hash.
 */
OSHash *OSHash_Create(void);



/** void *OSHash_Free(OSHash *self)
 * Frees the memory used by the hash.
 */
void *OSHash_Free(OSHash *self) __attribute__((nonnull));



/** void OSHash_Add(OSHash *hash, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int OSHash_Add(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1,2)));
int OSHash_Update(OSHash *hash, const char *key, void *data) __attribute__((nonnull(1,2)));
void* OSHash_Delete(OSHash *self, const char *key) __attribute__((nonnull));


/** void *OSHash_Get(OSHash *self, char *key)
 * Returns NULL on error (key not found).
 * Returns the key otherwise.
 * Key must not be NULL.
 */
void *OSHash_Get(const OSHash *self, const char *key) __attribute__((nonnull));

int OSHash_setSize(OSHash *self, unsigned int new_size) __attribute__((nonnull));

#endif

/* EOF */
