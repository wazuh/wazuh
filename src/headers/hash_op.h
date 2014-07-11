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
OSHash *OSHash_Create();



/** void *OSHash_Free(OSHash *self)
 * Frees the memory used by the hash.
 */
void *OSHash_Free(OSHash *self);



/** void OSHash_Add(OSHash *hash, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int OSHash_Add(OSHash *hash, char *key, void *data);
int OSHash_Update(OSHash *hash, char *key, void *data);
void* OSHash_Delete(OSHash *self, char *key);


/** void *OSHash_Get(OSHash *self, char *key)
 * Returns NULL on error (key not found).
 * Returns the key otherwise.
 * Key must not be NULL.
 */
void *OSHash_Get(OSHash *self, char *key);

int OSHash_setSize(OSHash *self, int new_size);

#endif

/* EOF */
