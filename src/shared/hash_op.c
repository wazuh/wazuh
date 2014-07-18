/* @(#) $Id: ./src/shared/hash_op.c, 2011/09/08 dcid Exp $
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


/* Common API for dealing with hashes/maps */


#include "shared.h"

static unsigned int _os_genhash(const OSHash *self, const char *key);

/** OSHash *OSHash_Create()
 * Creates the Hash.
 * Returns NULL on error.
 */
OSHash *OSHash_Create()
{
    unsigned int i = 0;
    OSHash *self;

    /* Allocating memory for the hash */
    self = calloc(1, sizeof(OSHash));
    if(!self)
    {
        return(NULL);
    }


    /* Setting default row size */
    self->rows = os_getprime(1024);
    if(self->rows == 0)
    {
        free(self);
        return(NULL);
    }


    /* Creating hashing table */
    self->table = (OSHashNode **)calloc(self->rows +1, sizeof(OSHashNode *));
    if(!self->table)
    {
        free(self);
        return(NULL);
    }


    /* Zeroing our tables */
    for(i = 0; i <= self->rows; i++)
    {
        self->table[i] = NULL;
    }


    /* Getting seed */
    srandom((unsigned int)time(0));
    self->initial_seed = os_getprime(random() % self->rows);
    self->constant = os_getprime(random() % self->rows);


    return(self);
}



/** void *OSHash_Free(OSHash *self)
 * Frees the memory used by the hash.
 */
void *OSHash_Free(OSHash *self)
{
    unsigned int i = 0;
    OSHashNode *curr_node;
    OSHashNode *next_node;


    /* Freeing each entry */
    while(i <= self->rows)
    {
        curr_node = self->table[i];
        next_node = curr_node;
        while(next_node)
        {
            next_node = next_node->next;
            free(curr_node->key);
            free(curr_node);
            curr_node = next_node;
        }
        i++;
    }


    /* Freeing the hash table */
    free(self->table);

    free(self);
    return(NULL);
}



/** int _os_genhash(OSHash *self, char *key)
 * Generates hash for key
 */
static unsigned int _os_genhash(const OSHash *self, const char *key)
{
    unsigned int hash_key = self->initial_seed;

    /* What we have here is a simple polynomial hash.
     * x0 * a^k-1 .. xk * a^k-k +1
     */
    while(*key)
    {
        hash_key *= self->constant;
        hash_key += (unsigned int) *key;
        key++;
    }

    return(hash_key);
}



/** int OSHash_setSize(OSHash *self, int size)
 * Sets new size for hash.
 * Returns 0 on error (out of memory).
 */
int OSHash_setSize(OSHash *self, unsigned int new_size)
{
    unsigned int i = 0;

    /* We can't decrease the size */
    if(new_size <= self->rows)
    {
        return(1);
    }


    /* Getting next prime */
    self->rows = os_getprime(new_size);
    if(self->rows == 0)
    {
        return(0);
    }


    /* If we fail, the hash should not be used anymore */
    self->table = realloc(self->table, (self->rows +1) * sizeof(OSHashNode *));
    if(!self->table)
    {
        return(0);
    }


    /* Zeroing our tables */
    for(i = 0; i <= self->rows; i++)
    {
        self->table[i] = NULL;
    }


    /* New seed */
    self->initial_seed = os_getprime(random() % self->rows);
    self->constant = os_getprime(random() % self->rows);

    return(1);
}


/** int OSHash_Update(OSHash *self, char *key, void *data)
 * Returns 0 on error (not found).
 * Returns 1 on successduplicated key (not added)
 * Key must not be NULL.
 */
int OSHash_Update(OSHash *self, const char *key, void *data)
{
    unsigned int hash_key;
    unsigned int index;

    OSHashNode *curr_node;


    /* Generating hash of the message */
    hash_key = _os_genhash(self, key);


    /* Getting array index */
    index = hash_key % self->rows;


    /* Checking for duplicated entries in the index */
    curr_node = self->table[index];
    while(curr_node)
    {
        /* Checking for duplicated key -- not adding */
        if(strcmp(curr_node->key, key) == 0)
        {
            curr_node->data = data;
            return(1);
        }
        curr_node = curr_node->next;
    }
    return(0);
}



/** int OSHash_Add(OSHash *self, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int OSHash_Add(OSHash *self, const char *key, void *data)
{
    unsigned int hash_key;
    unsigned int index;

    OSHashNode *curr_node;
    OSHashNode *new_node;


    /* Generating hash of the message */
    hash_key = _os_genhash(self, key);


    /* Getting array index */
    index = hash_key % self->rows;


    /* Checking for duplicated entries in the index */
    curr_node = self->table[index];
    while(curr_node)
    {
        /* Checking for duplicated key -- not adding */
        if(strcmp(curr_node->key, key) == 0)
        {
            /* Not adding */
            return(1);
        }
        curr_node = curr_node->next;
    }


    /* Creating new node */
    new_node = calloc(1, sizeof(OSHashNode));
    if(!new_node)
    {
        return(0);
    }
    new_node->next = NULL;
    new_node->data = data;
    new_node->key = strdup(key);
    if( new_node->key == NULL ) {
        free(new_node);
        debug1("hash_op: DEBUG: strdup() failed!");
        return(0);
    }


    /* Adding to table */
    if(!self->table[index])
    {
        self->table[index] = new_node;
    }
    /* If there is duplicated, add to the beginning */
    else
    {
        new_node->next = self->table[index];
        self->table[index] = new_node;
    }

    return(2);
}



/** void *OSHash_Get(OSHash *self, char *key)
 * Returns NULL on error (key not found).
 * Returns the key otherwise.
 * Key must not be NULL.
 */
void *OSHash_Get(const OSHash *self, const char *key)
{
    unsigned int hash_key;
    unsigned int index;

    const OSHashNode *curr_node;


    /* Generating hash of the message */
    hash_key = _os_genhash(self, key);


    /* Getting array index */
    index = hash_key % self->rows;


    /* Getting entry */
    curr_node = self->table[index];
    while(curr_node != NULL)
    {
        /* Skip null pointers */
        if( curr_node->key == NULL )
            continue;

        /* We may have colisions, so double check with strcmp */
        if(strcmp(curr_node->key, key) == 0)
        {
            return(curr_node->data);
        }

        curr_node = curr_node->next;
    }

    return(NULL);
}

/* Returns a pointer to a hash node if found, that hash node is removed from the table */
void* OSHash_Delete(OSHash *self, const char *key)
{
    OSHashNode *curr_node;
    OSHashNode *prev_node = 0;
    unsigned int hash_key;
    unsigned int index;
    void *data;

    /* Generating hash of the message */
    hash_key = _os_genhash(self, key);

    /* Getting array index */
    index = hash_key % self->rows;

    curr_node = self->table[index];
    while( curr_node != NULL ) {
        if(strcmp(curr_node->key, key) == 0) {
            if( prev_node == NULL ) {
                self->table[index] = curr_node->next;
            }
            else {
                prev_node->next = curr_node->next;
            }
            free(curr_node->key);
            data = curr_node->data;
            free(curr_node);
            return data;
        }
        prev_node = curr_node;
        curr_node = curr_node->next;
    }

    return NULL;
}

/* EOF */
