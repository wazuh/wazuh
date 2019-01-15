/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common API for dealing with hashes/maps */

#include "shared.h"

static unsigned int _os_genhash(const OSHash *self, const char *key) __attribute__((nonnull));

int _OSHash_Add(OSHash *self, const char *key, void *data, int update);

/* Create hash
 * Returns NULL on error
 */
OSHash *OSHash_Create()
{
    unsigned int i = 0;
    OSHash *self;

    /* Allocate memory for the hash */
    self = (OSHash *) calloc(1, sizeof(OSHash));
    if (!self) {
        return (NULL);
    }

    /* Set default row size */
    self->rows = os_getprime(1024);
    if (self->rows == 0) {
        free(self);
        return (NULL);
    }

    /* Create hashing table */
    self->table = (OSHashNode **)calloc(self->rows + 1, sizeof(OSHashNode *));
    if (!self->table) {
        free(self);
        return (NULL);
    }

    /* Zero our tables */
    for (i = 0; i <= self->rows; i++) {
        self->table[i] = NULL;
    }

    /* Get seed */
    srandom((unsigned int)time(0));
    self->initial_seed = os_getprime((unsigned)os_random() % self->rows);
    self->constant = os_getprime((unsigned)os_random() % self->rows);
    pthread_rwlock_init(&self->mutex, NULL);
    return (self);
}

/* Set the pointer to the function to free the memory data */
int OSHash_SetFreeDataPointer(OSHash *self, void (free_data_function)(void *))
{
    self->free_data_function = free_data_function;
    return (1);
}

/* Free the memory used by the hash */
void *OSHash_Free(OSHash *self)
{
    unsigned int i = 0;
    OSHashNode *curr_node;
    OSHashNode *next_node;

    /* Free each entry */
    while (i <= self->rows) {
        curr_node = self->table[i];
        next_node = curr_node;
        while (next_node) {
            next_node = next_node->next;
            if (curr_node->key) free(curr_node->key);
            /* Take care of the data as well (if a function has been defined) */
            if (curr_node->data && self->free_data_function) self->free_data_function(curr_node->data);
            free(curr_node);
            curr_node = next_node;
        }
        i++;
    }

    /* Free the hash table */
    free(self->table);
    pthread_rwlock_destroy(&self->mutex);
    free(self);
    return (NULL);
}

/* Generates hash for key */
static unsigned int _os_genhash(const OSHash *self, const char *key)
{
    unsigned int hash_key = self->initial_seed;

    /* What we have here is a simple polynomial hash.
     * x0 * a^k-1 .. xk * a^k-k +1
     */
    while (*key) {
        hash_key *= self->constant;
        hash_key += (unsigned int) * key;
        key++;
    }

    return (hash_key);
}

/* Set new size for hash
 * Returns 0 on error (out of memory)
 */
int OSHash_setSize(OSHash *self, unsigned int new_size)
{
    unsigned int i = 0, orig_size = self->rows;
    OSHashNode **tmpTable = NULL;
    
    /* We can't decrease the size */
    if (new_size <= self->rows) {
        return (1);
    }

    /* Get next prime */
    self->rows = os_getprime(new_size);
    if (self->rows == 0) {
        return (0);
    }

    /* Resize hash table */
    /* If a call to realloc() fails, the pointer passed to it will remain unchanged */
    tmpTable = (OSHashNode **) realloc(self->table, (self->rows + 1) * sizeof(OSHashNode *));
    if (!tmpTable) return (0);
    
    /* If a call to realloc() succeeds, the pointer passed to it would have been freed */
    self->table = tmpTable;
    
    /* Check if previous tables had allocated data */
    OSHashNode *curr_node, *next_node;
    for(i = 0; i < orig_size; i++) {
        curr_node = self->table[i];
        next_node = curr_node;
        while(next_node) {
            next_node = next_node->next;
            if (curr_node->key) free(curr_node->key);
            /* Take care of the data as well (if a function has been defined) */
            if (curr_node->data && self->free_data_function) self->free_data_function(curr_node->data);
            free(curr_node);
            curr_node = next_node;
        }
    }

    /* Zero our tables */
    for (i = 0; i <= self->rows; i++) {
        self->table[i] = NULL;
    }

    /* New seed */
    self->initial_seed = os_getprime((unsigned)os_random() % self->rows);
    self->constant = os_getprime((unsigned)os_random() % self->rows);

    return (1);
}

int OSHash_setSize_ex(OSHash *self, unsigned int new_size)
{
    int result;
    w_rwlock_wrlock((pthread_rwlock_t *)&self->mutex);
    result = OSHash_setSize(self,new_size);
    w_rwlock_unlock((pthread_rwlock_t *)&self->mutex);
    return result;
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

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Check for duplicated entries in the index */
    curr_node = self->table[index];
    while (curr_node) {
        /* Checking for duplicated key -- not adding */
        if (strcmp(curr_node->key, key) == 0) {
            if (curr_node->data && self->free_data_function) self->free_data_function(curr_node->data);
            curr_node->data = data;
            return (1);
        }
        curr_node = curr_node->next;
    }
    return (0);
}

/** int OSHash_Update(OSHash *self, char *key, void *data)
 * Returns 0 on error (not found).
 * Returns 1 on successduplicated key (not added)
 * Key must not be NULL.
 */
int OSHash_Update_ex(OSHash *self, const char *key, void *data)
{
    int result;

    w_rwlock_wrlock((pthread_rwlock_t *)&self->mutex);
    result = OSHash_Update(self,key,data);
    w_rwlock_unlock((pthread_rwlock_t *)&self->mutex);

    return result;
}

/** int OSHash_Add(OSHash *self, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int OSHash_Add(OSHash *self, const char *key, void *data) {
    return _OSHash_Add(self, key, data, 0);
}

/** int OSHash_Set(OSHash *self, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (updated)
 * Returns 2 on success (added)
 * Key must not be NULL.
 */
int OSHash_Set(OSHash *self, const char *key, void *data) {
    return _OSHash_Add(self, key, data, 1);
}

int _OSHash_Add(OSHash *self, const char *key, void *data, int update)
{
    unsigned int hash_key;
    unsigned int index;
    OSHashNode *curr_node;
    OSHashNode *new_node;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Check for duplicated entries in the index */
    curr_node = self->table[index];
    while (curr_node) {
        /* Checking for duplicated key */
        if (strcmp(curr_node->key, key) == 0) {
            if (update) {
                 curr_node->data = data;
            }
            return (1);
        }
        curr_node = curr_node->next;
    }

    /* Create new node */
    new_node = (OSHashNode *) calloc(1, sizeof(OSHashNode));
    if (!new_node) {
        mdebug1("hash_op: calloc() failed!");
        return (0);
    }
    new_node->next = NULL;
    new_node->data = data;
    new_node->key = strdup(key);
    if ( new_node->key == NULL ) {
        free(new_node);
        mdebug1("hash_op: strdup() failed!");
        return (0);
    }

    /* Add to table */
    if (!self->table[index]) {
        self->table[index] = new_node;
    }
    /* If there is duplicated, add to the beginning */
    else {
        new_node->next = self->table[index];
        self->table[index] = new_node;
    }

    return (2);
}


/** int OSHash_Numeric_Add_ex(OSHash *self, int key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int OSHash_Numeric_Add_ex(OSHash *self, int key, void *data)
{
    char string_key[12];
    int result;

    snprintf(string_key, 12, "%d", key);
    result = OSHash_Add_ex(self, string_key, data);

    return result;
}

/** int OSHash_Add_ex(OSHash *self, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int OSHash_Add_ex(OSHash *self, const char *key, void *data)
{
    int result;
    w_rwlock_wrlock((pthread_rwlock_t *)&self->mutex);
    result = OSHash_Add(self,key,data);
    w_rwlock_unlock((pthread_rwlock_t *)&self->mutex);

    return result;
}

/** int OSHash_Set_ex(OSHash *self, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (updated)
 * Returns 2 on success (added)
 * Key must not be NULL.
 */
int OSHash_Set_ex(OSHash *self, const char *key, void *data)
{
    int result;
    w_rwlock_wrlock((pthread_rwlock_t *)&self->mutex);
    result = OSHash_Set(self,key,data);
    w_rwlock_unlock((pthread_rwlock_t *)&self->mutex);

    return result;
}

/** int OSHash_Add_ins(OSHash *self, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int OSHash_Add_ins(OSHash *self, const char *key, void *data)
{
    int result;
    char *key_cpy = strdup(key);
    str_lowercase(key_cpy);
    result = OSHash_Add_ex(self,key_cpy,data);
    free(key_cpy);
    return result;
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

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Get entry */
    curr_node = self->table[index];
    while (curr_node != NULL) {
        /* Skip null pointers */
        if ( curr_node->key == NULL ) {
            continue;
        }

        /* We may have collisions, so double check with strcmp */
        if (strcmp(curr_node->key, key) == 0) {
            return (curr_node->data);
        }

        curr_node = curr_node->next;
    }

    return (NULL);
}

/** void *OSHash_Numeric_Get_ex(OSHash *self, int key)
 * Returns NULL on error (key not found).
 * Returns the key otherwise.
 * Key must not be NULL.
 */
void *OSHash_Numeric_Get_ex(const OSHash *self, int key)
{
    char string_key[12];
    void *result;

    snprintf(string_key, 12, "%d", key);
    result = OSHash_Get_ex(self, string_key);

    return result;
}

/** void *OSHash_Get_ex(OSHash *self, char *key)
 * Returns NULL on error (key not found).
 * Returns the key otherwise.
 * Key must not be NULL.
 */
void *OSHash_Get_ex(const OSHash *self, const char *key)
{
    void *result;
    w_rwlock_rdlock((pthread_rwlock_t *)&self->mutex);
    result = OSHash_Get(self,key);
    w_rwlock_unlock((pthread_rwlock_t *)&self->mutex);

    return result;
}

/** void *OSHash_Get_ins(OSHash *self, char *key)
 * Returns NULL on error (key not found).
 * Returns the key otherwise.
 * Key must not be NULL.
 */
void *OSHash_Get_ins(const OSHash *self, const char *key)
{
    void *result;
    char *key_cpy = strdup(key);
    str_lowercase(key_cpy);
    result = OSHash_Get_ex(self,key_cpy);
    free(key_cpy);
    return result;
}

/* Return a pointer to a hash node if found, that hash node is removed from the table */
void *OSHash_Delete(OSHash *self, const char *key)
{
    OSHashNode *curr_node;
    OSHashNode *prev_node = 0;
    unsigned int hash_key;
    unsigned int index;
    void *data;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    curr_node = self->table[index];
    while ( curr_node != NULL ) {
        if (strcmp(curr_node->key, key) == 0) {
            if ( prev_node == NULL ) {
                self->table[index] = curr_node->next;
            } else {
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

void *OSHash_Numeric_Delete_ex(OSHash *self, int key)
{
    char string_key[12];
    void *result;

    snprintf(string_key, 12, "%d", key);
    result = OSHash_Delete_ex(self, string_key);

    return result;
}

/* Return a pointer to a hash node if found, that hash node is removed from the table */
void *OSHash_Delete_ex(OSHash *self, const char *key)
{
    void *result;
    w_rwlock_wrlock((pthread_rwlock_t *)&self->mutex);
    result = OSHash_Delete(self,key);
    w_rwlock_unlock((pthread_rwlock_t *)&self->mutex);

    return result;
}

void *OSHash_Delete_ins(OSHash *self, const char *key)
{
    void *result;
    char *key_cpy = strdup(key);
    str_lowercase(key_cpy);
    result = OSHash_Delete_ex(self,key_cpy);
    free(key_cpy);
    return result;
}

OSHash *OSHash_Duplicate(const OSHash *hash) {
    OSHash *self;
    unsigned int i;
    OSHashNode *curr_node;
    OSHashNode **next_addr;

    os_calloc(1, sizeof(OSHash), self);
    self->rows = hash->rows;
    self->initial_seed = hash->initial_seed;
    self->constant = hash->constant;
    self->free_data_function = hash->free_data_function;
    
    os_calloc(self->rows + 1, sizeof(OSHashNode*), self->table);
    pthread_rwlock_init(&self->mutex, NULL);

    for (i = 0; i <= self->rows; i++) {
        next_addr = &self->table[i];

        for (curr_node = hash->table[i]; curr_node; curr_node = curr_node->next) {
            os_calloc(1, sizeof(OSHashNode), *next_addr);
            (*next_addr)->key = strdup(curr_node->key);
            (*next_addr)->data = curr_node->data;
            next_addr = &(*next_addr)->next;
        }
    }

    return self;
}

OSHash *OSHash_Duplicate_ex(const OSHash *hash) {

    OSHash *result;

    w_rwlock_rdlock((pthread_rwlock_t *)&hash->mutex);
    result = OSHash_Duplicate(hash);
    w_rwlock_unlock((pthread_rwlock_t *)&hash->mutex);

    return result;
}


OSHashNode *OSHash_Begin(const OSHash *self, unsigned int *i){

    OSHashNode *curr_node;
    *i = 0;

    while (*i <= self->rows) {
        curr_node = self->table[*i];
        if (curr_node && curr_node->key) {
            return curr_node;
        }
        (*i)++;
    }

    return NULL;
}

OSHashNode *OSHash_Next(const OSHash *self, unsigned int *i, OSHashNode *current){

    if(current && current->next){
        return current->next;
    }

    (*i)++;

    while (*i <= self->rows) {
        current = self->table[*i];
        if (current && current->key) {
            return current;
        }
        (*i)++;
    }

    return NULL;
}

void *OSHash_Clean(OSHash *self, void (*cleaner)(void*)){
    unsigned int *i;
    os_calloc(1, sizeof(unsigned int), i);
    OSHashNode *curr_node;
    OSHashNode *next_node;

    curr_node = OSHash_Begin(self, i);
    if(curr_node){
        do {
            next_node = OSHash_Next(self, i, curr_node);
            if(curr_node->key){
                free(curr_node->key);
            }
            if(curr_node->data){
                cleaner(curr_node->data);
            }
            free(curr_node);
            curr_node = next_node;
        } while (curr_node);
    }

    os_free(i);

    /* Free the hash table */
    free(self->table);
    pthread_rwlock_destroy(&self->mutex);
    free(self);
    return NULL;
}
