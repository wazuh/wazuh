/*
 * Wazuh DB pool handler definition
 * Copyright (C) 2015, Wazuh Inc.
 * February 16, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb_pool.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

STATIC wdb_pool_t wdb_pool;

// Initialize global pool.

__attribute__((no_thread_safety_analysis))
void wdb_pool_init() {
    wdb_pool.nodes = rbtree_init();
    w_mutex_init(&wdb_pool.mutex, NULL)
}

// Find a node in the pool by name.

wdb_t * wdb_pool_get(const char * name) {
    w_mutex_lock(&wdb_pool.mutex);
    wdb_t * node = rbtree_get(wdb_pool.nodes, name);

    if (node == NULL) {
        w_mutex_unlock(&wdb_pool.mutex);
        return NULL;
    }

    node->refcount++;
    w_mutex_unlock(&wdb_pool.mutex);
    w_mutex_lock(&node->mutex);

    return node;
}

// Find a node in the pool by name, or create if it does not exist.

wdb_t * wdb_pool_get_or_create(const char * name) {
    w_mutex_lock(&wdb_pool.mutex);
    wdb_t * node = rbtree_get(wdb_pool.nodes, name);

    if (node == NULL) {
        node = wdb_init(name);
        rbtree_insert(wdb_pool.nodes, name, node);
        wdb_pool.size++;
    }

    node->refcount++;
    w_mutex_unlock(&wdb_pool.mutex);
    w_mutex_lock(&node->mutex);

    return node;
}

wdb_t * wdb_pool_get_or_create_global(const char * name, bool read) {
    w_mutex_lock(&wdb_pool.mutex);
    wdb_t * node = rbtree_get(wdb_pool.nodes, name);

    if (node == NULL) {
        node = wdb_init(name);
        rbtree_insert(wdb_pool.nodes, name, node);
        wdb_pool.size++;
    }

    node->refcount++;
    w_mutex_unlock(&wdb_pool.mutex);
    if (read == TRUE) {
        w_rwlock_rdlock(&node->rwlock);
    } else {
        w_rwlock_wrlock(&node->rwlock);
    }

    return node;
}

// Leave a node.

void wdb_pool_leave(wdb_t * node) {
    if (node) {
        w_mutex_unlock(&node->mutex);
        w_mutex_lock(&wdb_pool.mutex);
        node->refcount--;
        w_mutex_unlock(&wdb_pool.mutex);
        node->last = time(NULL);
    }
}

void wdb_pool_leave_global(wdb_t * node) {
    if (node) {
        w_rwlock_unlock(&node->rwlock);
        w_mutex_lock(&wdb_pool.mutex);
        node->refcount--;
        w_mutex_unlock(&wdb_pool.mutex);
        node->last = time(NULL);
    }
}

// Get all the existing names in the pool.

char ** wdb_pool_keys() {
    w_mutex_lock(&wdb_pool.mutex);
    char ** keys = rbtree_keys(wdb_pool.nodes);
    w_mutex_unlock(&wdb_pool.mutex);

    return keys;
}

// Remove closed databases from the pool.

void wdb_pool_clean() {
    w_mutex_lock(&wdb_pool.mutex);
    char ** keys = rbtree_keys(wdb_pool.nodes);

    for (int i = 0; keys[i]; i++) {
        wdb_t * node = rbtree_get(wdb_pool.nodes, keys[i]);

        if (node == NULL) {
            merror("Null node found when cleaning database files. This is a bug.");
            continue;
        }

        if (node->refcount == 0 && node->db == NULL) {
            wdb_destroy(node);
            rbtree_delete(wdb_pool.nodes, keys[i]);
            wdb_pool.size--;
        }
    }

    free_strarray(keys);
    w_mutex_unlock(&wdb_pool.mutex);
}

// Get the current pool size.

unsigned wdb_pool_size() {
    return wdb_pool.size;
}
