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

static wdb_pool_t wdb_pool;

// Initialize global pool.

void wdb_pool_init() {
    wdb_pool.nodes = rbtree_init();
    w_mutex_init(&wdb_pool.mutex, NULL)
}

// Find a node in the pool by name.

wdb_t * wdb_pool_get(const char * name) {
   w_mutex_lock(&wdb_pool.mutex);
    wdb_t * node = rbtree_get(wdb_pool.nodes, name);

    if (node != NULL) {
        node->refcount++;
    }

    w_mutex_unlock(&wdb_pool.mutex);
    w_mutex_lock(&node->mutex);

    return node;
}

// Find a node in the pool by name, or create if it does not exist.

wdb_t * wdb_pool_get_or_create(const char * name) {
    w_mutex_lock(&wdb_pool.mutex);
    wdb_t * node = rbtree_get(wdb_pool.nodes, name);

    if (node == NULL) {
        node =  wdb_init(NULL, name);
    }

    node->refcount++;
    w_mutex_unlock(&wdb_pool.mutex);
    w_mutex_lock(&node->mutex);

    return node;
}

// Leave a node.

void wdb_pool_leave(wdb_t * node) {
    w_mutex_unlock(&node->mutex);

    if (node) {
        w_mutex_lock(&wdb_pool.mutex);
        node->refcount--;
        node->last = time(NULL);
        w_mutex_unlock(&wdb_pool.mutex);
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

        if (node->refcount == 0) {
            wdb_destroy(node);
        }
    }

    free_strarray(keys);
    w_mutex_unlock(&wdb_pool.mutex);
}
