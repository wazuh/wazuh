/**
 * @file indexed_queue_op.h
 * @brief Indexed Queue (abstract data type)
 * @date 2025-08-08
 *
 * @copyright Copyright (C) 2015 Wazuh, Inc.
 */

/*
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * Library that creates a queue where items are pushed and popped following
 * the FIFO (First In, First Out) principle, while also providing O(log n)
 * access by key through a red-black tree index.
 *
 * Features:
 * - FIFO queue operations (push, pop, peek)
 * - O(log n) key-based operations (get, update, delete)
 * - Optional size limitation
 * - Thread-safe with mutex and condition variables
 * - Upsert operation (insert or update)
 */

#ifndef INDEXED_QUEUE_OP_H
#define INDEXED_QUEUE_OP_H

#include <stdatomic.h>
#include <pthread.h>
#include "queue_linked_op.h"
#include "rbtree_op.h"

/**
 * @brief Indexed queue node entry
 *
 * Links a queue node with its key for indexing
 */
typedef struct w_indexed_queue_entry {
    char *key;                           ///< Node key for indexing
    void *data;                         ///< Pointer to the actual data
    w_linked_queue_node_t *queue_node;  ///< Reference to the queue node
} w_indexed_queue_entry_t;

/**
 * @brief Indexed queue main structure
 *
 * Combines a FIFO queue with a red-black tree index for fast key-based access
 */
typedef struct w_indexed_queue {
    w_linked_queue_t *queue;            ///< Underlying FIFO queue
    rb_tree *index;                     ///< Red-black tree for key-based access
    pthread_mutex_t mutex;              ///< Mutex for mutual exclusion
    pthread_cond_t available;           ///< Condition variable when queue is empty
    pthread_cond_t available_not_full;  ///< Condition variable when queue is full
    size_t max_size;                    ///< Maximum size (0 = unlimited)
    _Atomic size_t current_size;        ///< Current number of elements
    void (*dispose)(void *);            ///< Function to dispose data elements
    char *(*get_key)(void *);           ///< Function to get key from data element
} w_indexed_queue_t;

/**
 * @brief Initialize a new indexed queue structure
 *
 * @param max_size Maximum size of the queue (0 for unlimited)
 * @return Initialized queue structure or NULL on error
 */
w_indexed_queue_t *indexed_queue_init(size_t max_size);

/**
 * @brief Free an indexed queue and all its elements
 *
 * @param queue The indexed queue to free
 */
void indexed_queue_free(w_indexed_queue_t *queue);

/**
 * @brief Set function to dispose data elements
 *
 * @param queue The indexed queue
 * @param dispose Function to call when disposing elements
 */
void indexed_queue_set_dispose(w_indexed_queue_t *queue, void (*dispose)(void *));

/**
 * @brief Set function to get key from data element
 *
 * @param queue The indexed queue
 * @param get_key Function to call to get key from data element
 */
void indexed_queue_set_get_key(w_indexed_queue_t *queue, char *(*get_key)(void *));

/**
 * @brief Check if the queue is empty
 *
 * @param queue The indexed queue
 * @return 1 if empty, 0 otherwise
 */
int indexed_queue_empty(const w_indexed_queue_t *queue);

/**
 * @brief Check if the queue is full
 *
 * @param queue The indexed queue
 * @return 1 if full, 0 otherwise
 */
int indexed_queue_full(const w_indexed_queue_t *queue);

/**
 * @brief Get current size of the queue
 *
 * @param queue The indexed queue
 * @return Current number of elements
 */
size_t indexed_queue_size(const w_indexed_queue_t *queue);

/**
 * @brief Insert element at the end of the queue (FIFO push)
 *
 * @param queue The indexed queue
 * @param key Unique key for the element
 * @param data Data to insert
 * @return 0 on success, -1 on error (key exists or queue full)
 */
int indexed_queue_push(w_indexed_queue_t *queue, const char *key, void *data);

/**
 * @brief Thread-safe insert with blocking when full
 *
 * @param queue The indexed queue
 * @param key Unique key for the element
 * @param data Data to insert
 * @return 0 on success, -1 on error (key exists)
 */
int indexed_queue_push_ex(w_indexed_queue_t *queue, const char *key, void *data);

/**
 * @brief Insert or update element (upsert operation)
 *
 * If key exists, updates the value. If not, inserts as new element.
 *
 * @param queue The indexed queue
 * @param key Key for the element
 * @param data Data to insert or update
 * @return 0 on success, -1 on error
 */
int indexed_queue_upsert(w_indexed_queue_t *queue, const char *key, void *data);

/**
 * @brief Thread-safe upsert operation
 *
 * @param queue The indexed queue
 * @param key Key for the element
 * @param data Data to insert or update
 * @return 1 if updated, 0 if inserted, -1 on error
 */
int indexed_queue_upsert_ex(w_indexed_queue_t *queue, const char *key, void *data);

/**
 * @brief Get element by key (without removing)
 *
 * @param queue The indexed queue
 * @param key Key to search for
 * @return Pointer to data if found, NULL otherwise
 */
void *indexed_queue_get(const w_indexed_queue_t *queue, const char *key);

/**
 * @brief Thread-safe get element by key
 *
 * @param queue The indexed queue
 * @param key Key to search for
 * @return Pointer to data if found, NULL otherwise
 */
void *indexed_queue_get_ex(w_indexed_queue_t *queue, const char *key);

/**
 * @brief Peek at the next element (FIFO head) without removing
 *
 * @param queue The indexed queue
 * @return Pointer to data of next element, NULL if empty
 */
void *indexed_queue_peek(const w_indexed_queue_t *queue);

/**
 * @brief Thread-safe peek operation
 *
 * @param queue The indexed queue
 * @return Pointer to data of next element, NULL if empty
 */
void *indexed_queue_peek_ex(w_indexed_queue_t *queue);

/**
 * @brief Remove and return next element (FIFO pop)
 *
 * @param queue The indexed queue
 * @return Pointer to data of popped element, NULL if empty
 */
void *indexed_queue_pop(w_indexed_queue_t *queue);

/**
 * @brief Thread-safe pop with blocking when empty
 *
 * @param queue The indexed queue
 * @return Pointer to data of popped element
 */
void *indexed_queue_pop_ex(w_indexed_queue_t *queue);

/**
 * @brief Thread-safe pop with timeout
 *
 * @param queue The indexed queue
 * @param abstime Timeout specification
 * @return Pointer to data of popped element, NULL on timeout
 */
void *indexed_queue_pop_ex_timedwait(w_indexed_queue_t *queue, const struct timespec *abstime);

/**
 * @brief Delete element by key
 *
 * @param queue The indexed queue
 * @param key Key of element to delete
 * @return 1 if element found and deleted, 0 otherwise
 */
int indexed_queue_delete(w_indexed_queue_t *queue, const char *key);

/**
 * @brief Thread-safe delete element by key
 *
 * @param queue The indexed queue
 * @param key Key of element to delete
 * @return 1 if element found and deleted, 0 otherwise
 */
int indexed_queue_delete_ex(w_indexed_queue_t *queue, const char *key);

/**
 * @brief Update element by key (key must exist)
 *
 * @param queue The indexed queue
 * @param key Key of element to update
 * @param data New data value
 * @return Pointer to old data on success, NULL if key not found
 */
void *indexed_queue_update(w_indexed_queue_t *queue, const char *key, void *data);

/**
 * @brief Thread-safe update element by key
 *
 * @param queue The indexed queue
 * @param key Key of element to update
 * @param data New data value
 * @return Pointer to old data on success, NULL if key not found
 */
void *indexed_queue_update_ex(w_indexed_queue_t *queue, const char *key, void *data);

#endif // INDEXED_QUEUE_OP_H
