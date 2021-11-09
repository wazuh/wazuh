/*
 * Linked Queue (abstract data type)
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 10, 2020
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * Library that creates a queue where items
 * are pushed and poped following the FIFO (First In, First Out)
 * principle. The difference with queue_op.h is that no buffer is allocated,
 * the size of the queue can change depending on the amount of items it has
 * */

#ifndef QUEUE_LINKED_OP_H
#define QUEUE_LINKED_OP_H

#include <pthread.h>

typedef struct w_linked_queue_t w_linked_queue_t;

typedef void (*w_linked_queue_free_fn)(void *data);

// Opaque iterator type.
typedef void* w_linked_queue_iterator;

/**
 * @brief Initializes a new queue structure
 * 
 * @param free_function free function to be used when freeing the data in each element.
 * if NULL, the data will be freed by calling the regular free() function.
 *
 * @return initialize queue structure
 * */
w_linked_queue_t *linked_queue_init(w_linked_queue_free_fn free_function);

/**
 * @brief Frees an existent queue
 * 
 * @param queue 
 * */
void linked_queue_free(w_linked_queue_t *queue);

/** 
 * @brief Inserts an element into the queue
 * 
 * @param queue the queue
 * @param data data to be inserted
 * @return node structure pushed to the queue
 * */
w_linked_queue_iterator linked_queue_push(w_linked_queue_t * queue, void * data);

/** 
 * @brief Same as queue_push but with mutual exclusion 
 * for multithreaded applications
 * 
 * @param queue the queue
 * @param data data to be inserted
 * @return node structure pushed to the queue
 * */
w_linked_queue_iterator linked_queue_push_ex(w_linked_queue_t * queue, void * data);

/**
 * @brief Retrieves next item in the queue
 * 
 * @param queue the queue
 * @return element if queue has a next
 *         NULL if queue is empty
 * */
void * linked_queue_pop(w_linked_queue_t * queue);

/**
 * @brief Same as queue_pop but with mutual exclusion 
 * for multithreaded applications.
 * 
 * @param queue the queue
 * @return next element in the queue
 * */
void * linked_queue_pop_ex(w_linked_queue_t * queue);

/**
 * @brief Returns the count of elements in queue.
 *
 * @param queue the queue
 * @return count of elements
 * */
size_t linked_queue_size(w_linked_queue_t * queue);

/**
 * @brief Remove element by its iterator.
 *
 * @param queue the queue
 * @return count of elements
 * */
size_t linked_queue_remove(w_linked_queue_t *queue, w_linked_queue_iterator it);

/**
 * @brief Unlinks an existent node from the queue and pushes it again to the end
 *
 * @param queue the queue
 * @param node node to be unlinked from the queue
 * */
void linked_queue_unlink_and_push_node(w_linked_queue_t * queue, const w_linked_queue_iterator node);

#endif
