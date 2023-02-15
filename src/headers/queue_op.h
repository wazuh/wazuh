/*
 * Queue (abstract data type)
 * Copyright (C) 2015, Wazuh Inc.
 * October 2, 2017
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * Library that creates a circular buffer where items
 * are pushed and poped following the FIFO (First In, First Out)
 * principle.
 * */
#ifndef QUEUE_OP_H
#define QUEUE_OP_H

#include <pthread.h>

/**
 * queue main structure 
 * */
typedef struct w_queue_s {
    void ** data; ///> Pointer to the circular buffer
    size_t begin; ///> Stores the index of the next empty space
    size_t end;   ///> Stores the index of the next element
    size_t size;  ///> Size of the queue
    pthread_mutex_t mutex; ///> mutex for mutual exclusion
    pthread_cond_t available; ///> condition variable when queue is empty
    pthread_cond_t available_not_empty; ///> Condition variable when queue is full
    unsigned int elements; ///> counts the number of elements stored in the queue
} w_queue_t;

/**
 * @brief Initializes a new queue structure
 * 
 * @param n size of the circular queue (fits n - 1 elements)
 * @return initialize queue structure
 * */
w_queue_t * queue_init(size_t n);

/**
 * @brief Frees an existent queue
 * 
 * @param queue 
 * */
void queue_free(w_queue_t * queue);

/**
 * @brief Evaluates whether the queue is full or not
 * 
 * @param queue
 * @return 1 if true, 0 if false
 * */
int queue_full(const w_queue_t * queue);

/**
 * @brief Evaluates whether the queue is empty or not
 * 
 * @param queue
 * @return 1 if true, 0 if false
 * */
int queue_empty(const w_queue_t * queue);

/** 
 * @brief Tries to insert an element into the queue
 * 
 * @param queue the queue
 * @param data data to be inserted
 * @return -1 if queue is full
 *          0 on success
 * */
int queue_push(w_queue_t * queue, void * data);

/** 
 * @brief Same as queue_push but with mutual exclusion 
 * for multithreaded applications
 * 
 * @param queue the queue
 * @param data data to be inserted
 * @return -1 if queue is full
 *          0 on success
 * */
int queue_push_ex(w_queue_t * queue, void * data);

/** 
 * @brief Same as queue_push_ex but if queue is full will
 * wait until there is space for the element (THREAD BLOCK)
 * 
 * @param queue the queue
 * @param data data to be inserted
 * @return 0 always
 * */
int queue_push_ex_block(w_queue_t * queue, void * data);

/**
 * @brief Retrieves next item in the queue
 * 
 * @param queue the queue
 * @return element if queue has a next
 *         NULL if queue is empty
 * */
void * queue_pop(w_queue_t * queue);

/**
 * @brief Same as queue_pop but with mutual exclusion 
 * for multithreaded applications. If queue is empty THREAD WILL BLOCK
 * 
 * @param queue the queue
 * @return next element in the queue
 * */
void * queue_pop_ex(w_queue_t * queue);

/**
 * @brief Same as queue_pop_ex but with a configured timeout for the
 * wait. If queue is empty THREAD WILL BLOCK
 * 
 * @param queue the queue
 * @param abstime timeout specification
 * @return next element in the queue
 * */
void * queue_pop_ex_timedwait(w_queue_t * queue, const struct timespec * abstime);

#endif // QUEUE_OP_H
