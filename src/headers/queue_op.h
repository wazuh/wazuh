/*
 * Queue (abstract data type)
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October 2, 2017
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef QUEUE_OP_H
#define QUEUE_OP_H

#include <pthread.h>

typedef struct queue_t {
    void ** data;
    size_t begin;
    size_t end;
    size_t size;
    pthread_mutex_t mutex;
    pthread_cond_t available;
    pthread_cond_t available_not_empty;
    unsigned int elements;
} w_queue_t;

w_queue_t * queue_init(size_t n);
void queue_free(w_queue_t * queue);
int queue_full(const w_queue_t * queue);
int queue_empty(const w_queue_t * queue);
int queue_push(w_queue_t * queue, void * data);
int queue_push_ex(w_queue_t * queue, void * data);
int queue_push_ex_block(w_queue_t * queue, void * data);
void * queue_pop(w_queue_t * queue);
void * queue_pop_ex(w_queue_t * queue);
void * queue_pop_ex_block(w_queue_t * queue);

#endif // QUEUE_OP_H
