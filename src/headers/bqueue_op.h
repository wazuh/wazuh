/*
 * Binary queue type
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 20, 2021
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef BQUEUE_OP_H
#define BQUEUE_OP_H

#include <shared.h>

#define BQUEUE_WAIT     1
#define BQUEUE_SHRINK   2

typedef struct {
    void * memory;
    void * head;
    void * tail;
    size_t length;
    size_t max_length;
    unsigned flags;
    pthread_mutex_t mutex;
    pthread_cond_t cond_pushed;
    pthread_cond_t cond_popped;
} bqueue_t;

bqueue_t * bqueue_init(size_t max_length, unsigned flags);
void bqueue_destroy(bqueue_t * queue);
int bqueue_push(bqueue_t * queue, const void * data, size_t length, unsigned flags);
size_t bqueue_pop(bqueue_t * queue, void * buffer, size_t length, unsigned flags);
size_t bqueue_peek(bqueue_t * queue, char * buffer, size_t length, unsigned flags);
int bqueue_drop(bqueue_t * queue, size_t length);

#endif
