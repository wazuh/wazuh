/*
 * Messqge queue type
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 9, 2021
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef MQUEUE_OP_H
#define MQUEUE_OP_H

#include <shared.h>

#define MQUEUE_WAIT     1
#define MQUEUE_SHRINK   2

typedef struct {
    char * memory;
    char * head;
    char * tail;
    size_t length;
    size_t max_length;
    unsigned flags;
    pthread_mutex_t mutex;
    pthread_cond_t cond_pushed;
    pthread_cond_t cond_popped;
} mqueue_t;

mqueue_t * mqueue_init(size_t max_length, unsigned flags);
void mqueue_destroy(mqueue_t * queue);
int mqueue_push(mqueue_t * queue, const char * data, unsigned flags);
int mqueue_pop(mqueue_t * queue, char * buffer, size_t length, unsigned flags);

#endif
