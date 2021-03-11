/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common API for dealing with atomic operations */

#ifndef ATOMIC_H
#define ATOMIC_H

#include <pthread.h>
#include "pthreads_op.h"

#define ATOMIC_INT_INITIALIZER(v) { .data = v, .mutex = PTHREAD_MUTEX_INITIALIZER}

typedef struct _atomic_int_t {
    int data;
    pthread_mutex_t mutex;
} atomic_int_t;

/**
 * @brief Thread safe function that gets the the value of an atomic int.
 *
 * @param atomic atomic int structure to get the data value.
 * @return int A copy of the atomic_int value.
 */
int atomic_int_get(atomic_int_t *atomic);

/**
 * @brief Thread safe functions that sets the value of an atomic int
 *
 * @param atomic atomic_int_t structure that is used.
 * @param value Value that will be used to set the atomic int value.
 */
void atomic_int_set(atomic_int_t *atomic, int value);


#endif // ATOMIC_H
