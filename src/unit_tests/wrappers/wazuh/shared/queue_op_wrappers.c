/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "queue_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_queue_push_ex(w_queue_t * queue, void * data) {
    int retval = mock();

    check_expected_ptr(queue);
    check_expected(data);

    if (retval != -1) {
        queue->data[queue->begin] = data;
        queue->begin = (queue->begin + 1) % queue->size;
        queue->elements++;
    }

    return retval;
}

int __wrap_queue_full(const w_queue_t * queue) {
    check_expected_ptr(queue);

    return mock();
}

void * __wrap_queue_pop_ex(w_queue_t * queue) {
    void * data = NULL;

    int retval = mock();

    check_expected_ptr(queue);

    if (retval != -1) {
        data = queue->data[queue->end];
        queue->end = (queue->end + 1) % queue->size;
        queue->elements--;
    }

    return data;
}

void * __wrap_queue_pop_ex_timedwait(w_queue_t * queue, __attribute__((unused)) const struct timespec * abstime) {
    void * data = NULL;

    int retval = mock();

    check_expected_ptr(queue);

    if (retval != -1) {
        data = queue->data[queue->end];
        queue->end = (queue->end + 1) % queue->size;
        queue->elements--;
    }

    return data;
}
