/*
 * Queue (abstract data type)
 * Copyright (C) 2017 Wazuh Inc.
 * October 2, 2017
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>

queue_t * queue_init(size_t size) {
    queue_t * queue;
    os_calloc(1, sizeof(queue_t), queue);
    os_malloc(size * sizeof(void *), queue->data);
    queue->size = size;
    return queue;
}

void queue_free(queue_t * queue) {
    if (queue) {
        free(queue->data);
        free(queue);
    }
}

int queue_full(const queue_t * queue) {
    return (queue->begin + 1) % queue->size == queue->end;
}

int queue_empty(const queue_t * queue) {
    return queue->begin == queue->end;
}

int queue_push(queue_t * queue, void * data) {
    if (queue_full(queue)) {
        return -1;
    } else {
        queue->data[queue->begin] = data;
        queue->begin = (queue->begin + 1) % queue->size;
        return 0;
    }
}

void * queue_pop(queue_t * queue) {
    void * data;

    if (queue_empty(queue)) {
        return NULL;
    } else {
        data = queue->data[queue->end];
        queue->data[queue->begin] = data;
        queue->end = (queue->end + 1) % queue->size;
        return data;
    }
}
