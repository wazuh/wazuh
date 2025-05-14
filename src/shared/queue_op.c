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

#include <shared.h>

w_queue_t * queue_init(size_t size) {
    w_queue_t * queue;
    os_calloc(1, sizeof(w_queue_t), queue);
    os_malloc(size * sizeof(void *), queue->data);
    queue->size = size;
    queue->elements = 0;
    queue->begin = 0;
    queue->end = 0;
    w_mutex_init(&queue->mutex, NULL);
    w_cond_init(&queue->available, NULL);
    w_cond_init(&queue->available_not_empty, NULL);
    return queue;
}

void queue_free(w_queue_t * queue) {
    if (queue) {
        free(queue->data);
        w_mutex_destroy(&queue->mutex);
        w_cond_destroy(&queue->available);
        w_cond_destroy(&queue->available_not_empty);
        free(queue);
    }
}

int queue_full(const w_queue_t * queue) {
    return (queue->begin + 1) % queue->size == queue->end;
}

int queue_empty(const w_queue_t * queue) {
    return queue->begin == queue->end;
}

int queue_empty_ex(w_queue_t * queue) {
    w_mutex_lock(&queue->mutex);
    bool empty = queue->begin == queue->end;
    w_mutex_unlock(&queue->mutex);
    return empty;
}

float queue_get_percentage_ex(const w_queue_t * queue) {

    if (queue == NULL) {
        return -1;
    }
    w_mutex_lock(&queue->mutex);
    size_t elements = queue->elements;
    size_t size = queue->size;
    w_mutex_unlock(&queue->mutex);

    return (float) elements / (float) (size - 1);
}

int queue_push(w_queue_t * queue, void * data) {
    if (queue_full(queue)) {
        return -1;
    } else {
        queue->data[queue->begin] = data;
        queue->begin = (queue->begin + 1) % queue->size;
        queue->elements++;
        return 0;
    }
}

int queue_push_ex(w_queue_t * queue, void * data) {
    int result;

    w_mutex_lock(&queue->mutex);

    if (result = queue_push(queue, data), result == 0) {
        w_cond_signal(&queue->available);
    }

    w_mutex_unlock(&queue->mutex);
    return result;
}

int queue_push_ex_block(w_queue_t * queue, void * data) {
    int result;

    w_mutex_lock(&queue->mutex);

    while (result = queue_full(queue), result) {
        w_cond_wait(&queue->available_not_empty, &queue->mutex);
    }

    result = queue_push(queue,data);

    w_cond_signal(&queue->available_not_empty);
    w_cond_signal(&queue->available);
    w_mutex_unlock(&queue->mutex);

    return result;
}

void * queue_pop(w_queue_t * queue) {
    void * data;

    if (queue_empty(queue)) {
        return NULL;
    } else {
        data = queue->data[queue->end];
        queue->end = (queue->end + 1) % queue->size;
        queue->elements--;
        return data;
    }
}

void * queue_pop_ex(w_queue_t * queue) {
    void * data;

    w_mutex_lock(&queue->mutex);

    while (data = queue_pop(queue), !data) {
        w_cond_wait(&queue->available, &queue->mutex);
    }

    w_cond_signal(&queue->available_not_empty);
    w_mutex_unlock(&queue->mutex);

    return data;
}

void * queue_pop_ex_timedwait(w_queue_t * queue, const struct timespec * abstime) {
    void * data;

    w_mutex_lock(&queue->mutex);

    while (data = queue_pop(queue), !data) {
        if (pthread_cond_timedwait(&queue->available, &queue->mutex, abstime) != 0) {
            w_mutex_unlock(&queue->mutex);
            return NULL;
        }
    }

    w_cond_signal(&queue->available_not_empty);
    w_mutex_unlock(&queue->mutex);

    return data;
}
