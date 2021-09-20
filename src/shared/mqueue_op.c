/*
 * Messqge queue type
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 10, 2021
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>

size_t _mqueue_used(mqueue_t * queue);
bool _mqueue_empty(mqueue_t * queue);
void _mqueue_expand(mqueue_t * queue, size_t new_length);
void _mqueue_shrink(mqueue_t * queue, size_t new_length);
void _mqueue_insert(mqueue_t * queue, const char * data, size_t data_len);
void _mqueue_extract(mqueue_t * queue, char * buffer, size_t buffer_len);
void _mqueue_trim(mqueue_t * queue);

mqueue_t * mqueue_init(size_t max_length, unsigned flags) {
    if (max_length <= 1) {
        return NULL;
    }

    mqueue_t * queue;
    os_calloc(1, sizeof(mqueue_t), queue);

    queue->max_length = max_length;
    queue->flags = flags;

    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond_pushed, NULL);
    pthread_cond_init(&queue->cond_popped, NULL);

    return queue;
}

void mqueue_destroy(mqueue_t * queue) {
    if (queue == NULL) {
        return;
    }

    free(queue->memory);

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond_pushed);
    pthread_cond_destroy(&queue->cond_popped);

    free(queue);
}

int mqueue_push(mqueue_t * queue, const char * data, unsigned flags) {
    pthread_mutex_lock(&queue->mutex);

    // Check if data would fit

    size_t data_len = strlen(data) + 1;

    if (data_len >= queue->max_length - 1) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }

    size_t used = _mqueue_used(queue);

    if (flags & MQUEUE_WAIT) {
        while (data_len + used >= queue->max_length - 1) {
            pthread_cond_wait(&queue->cond_popped, &queue->mutex);
            used = _mqueue_used(queue);
        }
    } else {
        if (data_len + used >= queue->max_length - 1) {
            pthread_mutex_unlock(&queue->mutex);
            return -1;
        }
    }

    // Check if data currently fits

    if (data_len + used >= queue->length) {
        _mqueue_expand(queue, data_len + used + 1);
    }

    _mqueue_insert(queue, data, data_len);

    pthread_cond_signal(&queue->cond_pushed);
    pthread_mutex_unlock(&queue->mutex);

    return 0;
}

int mqueue_pop(mqueue_t * queue, char * buffer, size_t length, unsigned flags) {
    pthread_mutex_lock(&queue->mutex);

    // Check if there is data available

    if (flags & MQUEUE_WAIT) {
        while (_mqueue_empty(queue)) {
            pthread_cond_wait(&queue->cond_pushed, &queue->mutex);
        }
    } else {
        if (_mqueue_empty(queue)) {
            pthread_mutex_unlock(&queue->mutex);
            return -1;
        }
    }

    _mqueue_extract(queue, buffer, length);

    if (_mqueue_empty(queue)) {
        _mqueue_trim(queue);
    } else if (queue->flags & MQUEUE_SHRINK && _mqueue_used(queue) < queue->length / 2) {
        _mqueue_shrink(queue, queue->length / 2);
    }

    pthread_cond_signal(&queue->cond_popped);
    pthread_mutex_unlock(&queue->mutex);

    return 0;
}

size_t _mqueue_used(mqueue_t * queue) {
    return queue->length > 0 ? (queue->tail + queue->length - queue->head) % queue->length : 0;
}

bool _mqueue_empty(mqueue_t * queue) {
    return queue->head == queue->tail;
}

void _mqueue_expand(mqueue_t * queue, size_t new_length) {
    char * new_memory;
    os_realloc(queue->memory, new_length, new_memory);

    queue->head += new_memory - queue->memory;
    queue->tail += new_memory - queue->memory;
    queue->memory = new_memory;

    if (queue->tail < queue->head) {
        size_t tail_len = queue->tail - queue->memory;
        size_t growth = new_length - queue->length;

        if (tail_len <= growth) {
            memcpy(queue->memory + queue->length, queue->memory, tail_len);
            queue->tail = queue->memory + (queue->length + tail_len) % new_length;
        } else {
            memcpy(queue->memory + queue->length, queue->memory, growth);
            memmove(queue->memory, queue->memory + growth, tail_len - growth);
            queue->tail -= growth;
        }
    }

    queue->length = new_length;
}

void _mqueue_shrink(mqueue_t * queue, size_t new_length) {
    if (_mqueue_empty(queue)) {
        queue->head = queue->tail = queue->memory;
    } else {
        size_t head_len = queue->head - queue->memory;
        size_t tail_len = queue->tail - queue->memory;

        if (head_len < tail_len) {
            // Data is contiguous
            if (new_length <= head_len) {
                // Chunk is fully at right. Move it to the memory beginning.
                memcpy(queue->memory, queue->head, queue->tail - queue->head);
                queue->head = queue->memory;
                queue->tail -= head_len;
            } else if (new_length <= tail_len) {
                // Chunk needs to be splitted
                size_t chunk_len = tail_len - new_length;
                memcpy(queue->memory, queue->tail - chunk_len, chunk_len);
                queue->tail = queue->memory + chunk_len;
            }

            // Otherwise, the chunk is fully at left. Do nothing.
        } else {
            // Data is already splitted. Move the head to the left.
            char * new_head = queue->head - (queue->length - new_length);

            if (head_len < new_length) {
                // Strings may overlap
                memmove(new_head, queue->head, queue->length - head_len);
            } else {
                memcpy(new_head, queue->head, queue->length - head_len);
            }

            queue->head = new_head;
        }
    }

    char * new_memory;
    os_realloc(queue->memory, new_length, new_memory);

    queue->head += new_memory - queue->memory;
    queue->tail += new_memory - queue->memory;
    queue->memory = new_memory;
    queue->length = new_length;
}

void _mqueue_insert(mqueue_t * queue, const char * data, size_t data_len) {
    size_t tail_len = queue->tail - queue->memory;

    if (tail_len + data_len <= queue->length) {
        memcpy(queue->tail, data, data_len);
    } else {
        size_t chunk_len = queue->length - tail_len;
        memcpy(queue->tail, data, chunk_len);
        memcpy(queue->memory, data + chunk_len, data_len - chunk_len);
    }

    queue->tail = queue->memory + (tail_len + data_len) % queue->length;
}

void _mqueue_extract(mqueue_t * queue, char * buffer, size_t buffer_len) {
    size_t max_len = queue->length - (queue->head - queue->memory);
    size_t chunk_len = strnlen(queue->head, max_len);

    if (chunk_len < max_len) {
        chunk_len++;

        if (chunk_len > buffer_len) {
            chunk_len = buffer_len;
        }

        memcpy(buffer, queue->head, chunk_len);
        queue->head = queue->memory + (queue->head - queue->memory + chunk_len) % queue->length;
    } else {
        if (chunk_len > buffer_len) {
            chunk_len = buffer_len;
        }

        memcpy(buffer, queue->head, chunk_len);

        if (chunk_len < buffer_len) {
            strncpy(buffer + chunk_len, queue->memory, buffer_len - chunk_len);
        }

        queue->head = queue->memory + strlen(queue->memory) + 1;
    }

    buffer[buffer_len - 1] = '\0';
}

void _mqueue_trim(mqueue_t * queue) {
    free(queue->memory);
    queue->memory = queue->head = queue->tail = NULL;
    queue->length = 0;
}
