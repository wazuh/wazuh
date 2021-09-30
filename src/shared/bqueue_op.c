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

#include <shared.h>

size_t _bqueue_used(bqueue_t * queue);
bool _bqueue_empty(bqueue_t * queue);
void _bqueue_expand(bqueue_t * queue, size_t new_length);
void _bqueue_shrink(bqueue_t * queue, size_t new_length);
void _bqueue_insert(bqueue_t * queue, const void * data, size_t data_len);
size_t _bqueue_extract(bqueue_t * queue, void * buffer, size_t buffer_len);
void _bqueue_trim(bqueue_t * queue);

bqueue_t * bqueue_init(size_t max_length, unsigned flags) {
    if (max_length <= 1) {
        return NULL;
    }

    bqueue_t * queue;
    os_calloc(1, sizeof(bqueue_t), queue);

    queue->max_length = max_length;
    queue->flags = flags;

    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond_pushed, NULL);
    pthread_cond_init(&queue->cond_popped, NULL);

    return queue;
}

void bqueue_destroy(bqueue_t * queue) {
    if (queue == NULL) {
        return;
    }

    free(queue->memory);

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond_pushed);
    pthread_cond_destroy(&queue->cond_popped);

    free(queue);
}

int bqueue_push(bqueue_t * queue, const void * data, size_t length, unsigned flags) {
    pthread_mutex_lock(&queue->mutex);

    // Check if data would fit

    if (length >= queue->max_length - 1) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }

    size_t used = _bqueue_used(queue);

    if (flags & BQUEUE_WAIT) {
        while (length + used >= queue->max_length - 1) {
            pthread_cond_wait(&queue->cond_popped, &queue->mutex);
            used = _bqueue_used(queue);
        }
    } else {
        if (length + used >= queue->max_length - 1) {
            pthread_mutex_unlock(&queue->mutex);
            return -1;
        }
    }

    // Check if data currently fits

    if (length + used >= queue->length) {
        _bqueue_expand(queue, length + used + 1);
    }

    _bqueue_insert(queue, data, length);

    pthread_cond_signal(&queue->cond_pushed);
    pthread_mutex_unlock(&queue->mutex);

    return 0;
}

size_t bqueue_pop(bqueue_t * queue, void * buffer, size_t length, unsigned flags) {
    pthread_mutex_lock(&queue->mutex);

    // Check if there is data available

    if (flags & BQUEUE_WAIT) {
        while (_bqueue_empty(queue)) {
            pthread_cond_wait(&queue->cond_pushed, &queue->mutex);
        }
    } else {
        if (_bqueue_empty(queue)) {
            pthread_mutex_unlock(&queue->mutex);
            return 0;
        }
    }

    size_t write_len = _bqueue_extract(queue, buffer, length);
    queue->head = queue->memory + (queue->head - queue->memory + write_len) % queue->length;

    if (_bqueue_empty(queue)) {
        _bqueue_trim(queue);
    } else if (queue->flags & BQUEUE_SHRINK && _bqueue_used(queue) < queue->length / 2) {
        _bqueue_shrink(queue, queue->length / 2);
    }

    pthread_cond_signal(&queue->cond_popped);
    pthread_mutex_unlock(&queue->mutex);

    return write_len;
}

size_t bqueue_peek(bqueue_t * queue, char * buffer, size_t length, unsigned flags) {
    pthread_mutex_lock(&queue->mutex);

    // Check if there is data available

    if (flags & BQUEUE_WAIT) {
        while (_bqueue_empty(queue)) {
            pthread_cond_wait(&queue->cond_pushed, &queue->mutex);
        }
    } else {
        if (_bqueue_empty(queue)) {
            pthread_mutex_unlock(&queue->mutex);
            return 0;
        }
    }

    size_t write_len = _bqueue_extract(queue, buffer, length);
    pthread_mutex_unlock(&queue->mutex);

    return write_len;
}

int bqueue_drop(bqueue_t * queue, size_t length) {
    int retval;

    pthread_mutex_lock(&queue->mutex);

    if (length <= _bqueue_used(queue)) {
        queue->head = queue->memory + (queue->head - queue->memory + length) % queue->length;

        if (_bqueue_empty(queue)) {
            _bqueue_trim(queue);
        } else if ((queue->flags & BQUEUE_SHRINK) && (_bqueue_used(queue) < queue->length / 2)) {
            _bqueue_shrink(queue, queue->length / 2);
        }

        pthread_cond_signal(&queue->cond_popped);
        retval = 0;
    } else {
        retval = -1;
    }

    pthread_mutex_unlock(&queue->mutex);
    return retval;
}

size_t bqueue_used(bqueue_t * queue) {
    return _bqueue_used(queue);
}

void bqueue_clear(bqueue_t * queue) {
    pthread_mutex_lock(&queue->mutex);
    _bqueue_trim(queue);
    pthread_mutex_unlock(&queue->mutex);
}

size_t _bqueue_used(bqueue_t * queue) {
    return queue->length > 0 ? (queue->tail + queue->length - queue->head) % queue->length : 0;
}

bool _bqueue_empty(bqueue_t * queue) {
    return queue->head == queue->tail;
}

void _bqueue_expand(bqueue_t * queue, size_t new_length) {
    void * new_memory;
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

void _bqueue_shrink(bqueue_t * queue, size_t new_length) {
    if (_bqueue_empty(queue)) {
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
            void * new_head = queue->head - (queue->length - new_length);

            if (head_len < new_length) {
                // Strings may overlap
                memmove(new_head, queue->head, queue->length - head_len);
            } else {
                memcpy(new_head, queue->head, queue->length - head_len);
            }

            queue->head = new_head;
        }
    }

    void * new_memory;
    os_realloc(queue->memory, new_length, new_memory);

    queue->head += new_memory - queue->memory;
    queue->tail += new_memory - queue->memory;
    queue->memory = new_memory;
    queue->length = new_length;
}

void _bqueue_insert(bqueue_t * queue, const void * data, size_t data_len) {
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

size_t _bqueue_extract(bqueue_t * queue, void * buffer, size_t buffer_len) {
    void * head;
    size_t head_len = 0;

    if (queue->head > queue->tail) {
        // Data is splitted
        head_len = queue->length - (queue->head - queue->memory);

        if (buffer_len < head_len) {
            memcpy(buffer, queue->head, buffer_len);
            return buffer_len;
        }

        memcpy(buffer, queue->head, head_len);
        buffer += head_len;
        buffer_len -= head_len;
        head = queue->memory;
    } else {
        head = queue->head;
    }

    // Data is contiguous
    size_t used = queue->tail - head;
    size_t chunk_len = buffer_len < used ? buffer_len : used;

    memcpy(buffer, head, chunk_len);
    return chunk_len + head_len;
}

void _bqueue_trim(bqueue_t * queue) {
    free(queue->memory);
    queue->memory = queue->head = queue->tail = NULL;
    queue->length = 0;
}
