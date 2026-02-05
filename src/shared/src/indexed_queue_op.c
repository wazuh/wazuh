/**
 * @file indexed_queue_op.c
 * @brief Indexed Queue implementation
 * @date 2025-08-08
 *
 * @copyright Copyright (C) 2015 Wazuh, Inc.
 */

/*
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "indexed_queue_op.h"
#include "shared.h"

static void indexed_queue_entry_free(void *entry_ptr) {
    w_indexed_queue_entry_t *entry = (w_indexed_queue_entry_t *)entry_ptr;
    if (entry) {
        free(entry->key);
        free(entry);
    }
}

w_indexed_queue_t *indexed_queue_init(size_t max_size) {
    w_indexed_queue_t *queue;
    os_calloc(1, sizeof(w_indexed_queue_t), queue);

    queue->queue = linked_queue_init();
    if (!queue->queue) {
        free(queue);
        return NULL;
    }

    queue->index = rbtree_init();
    if (!queue->index) {
        linked_queue_free(queue->queue);
        free(queue);
        return NULL;
    }

    rbtree_set_dispose(queue->index, indexed_queue_entry_free);

    w_mutex_init(&queue->mutex, NULL);

    w_cond_init(&queue->available, NULL);

    w_cond_init(&queue->available_not_full, NULL);

    queue->max_size = max_size;
    queue->current_size = 0;
    queue->dispose = NULL;
    queue->get_key = NULL;

    return queue;
}

void indexed_queue_free(w_indexed_queue_t *queue) {
    if (!queue) {
        return;
    }

    w_mutex_lock(&queue->mutex);

    // Free all remaining data if dispose function is set
    if (queue->dispose) {
        void *data;
        while ((data = linked_queue_pop(queue->queue)) != NULL) {
            queue->dispose(data);
        }
    } else {
        // Just empty the queue
        while (linked_queue_pop(queue->queue) != NULL) {
            // Do nothing, just remove elements
        }
    }

    w_mutex_unlock(&queue->mutex);

    rbtree_destroy(queue->index);
    linked_queue_free(queue->queue);
    w_cond_destroy(&queue->available_not_full);
    w_cond_destroy(&queue->available);
    w_mutex_destroy(&queue->mutex);
    free(queue);
}

void indexed_queue_set_dispose(w_indexed_queue_t *queue, void (*dispose)(void *)) {
    if (queue) {
        w_mutex_lock(&queue->mutex);
        queue->dispose = dispose;
        w_mutex_unlock(&queue->mutex);
    }
}

void indexed_queue_set_get_key(w_indexed_queue_t *queue, char *(*get_key)(void *)) {
    if (queue) {
        w_mutex_lock(&queue->mutex);
        queue->get_key = get_key;
        w_mutex_unlock(&queue->mutex);
    }
}

int indexed_queue_empty(const w_indexed_queue_t *queue) {
    return queue ? (queue->current_size == 0) : 1;
}

int indexed_queue_full(const w_indexed_queue_t *queue) {
    if (!queue || queue->max_size == 0) {
        return 0; // Unlimited size
    }
    return queue->current_size >= queue->max_size;
}

size_t indexed_queue_size(const w_indexed_queue_t *queue) {
    return queue ? queue->current_size : 0;
}

int indexed_queue_push(w_indexed_queue_t *queue, const char *key, void *data) {
    if (!queue || !key || !data) {
        return -1;
    }

    // Check if queue is full
    if (indexed_queue_full(queue)) {
        return -1;
    }

    // Check if key already exists
    if (rbtree_get(queue->index, key) != NULL) {
        return -1; // Key already exists
    }

    // Create entry
    w_indexed_queue_entry_t *entry;
    os_malloc(sizeof(w_indexed_queue_entry_t), entry);

    entry->key = strdup(key);
    if (!entry->key) {
        free(entry);
        return -1;
    }
    entry->data = data;

    // Add to queue
    entry->queue_node = linked_queue_push(queue->queue, data);
    if (!entry->queue_node) {
        free(entry->key);
        free(entry);
        return -1;
    }

    // Add to index
    if (!rbtree_insert(queue->index, key, entry)) {
        // This shouldn't happen since we checked above, but cleanup anyway
        linked_queue_pop(queue->queue); // Remove from queue
        free(entry->key);
        free(entry);
        return -1;
    }

    atomic_fetch_add(&queue->current_size, 1);
    return 0;
}

int indexed_queue_push_ex(w_indexed_queue_t *queue, const char *key, void *data) {
    if (!queue || !key || !data) {
        return -1;
    }

    w_mutex_lock(&queue->mutex);

    // Wait if queue is full
    while (indexed_queue_full(queue)) {
        w_cond_wait(&queue->available_not_full, &queue->mutex);
    }

    int result = indexed_queue_push(queue, key, data);
    if (result == 0) {
        w_cond_signal(&queue->available);
    }

    w_mutex_unlock(&queue->mutex);
    return result;
}

int indexed_queue_upsert(w_indexed_queue_t *queue, const char *key, void *data) {
    if (!queue || !key || !data) {
        return -1;
    }

    w_indexed_queue_entry_t *entry = rbtree_get(queue->index, key);
    if (entry) {
        // Update existing entry
        if (queue->dispose) {
            queue->dispose(entry->data);
        }
        entry->data = data;
        // Update the queue node data too
        entry->queue_node->data = data;
        return 0;
    } else {
        // Insert new entry
        return indexed_queue_push(queue, key, data);
    }
}

int indexed_queue_upsert_ex(w_indexed_queue_t *queue, const char *key, void *data) {
    if (!queue || !key || !data) {
        return -1;
    }

    w_mutex_lock(&queue->mutex);

    w_indexed_queue_entry_t *entry = rbtree_get(queue->index, key);
    if (entry) {
        // Update existing entry
        if (queue->dispose) {
            queue->dispose(entry->data);
        }
        entry->data = data;
        entry->queue_node->data = data;
        w_mutex_unlock(&queue->mutex);
        return 1;
    } else {
        // Wait if queue is full for new insertions
        while (indexed_queue_full(queue)) {
            w_cond_wait(&queue->available_not_full, &queue->mutex);
        }

        int result = indexed_queue_push(queue, key, data);
        if (result == 0) {
            w_cond_signal(&queue->available);
        }

        w_mutex_unlock(&queue->mutex);
        return result;
    }
}

void *indexed_queue_get(const w_indexed_queue_t *queue, const char *key) {
    if (!queue || !key) {
        return NULL;
    }

    w_indexed_queue_entry_t *entry = rbtree_get(queue->index, key);
    return entry ? entry->data : NULL;
}

void *indexed_queue_get_ex(w_indexed_queue_t *queue, const char *key) {
    if (!queue || !key) {
        return NULL;
    }

    w_mutex_lock(&queue->mutex);
    void *data = indexed_queue_get(queue, key);
    w_mutex_unlock(&queue->mutex);
    return data;
}

void *indexed_queue_peek(const w_indexed_queue_t *queue) {
    if (!queue || indexed_queue_empty(queue)) {
        return NULL;
    }

    // Peek at the first element in the queue
    if (queue->queue->first) {
        return queue->queue->first->data;
    }
    return NULL;
}

void *indexed_queue_peek_ex(w_indexed_queue_t *queue) {
    if (!queue) {
        return NULL;
    }

    w_mutex_lock(&queue->mutex);
    void *data = indexed_queue_peek(queue);
    w_mutex_unlock(&queue->mutex);
    return data;
}

void *indexed_queue_pop(w_indexed_queue_t *queue) {
    if (!queue || indexed_queue_empty(queue)) {
        return NULL;
    }

    // Pop from queue
    void *data = linked_queue_pop(queue->queue);
    if (!data) {
        return NULL;
    }

    // Find and remove from index using get_key callback if available
    if (queue->get_key) {
        // O(log n) key lookup using callback
        char *key = queue->get_key(data);
        if (key) {
            rbtree_delete(queue->index, key);
        }
    } else {
        // Fallback to O(n) search if no callback is set
        char **keys = rbtree_keys(queue->index);
        if (keys) {
            for (int i = 0; keys[i]; i++) {
                w_indexed_queue_entry_t *entry = rbtree_get(queue->index, keys[i]);
                if (entry && entry->data == data) {
                    rbtree_delete(queue->index, keys[i]);
                    break;
                }
            }
            // Free keys array
            for (int i = 0; keys[i]; i++) {
                free(keys[i]);
            }
            free(keys);
        }
    }

    atomic_fetch_sub(&queue->current_size, 1);
    return data;
}

void *indexed_queue_pop_ex(w_indexed_queue_t *queue) {
    if (!queue) {
        return NULL;
    }

    w_mutex_lock(&queue->mutex);

    while (indexed_queue_empty(queue)) {
        w_cond_wait(&queue->available, &queue->mutex);
    }

    void *data = indexed_queue_pop(queue);
    w_cond_signal(&queue->available_not_full);

    w_mutex_unlock(&queue->mutex);
    return data;
}

void *indexed_queue_pop_ex_timedwait(w_indexed_queue_t *queue, const struct timespec *abstime) {
    if (!queue) {
        return NULL;
    }

    w_mutex_lock(&queue->mutex);

    while (indexed_queue_empty(queue)) {
        int result = pthread_cond_timedwait(&queue->available, &queue->mutex, abstime);
        if (result != 0) {
            w_mutex_unlock(&queue->mutex);
            return NULL;
        }
    }

    void *data = indexed_queue_pop(queue);
    w_cond_signal(&queue->available_not_full);

    w_mutex_unlock(&queue->mutex);
    return data;
}

int indexed_queue_delete(w_indexed_queue_t *queue, const char *key) {
    if (!queue || !key) {
        return 0;
    }

    w_indexed_queue_entry_t *entry = rbtree_get(queue->index, key);
    if (!entry) {
        return 0; // Key not found
    }

    // Remove from queue by unlinking the node
    // We need to manually unlink since we have the node reference
    w_linked_queue_node_t *node = entry->queue_node;
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        // This was the first node
        queue->queue->first = node->next;
    }

    if (node->next) {
        node->next->prev = node->prev;
    } else {
        // This was the last node
        queue->queue->last = node->prev;
    }

    queue->queue->elements--;

    // Dispose data if function is set
    if (queue->dispose) {
        queue->dispose(entry->data);
    }

    // Free the queue node
    free(node);

    // Remove from index (this will also free the entry)
    rbtree_delete(queue->index, key);

    atomic_fetch_sub(&queue->current_size, 1);
    return 1;
}

int indexed_queue_delete_ex(w_indexed_queue_t *queue, const char *key) {
    if (!queue || !key) {
        return 0;
    }

    w_mutex_lock(&queue->mutex);
    int result = indexed_queue_delete(queue, key);
    if (result) {
        w_cond_signal(&queue->available_not_full);
    }
    w_mutex_unlock(&queue->mutex);
    return result;
}

void *indexed_queue_update(w_indexed_queue_t *queue, const char *key, void *data) {
    if (!queue || !key || !data) {
        return NULL;
    }

    w_indexed_queue_entry_t *entry = rbtree_get(queue->index, key);
    if (!entry) {
        return NULL; // Key not found
    }

    void *old_data = entry->data;
    entry->data = data;
    entry->queue_node->data = data;

    return old_data;
}

void *indexed_queue_update_ex(w_indexed_queue_t *queue, const char *key, void *data) {
    if (!queue || !key || !data) {
        return NULL;
    }

    w_mutex_lock(&queue->mutex);
    void *old_data = indexed_queue_update(queue, key, data);
    w_mutex_unlock(&queue->mutex);
    return old_data;
}
