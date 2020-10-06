/*
 * Linked Queue (abstract data type)
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 10, 2020
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>

/**
 * Appends a node to the end of the queue
 * @param queue Queue where the node will be appended
 * @param node  Node that will be appended
 * */
static void linked_queue_append_node(w_linked_queue_t *queue, w_linked_queue_node_t *node);

static void linked_queue_pop_node(w_linked_queue_t *queue);

w_linked_queue_t *linked_queue_init() {
    w_linked_queue_t *queue;
    os_calloc(1, sizeof(w_linked_queue_t), queue);
    queue->elements = 0;
    queue->first = NULL;
    queue->last = NULL;
    w_mutex_init(&queue->mutex, NULL);
    w_cond_init(&queue->available, NULL);
    return queue;
}

void linked_queue_free(w_linked_queue_t *queue) {
    if (queue) {
        w_mutex_destroy(&queue->mutex);
        w_cond_destroy(&queue->available);
        os_free(queue);
    }
}

void linked_queue_push(w_linked_queue_t * queue, void * data) {
    w_linked_queue_node_t *node;
    os_calloc(1, sizeof(w_linked_queue_node_t), node);
    node->data = data;
    node->next = NULL;
    linked_queue_append_node(queue, node);
}

void linked_queue_push_ex(w_linked_queue_t * queue, void * data) {
    w_linked_queue_node_t *node;
    os_calloc(1, sizeof(w_linked_queue_node_t), node);
    node->data = data;
    node->next = NULL;
    w_mutex_lock(&queue->mutex);
    linked_queue_append_node(queue, node);
    w_cond_signal(&queue->available);
    w_mutex_unlock(&queue->mutex);
}

void * linked_queue_pop(w_linked_queue_t * queue) {
    void * data;

    if (!queue->first) {
       data = NULL;
    } else {
        data = queue->last->data;
        linked_queue_pop_node(queue);
    }
    return data;
}

void * linked_queue_pop_ex(w_linked_queue_t * queue) {
    void * data;

    w_mutex_lock(&queue->mutex);
    while (data = linked_queue_pop(queue), !data) {
        w_cond_wait(&queue->available, &queue->mutex);
    }
    w_mutex_unlock(&queue->mutex);

    return data;
}

static void linked_queue_append_node(w_linked_queue_t *queue, w_linked_queue_node_t *node) {
    if (!queue->first) {
        // First node, will be both first and last
        queue->first = node;
        queue->last = node;
        node->prev = NULL;
        node->next = NULL;
    } else {
        queue->last->next = node;
        node->prev = queue->last;
        node->next = NULL;
        queue->last = node;
    }
    queue->elements++;
}

static void linked_queue_pop_node(w_linked_queue_t *queue) {
    w_linked_queue_node_t *tmp = queue->last;
    queue->last = queue->last->prev;
    if (queue->last) {
        queue->last->next = NULL;
    } else {
        // queue is now empty
        queue->first = NULL;
    }
    queue->elements--;
    os_free(tmp);
}
