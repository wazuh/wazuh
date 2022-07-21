/*
 * Network counter library for Remoted
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <shared.h>
#include "remoted.h"

#define SIZE_BLOCK 256

typedef struct rem_fdlist_t {
    size_t* list;
    int size;
} rem_fdlist_t;

static rem_fdlist_t connections;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


void rem_initList(int initial_size) {
    os_calloc(initial_size, sizeof(size_t), connections.list);
    connections.size = initial_size;
}


void rem_setCounter(int fd, size_t counter) {
    assert(fd >= 0);

    w_mutex_lock(&lock);
    while (fd >= connections.size) {
        os_realloc(connections.list, sizeof(size_t) * (connections.size + SIZE_BLOCK), connections.list);
        memset(&connections.list[connections.size], 0, sizeof(size_t) * SIZE_BLOCK);
        connections.size = connections.size + SIZE_BLOCK;
    }
    connections.list[fd] = counter;
    w_mutex_unlock(&lock);
}


size_t rem_getCounter(int fd) {
    assert(fd >= 0);

    w_mutex_lock(&lock);
    size_t counter = (fd >= connections.size) ? 0 : connections.list[fd];
    w_mutex_unlock(&lock);
    return counter;
}
