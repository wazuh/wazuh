/*
 * Event notification
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 4, 2018
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef NOTIFY_OP_H
#define NOTIFY_OP_H

#if defined(__linux__)

#include <sys/epoll.h>

typedef struct wnotify_t {
    int fd;
    int size;
    struct epoll_event * events;
} wnotify_t;

static inline int wnotify_get(const wnotify_t * notify, int index) {
    return notify->events[index].data.fd;
}

#elif defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)

#include <sys/types.h>
#include <sys/event.h>

typedef struct wnotify_t {
    int fd;
    int size;
    struct kevent * events;
} wnotify_t;

static inline int wnotify_get(const wnotify_t * notify, int index) {
    return notify->events[index].ident;
}

#endif /* __linux__ */

#if defined(__linux__) || defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)

wnotify_t * wnotify_init(int size);
int wnotify_add(wnotify_t * notify, int fd);
int wnotify_delete(wnotify_t * notify, int fd);
int wnotify_wait(wnotify_t * notify, int timeout);
void wnotify_close(wnotify_t * notify);

#endif

#endif
