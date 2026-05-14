/*
 * Event notification
 * Copyright (C) 2015, Wazuh Inc.
 * May 4, 2018
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef NOTIFY_OP_H
#define NOTIFY_OP_H

typedef enum {
    WO_UNKNOWN = 0,
    WO_READ  = 1,
    WO_WRITE = 2
} woperation_t;

typedef enum {
    WE_UNKNOWN = 0,
    WE_READ  = 1,
    WE_WRITE = 2
} wevent_t;

#if defined(__linux__)

#include <sys/epoll.h>

typedef struct wnotify_t {
    int fd;
    int size;
    struct epoll_event * events;
} wnotify_t;

static inline int wnotify_get(const wnotify_t * notify, int index, wevent_t * event) {
    if (event != NULL) {
        const uint32_t events = notify->events[index].events;
        *event = (wevent_t)((events & EPOLLIN ? WE_READ : WE_UNKNOWN) | (events & EPOLLOUT ? WE_WRITE : WE_UNKNOWN));
    }

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


static inline int wnotify_get(const wnotify_t * notify, int index, wevent_t * event) {
    if (event != NULL) {
        const unsigned int filter = notify->events[index].filter;
        *event = (wevent_t)((filter & EVFILT_READ ? WE_READ : WE_UNKNOWN) | (filter & EVFILT_WRITE ? WE_WRITE : WE_UNKNOWN));
    }

    return notify->events[index].ident;
}

#endif /* __linux__ */

#if defined(__linux__) || defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)

wnotify_t * wnotify_init(int size);
int wnotify_add(wnotify_t * notify, int fd, const woperation_t op);
int wnotify_modify(wnotify_t * notify, int fd, const woperation_t op);
int wnotify_delete(wnotify_t * notify, int fd, const woperation_t op);
int wnotify_wait(wnotify_t * notify, int timeout);
void wnotify_close(wnotify_t * notify);

#endif

#endif
