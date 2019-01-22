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

#include <shared.h>

#if defined(__linux__)

wnotify_t * wnotify_init(int size) {
    wnotify_t * notify;
    int fd;

    if (fd = epoll_create(size), fd < 0) {
        return NULL;
    }

    os_calloc(1, sizeof(wnotify_t), notify);
    notify->fd = fd;
    notify->size = size;
    os_calloc(size, sizeof(struct epoll_event), notify->events);

    return notify;
}

int wnotify_add(wnotify_t * notify, int fd) {
    struct epoll_event request = { .events = EPOLLIN, .data = { .fd = fd } };
    return epoll_ctl(notify->fd, EPOLL_CTL_ADD, fd, &request);
}

int wnotify_delete(wnotify_t * notify, int fd) {
    struct epoll_event request = { .events = EPOLLIN, .data = { .fd = fd } };
    return epoll_ctl(notify->fd, EPOLL_CTL_DEL, fd, &request);
}

int wnotify_wait(wnotify_t * notify, int timeout) {
    return epoll_wait(notify->fd, notify->events, notify->size, timeout);
}

#elif defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)

wnotify_t * wnotify_init(int size) {
    wnotify_t * notify;
    int fd;

    if (fd = kqueue(), fd < 0) {
        return NULL;
    }

    os_calloc(1, sizeof(wnotify_t), notify);
    notify->fd = fd;
    notify->size = size;
    os_calloc(size, sizeof(struct kevent), notify->events);
    return notify;
}

int wnotify_add(wnotify_t * notify, int fd) {
    struct kevent request;

    EV_SET(&request, fd, EVFILT_READ, EV_ADD, 0, 0, 0);
    return kevent(notify->fd, &request, 1, NULL, 0, NULL);
}

int wnotify_delete(wnotify_t * notify, int fd) {
    struct kevent request;

    EV_SET(&request, fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
    return kevent(notify->fd, &request, 1, NULL, 0, NULL);
}

int wnotify_wait(wnotify_t * notify, int timeout) {
    struct timespec ts = { timeout / 1000, (timeout % 1000) * 1000000 };
    return kevent(notify->fd, NULL, 0, notify->events, notify->size, timeout >= 0 ? &ts : NULL);
}

#endif /* __linux__ */

#if defined(__linux__) || defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)

void wnotify_close(wnotify_t * notify) {
    if (notify) {
        close(notify->fd);
        free(notify->events);
        free(notify);
    }
}

#endif
