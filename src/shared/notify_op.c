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

int wnotify_add(wnotify_t * notify, int fd, const woperation_t op) {

    const int operation = (op & WO_READ ? EPOLLIN : 0) | (op & WO_WRITE ? EPOLLOUT : 0);
    struct epoll_event request = { .events = operation, .data = { .fd = fd } };
    return epoll_ctl(notify->fd, EPOLL_CTL_ADD, fd, &request);
}

int wnotify_modify(wnotify_t * notify, int fd, const woperation_t op) {

    const int operation = (op & WO_READ ? EPOLLIN : 0) | (op & WO_WRITE ? EPOLLOUT : 0);
    struct epoll_event request = { .events = operation, .data = { .fd = fd } };
    return epoll_ctl(notify->fd, EPOLL_CTL_MOD, fd, &request);
}

int wnotify_delete(wnotify_t * notify, int fd, const woperation_t op) {

    const int operation = (op & WO_READ ? EPOLLIN : 0) | (op & WO_WRITE ? EPOLLOUT : 0);
    struct epoll_event request = { .events = operation, .data = { .fd = fd } };
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

int wnotify_add(wnotify_t * notify, int fd, const woperation_t op) {
    struct kevent request;

    const int operation = (op & WO_READ ? EVFILT_READ : 0) | (op & WO_WRITE ? EVFILT_WRITE : 0);
    EV_SET(&request, fd, operation, EV_ADD, 0, 0, 0);
    return kevent(notify->fd, &request, 1, NULL, 0, NULL);
}

int wnotify_modify(wnotify_t * notify, int fd, const woperation_t op) {

    // Re-adding an existing event will modify the parameters of the original event,
    // and not result in a duplicate entry.
    return wnotify_add(notify, fd, op);
}

int wnotify_delete(wnotify_t * notify, int fd, const woperation_t op) {
    struct kevent request;

    const int operation = (op & WO_READ ? EVFILT_READ : 0) | (op & WO_WRITE ? EVFILT_WRITE : 0);
    EV_SET(&request, fd, operation, EV_DELETE, 0, 0, 0);
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
