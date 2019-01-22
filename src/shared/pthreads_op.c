/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32
#include "shared.h"
#include <pthread.h>
#include <sys/resource.h>

/* Create a new thread and give the argument passed to the function
 * Returns 0 on success or -1 on error
 */

int CreateThreadJoinable(pthread_t *lthread, void * (*function_pointer)(void *), void *data)
{
    pthread_attr_t attr;
    size_t read_size = 0;
    size_t stacksize = 0;
    int ret = 0;

    if (pthread_attr_init(&attr)) {
        merror(THREAD_ERROR " Cannot initialize attributes.");
        return -1;
    }

    read_size = 1024 * (size_t)getDefine_Int("wazuh", "thread_stack_size", 2048, 65536);

    /* Set the maximum stack limit to new threads */
    if (pthread_attr_setstacksize(&attr, read_size)) {
        merror(THREAD_ERROR " Cannot set stack size to %d KB.", (int)read_size);
        return -1;
    }

    if (pthread_attr_getstacksize(&attr, &stacksize)) {
        merror(THREAD_ERROR " Cannot confirm stack size setting.");
        return -1;
    }

    mdebug2("Thread stack size set to: %d KiB", (int)stacksize / 1024);

    ret = pthread_create(lthread, &attr, function_pointer, (void *)data);
    if (ret != 0) {
        merror(THREAD_ERROR " %s (%d)", strerror(ret), ret);
        return -1;
    }

    pthread_attr_destroy(&attr);

    return (0);
}

int CreateThread(void * (*function_pointer)(void *), void *data)
{
    pthread_t lthread;

    if (CreateThreadJoinable(&lthread, function_pointer, data) < 0) {
        return -1;
    }

    if (pthread_detach(lthread) != 0) {
        merror(THREAD_ERROR " Cannot detach thread.");
        return -1;
    }

    return (0);
}

#endif /* !WIN32 */
