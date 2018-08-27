/* Copyright (C) 2009 Trend Micro Inc.
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

/* Create a new thread and give the argument passed to the function
 * Returns 0 on success or -1 on error
 */

#if defined(__MACH__)

#include <sys/resource.h>

/* Set the maximum stack limit to new threads on mac OS */
int CreateThread(void * (*function_pointer)(void *), void *data)
{
    pthread_t lthread;
    pthread_attr_t attr;
    struct rlimit lim;
    size_t stacksize = 0;
    int ret = 0;

    if (getrlimit(RLIMIT_STACK, &lim)) {
        merror_exit("At getrlimit(RLIMIT_STACK): %s (%d)", strerror(errno), errno);
    }

    if (lim.rlim_cur != RLIM_INFINITY && lim.rlim_cur >= PTHREAD_STACK_MIN) {

        if (pthread_attr_init(&attr)) {
            merror(THREAD_ERROR);
            return (-1);
        }

        if (pthread_attr_setstacksize(&attr, lim.rlim_cur)) {
            merror(THREAD_ERROR);
            return (-1);
        }

        if (pthread_attr_getstacksize(&attr, &stacksize)) {
            merror(THREAD_ERROR);
            return (-1);
        }
        mdebug2("Thread stack size set to: %d", (int)stacksize);
    }

    ret = pthread_create(&lthread, &attr, function_pointer, (void *)data);
    if (ret != 0) {
        merror(THREAD_ERROR);
        return (-1);
    }

    if (pthread_detach(lthread) != 0) {
        merror(THREAD_ERROR);
        return (-1);
    }

    pthread_attr_destroy(&attr);

    return (0);
}

#else

int CreateThread(void * (*function_pointer)(void *), void *data)
{
    pthread_t lthread;
    int ret = 0;

    ret = pthread_create(&lthread, NULL, function_pointer, (void *)data);
    if (ret != 0) {
        merror(THREAD_ERROR);
        return (-1);
    }

    if (pthread_detach(lthread) != 0) {
        merror(THREAD_ERROR);
        return (-1);
    }

    return (0);
}

#endif /* mac OS */
#endif /* !WIN32 */
