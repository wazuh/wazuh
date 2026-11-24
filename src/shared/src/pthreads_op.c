/* Copyright (C) Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32
#include "shared.h"
#include <pthread.h>
#include <sys/resource.h>

/* wazuh.thread_stack_size, in bytes. The one place the option is read, with its range and default:
 * getDefine_Int_default() exits on a present but out-of-range value. */
size_t w_thread_stack_size(void)
{
#ifdef CLIENT
    return 1024 * (size_t)getDefine_Int("wazuh", "thread_stack_size", 2048, 65536);
#else
    return 1024 * (size_t)getDefine_Int_default("wazuh", "thread_stack_size", 2048, 65536, 8192);
#endif
}

/* The stack size this process's threads get, in bytes; 0 until it is first read. Read once per
 * process: re-reading the file at every thread creation let an out-of-range value written while a
 * daemon runs stop it (getDefine_Int_default() exits) the next time it started a thread -- modulesd
 * died serving a restart request, before the control script's checks could refuse the value. A
 * change to the file now takes effect at the next start, where `-t` judges it. Atomics, not a mutex:
 * the first readers may be several threads, and test binaries wrap pthread_mutex_lock(). */
static size_t thread_stack_size_bytes;

size_t w_thread_stack_size_in_use(void)
{
    size_t bytes = __atomic_load_n(&thread_stack_size_bytes, __ATOMIC_ACQUIRE);

    if (bytes == 0) {
        size_t expected = 0;

        bytes = w_thread_stack_size();

        if (!__atomic_compare_exchange_n(&thread_stack_size_bytes, &expected, bytes, false, __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE)) {
            bytes = expected;
        }
    }

    return bytes;
}

/* The internal options libwazuh itself reads, judged up front. wazuh.thread_stack_size is used at
 * thread creation, which on a manager daemon is after its -t has returned and after it has
 * daemonized, so an out-of-range value used to pass `-t` (and with it `wazuh-manager-control check`)
 * and then stop the daemon at start. Each manager C daemon calls this before its -t returns, on both
 * paths, so the value is refused while the refusal still reaches the control script; the value read
 * here is the one the daemon's threads use for the rest of its life. Exits through
 * getDefine_Int_default() on an invalid value; ranges unchanged. */
void w_validate_shared_internal_options(void)
{
    __atomic_store_n(&thread_stack_size_bytes, w_thread_stack_size(), __ATOMIC_RELEASE);
}

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

    read_size = w_thread_stack_size_in_use();

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
        return 0;
    }

    if (pthread_detach(lthread) != 0) {
        merror(THREAD_ERROR " Cannot detach thread.");
        return 0;
    }

    return 1;
}

#endif /* !WIN32 */
