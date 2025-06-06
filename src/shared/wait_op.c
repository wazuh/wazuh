/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

#define LOCK_LOOP   5

static int __wait_lock = 0;


/* Create global lock */
void os_setwait()
{
    FILE *fp = NULL;

    /* For same threads */
    __wait_lock = 1;
    fp = wfopen(WAIT_FILE, "w");

    if (fp) {
        fprintf(fp, "l");
        fclose(fp);
    }

    return;
}

/* Remove global lock */
void os_delwait()
{
    __wait_lock = 0;
    unlink(WAIT_FILE);

    return;
}

/* Check for the wait file. If present, wait.
 * Works as a simple inter process lock (only the main
 * process is allowed to lock).
 */
#ifdef WIN32

void loop_check(bool (*fn_ptr)()) {
    while (1) {
        if (!__wait_lock || (fn_ptr && fn_ptr())) {
            break;
        }

        /* Sleep LOCK_LOOP seconds and check if lock is gone */
        sleep(LOCK_LOOP);
    }
}

void os_wait_primitive(bool (*fn_ptr)()) {
    static int just_unlocked = 0;

    if (!__wait_lock) {
        just_unlocked = 1;
        return;
    }

    /* Wait until the lock is gone */

    if (just_unlocked) {
        mwarn(WAITING_MSG);
    } else {
        mdebug1(WAITING_MSG);
    }

    loop_check(fn_ptr);

    if (just_unlocked) {
        minfo(WAITING_FREE);
    } else {
        mdebug1(WAITING_FREE);
    }

    just_unlocked = 1;

    return;

}

#else /* !WIN32 */

void loop_check(struct stat *file_status, bool (*fn_ptr)()) {
    while (1) {
        if (w_stat(WAIT_FILE, file_status) == -1 || (fn_ptr && fn_ptr())) {
            break;
        }
        /* Sleep LOCK_LOOP seconds and check if lock is gone */
        sleep(LOCK_LOOP);
    }
}

void os_wait_primitive(bool (*fn_ptr)()) {
    struct stat file_status;
    static atomic_int_t just_unlocked = ATOMIC_INT_INITIALIZER(0);

    /* If the wait file is not present, keep going */
    if (w_stat(WAIT_FILE, &file_status) == -1) {
        atomic_int_set(&just_unlocked, 1);
        return;
    }

    /* Wait until the lock is gone */
    if (atomic_int_get(&just_unlocked) == 1){
        mwarn(WAITING_MSG);
    } else {
        mdebug1(WAITING_MSG);
    }

    loop_check(&file_status, fn_ptr);

    if (atomic_int_get(&just_unlocked) == 1) {
        minfo(WAITING_FREE);
    } else {
        mdebug1(WAITING_FREE);
    }

    atomic_int_set(&just_unlocked, 1);

    return;
}

#endif /* !WIN32 */

void os_wait() {
    os_wait_primitive(NULL);
}

void os_wait_predicate(bool (*fn_ptr)()) {
    os_wait_primitive(fn_ptr);
}


// Check whether the agent wait mark is on (manager is disconnected)

bool os_iswait() {
#ifndef WIN32
    return IsFile(WAIT_FILE) == 0;
#else
    return __wait_lock;
#endif

}
