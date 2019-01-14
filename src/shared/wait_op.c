/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

    if (isChroot()) {
        fp = fopen(WAIT_FILE, "w");
    } else {
        fp = fopen(WAIT_FILE_PATH, "w");
    }

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

    if (isChroot()) {
        unlink(WAIT_FILE);
    } else {
        unlink(WAIT_FILE_PATH);
    }
    return;
}

/* Check for the wait file. If present, wait.
 * Works as a simple inter process lock (only the main
 * process is allowed to lock).
 */
#ifdef WIN32
void os_wait()
{
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
    while (1) {
        if (!__wait_lock) {
            break;
        }

        /* Sleep LOCK_LOOP seconds and check if lock is gone */
        sleep(LOCK_LOOP);
    }

    if (just_unlocked) {
        minfo(WAITING_FREE);
    } else {
        mdebug1(WAITING_FREE);
    }

    just_unlocked = 1;

    return;

}

#else /* !WIN32 */

void os_wait()
{
    struct stat file_status;
    static int just_unlocked = 0;

    /* If the wait file is not present, keep going */
    if (isChroot()) {
        if (stat(WAIT_FILE, &file_status) == -1) {
            just_unlocked = 1;
            return;
        }
    } else {
        if (stat(WAIT_FILE_PATH, &file_status) == -1) {
            just_unlocked = 1;
            return;
        }
    }

    /* Wait until the lock is gone */
    if (just_unlocked){
        mwarn(WAITING_MSG);
    } else {
        mdebug1(WAITING_MSG);
    }

    while (1) {
        if (isChroot()) {
            if (stat(WAIT_FILE, &file_status) == -1) {
                break;
            }
        } else {
            if (stat(WAIT_FILE_PATH, &file_status) == -1) {
                break;
            }
        }

        /* Sleep LOCK_LOOP seconds and check if lock is gone */
        sleep(LOCK_LOOP);
    }

    if (just_unlocked) {
        minfo(WAITING_FREE);
    } else {
        mdebug1(WAITING_FREE);
    }

    just_unlocked = 1;

    return;
}

#endif /* !WIN32 */
