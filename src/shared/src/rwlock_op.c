/**
 * @file rwlock_op.c
 * @brief Read-write lock library definition
 * @date 2022-09-02
 *
 * @copyright Copyright (C) 2015 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>

// Initialize a read_write lock.

void rwlock_init(rwlock_t * rwlock) {
    errno = pthread_mutex_init(&rwlock->mutex, NULL);
    if (errno != 0) {
        merror_exit(MUTEX_INIT, strerror(errno), errno);
    }

    errno = pthread_rwlock_init(&rwlock->rwlock, NULL);
    if (errno != 0) {
        merror_exit(RWLOCK_INIT, strerror(errno), errno);
    }
}

// Lock a read-write lock for reading.

void rwlock_lock_read(rwlock_t * rwlock) {
    errno = pthread_mutex_lock(&rwlock->mutex);
    if (errno != 0) {
        merror_exit(MUTEX_LOCK, strerror(errno), errno);
    }

    errno = pthread_rwlock_rdlock(&rwlock->rwlock);
    if (errno != 0) {
        merror_exit(RWLOCK_LOCK_RD, strerror(errno), errno);
    }

    errno = pthread_mutex_unlock(&rwlock->mutex);
    if (errno != 0) {
        merror_exit(MUTEX_UNLOCK, strerror(errno), errno);
    }
}

// Lock a read-write lock for writing.

void rwlock_lock_write(rwlock_t * rwlock) {
    errno = pthread_mutex_lock(&rwlock->mutex);
    if (errno != 0) {
        merror_exit(MUTEX_LOCK, strerror(errno), errno);
    }

    errno = pthread_rwlock_wrlock(&rwlock->rwlock);
    if (errno != 0) {
        merror_exit(RWLOCK_LOCK_WR, strerror(errno), errno);
    }

    errno = pthread_mutex_unlock(&rwlock->mutex);
    if (errno != 0) {
        merror_exit(MUTEX_UNLOCK, strerror(errno), errno);
    }
}

// Unlock a read-write lock.

void rwlock_unlock(rwlock_t * rwlock) {
    errno = pthread_rwlock_unlock(&rwlock->rwlock);
    if (errno != 0) {
        merror_exit(RWLOCK_UNLOCK, strerror(errno), errno);
    }
}

// Free a read-write lock.

void rwlock_destroy(rwlock_t * rwlock) {
    errno = pthread_mutex_destroy(&rwlock->mutex);
    if (errno != 0) {
        merror_exit(MUTEX_DESTROY, strerror(errno), errno);
    }

    errno = pthread_rwlock_destroy(&rwlock->rwlock);
    if (errno != 0) {
        merror_exit(RWLOCK_DESTROY, strerror(errno), errno);
    }
}
