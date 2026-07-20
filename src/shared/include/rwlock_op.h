/**
 * @file rwlock_op.h
 * @brief Read-write lock library declaration
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

#ifndef RWLOCK_OP_H
#define RWLOCK_OP_H

#include <pthread.h>

#define RWLOCK_LOCK_READ(rwlock, stmt) rwlock_lock_read(rwlock); stmt; rwlock_unlock(rwlock);
#define RWLOCK_LOCK_WRITE(rwlock, stmt) rwlock_lock_write(rwlock); stmt; rwlock_unlock(rwlock);

/**
 * @brief Read-write lock
 *
 * This structure provides a read-write lock with FIFO queueing.
 */
typedef struct {
    pthread_mutex_t mutex;
    pthread_rwlock_t rwlock;
} rwlock_t;

/**
 * @brief Initialize a read_write lock.
 *
 * @param rwlock Pointer to a rwlock_t structure.
 * @post Dies with critical error if the lock is initialized twice.
 */
void rwlock_init(rwlock_t * rwlock);

/**
 * @brief Lock a read-write lock for reading.
 *
 * @param rwlock Pointer to a rwlock_t structure.
 * @post Dies with critical error if a deadlock is detected.
 */
void rwlock_lock_read(rwlock_t * rwlock);

/**
 * @brief Lock a read-write lock for writing.
 *
 * @param rwlock Pointer to a rwlock_t structure.
 * @post Dies with critical error if a deadlock is detected.
 */
void rwlock_lock_write(rwlock_t * rwlock);

/**
 * @brief Unlock a read-write lock.
 *
 * @param rwlock Pointer to a rwlock_t structure.
 * @post Dies with critical error if the current thread does not lock this lock.
 */
void rwlock_unlock(rwlock_t * rwlock);

/**
 * @brief Free a read-write lock.
 *
 * @param rwlock Pointer to a rwlock_t structure.
 * @post Dies with critical error if the lock is currently locked.
 */
void rwlock_destroy(rwlock_t * rwlock);

#endif
