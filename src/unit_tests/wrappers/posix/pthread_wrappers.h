/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef PTHREAD_WRAPPERS_H
#define PTHREAD_WRAPPERS_H

#include <pthread.h>

int __wrap_pthread_mutex_lock(pthread_mutex_t *x);

int __wrap_pthread_mutex_unlock(pthread_mutex_t *x);

int __wrap_pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);

int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);

int __wrap_pthread_rwlock_unlock(pthread_rwlock_t *rwlock);

int __wrap_pthread_exit();

int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

int __wrap_pthread_cond_signal(pthread_cond_t *cond);

extern void (*pthread_callback_ptr)(void);

#endif
