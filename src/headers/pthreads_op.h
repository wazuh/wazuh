/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef PTHREADS_OP_H
#define PTHREADS_OP_H

#define w_create_thread(x, y) if (CreateThread((void * (*) (void *))x, y)) exit(1)
#define w_mutex_init(x, y) { int error = pthread_mutex_init(x, y); if (error) merror_exit("At pthread_mutex_init(): %s", strerror(error)); }
#define w_cond_init(x, y) { int error = pthread_cond_init(x, y); if (error) merror_exit("At pthread_cond_init(): %s", strerror(error)); }
#define w_mutex_lock(x) { int error = pthread_mutex_lock(x); if (error) merror_exit("At pthread_mutex_lock(): %s", strerror(error)); }
#define w_mutex_unlock(x) { int error = pthread_mutex_unlock(x); if (error) merror_exit("At pthread_mutex_unlock(): %s", strerror(error)); }
#define w_cond_wait(x, y) { int error = pthread_cond_wait(x, y); if (error) merror_exit("At pthread_cond_wait(): %s", strerror(error)); }
#define w_cond_signal(x) { int error = pthread_cond_signal(x); if (error) merror_exit("At pthread_cond_signal(): %s", strerror(error)); }

#ifndef WIN32
int CreateThread(void * (*function_pointer)(void *), void * data) __attribute__((nonnull(1)));
#endif

#endif
