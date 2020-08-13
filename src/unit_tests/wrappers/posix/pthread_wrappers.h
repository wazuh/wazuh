/* Copyright (C) 2015-2020, Wazuh Inc.
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

#endif
