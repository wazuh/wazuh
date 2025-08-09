/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "pthread_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

void (*pthread_callback_ptr)(void) = NULL;

int __wrap_pthread_mutex_lock(__attribute__((unused)) pthread_mutex_t *x) {
    function_called();
    return 0;
}

int __wrap_pthread_mutex_unlock(__attribute__((unused)) pthread_mutex_t *x) {
    function_called();
    return 0;
}

int __wrap_pthread_rwlock_rdlock(__attribute__((unused)) pthread_rwlock_t *rwlock) {
    function_called();
    return 0;
}

int __wrap_pthread_rwlock_wrlock(__attribute__((unused)) pthread_rwlock_t *rwlock) {
    function_called();
    return 0;
}

int __wrap_pthread_rwlock_unlock(__attribute__((unused)) pthread_rwlock_t *rwlock) {
    function_called();
    return 0;
}

int __wrap_pthread_exit() {
    return mock();
}

int __wrap_pthread_cond_wait(pthread_cond_t *cond,pthread_mutex_t *mutex) {
    check_expected_ptr(cond);
    check_expected_ptr(mutex);
    // callback function to avoid infinite loops when testing
    if (pthread_callback_ptr)
        pthread_callback_ptr();
    return 0;
}

int __wrap_pthread_cond_signal(pthread_cond_t *cond) {
    check_expected_ptr(cond);
    return 0;
}
