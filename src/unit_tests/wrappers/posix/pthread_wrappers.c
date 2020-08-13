/* Copyright (C) 2015-2020, Wazuh Inc.
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
#include <cmocka.h>


int __wrap_pthread_mutex_lock(__attribute__((unused)) pthread_mutex_t *x) {
    function_called();
    return 0;
}

int __wrap_pthread_mutex_unlock(__attribute__((unused)) pthread_mutex_t *x) {
    function_called();
    return 0;
}
