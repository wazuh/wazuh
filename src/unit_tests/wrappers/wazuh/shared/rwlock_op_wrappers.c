/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "rwlock_op_wrappers.h"

void __wrap_rwlock_lock_read(rwlock_t * rwlock) {
    (void)rwlock;
    function_called();
}

void __wrap_rwlock_lock_write(rwlock_t * rwlock) {
    (void)rwlock;
    function_called();
}

void __wrap_rwlock_unlock(rwlock_t * rwlock) {
    (void)rwlock;
    function_called();
}
