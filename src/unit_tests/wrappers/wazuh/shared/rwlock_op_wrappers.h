/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef RWLOCK_OP_WRAPPERS_H
#define RWLOCK_OP_WRAPPERS_H

#include <rwlock_op.h>

void __wrap_rwlock_lock_read(rwlock_t * rwlock);
void __wrap_rwlock_lock_write(rwlock_t * rwlock);
void __wrap_rwlock_unlock(rwlock_t * rwlock);

#endif
