/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifndef ATOMIC_WRAPPERS
#define ATOMIC_WRAPPERS

#include "../../../../headers/atomic.h"

int __wrap_atomic_int_get(atomic_int_t *atomic);

void __wrap_atomic_int_set(atomic_int_t *atomic, __attribute__((unused)) int value);

int __wrap_atomic_int_inc(atomic_int_t *atomic);

int __wrap_atomic_int_dec(atomic_int_t *atomic);

#endif //ATOMIC_WRAPPERS
