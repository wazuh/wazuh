/*
 * Copyright (C) 2015, Wazuh Inc.
 * December 18, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

int atomic_int_get(atomic_int_t *atomic) {
    assert(atomic != NULL);

    int retval = 0;

    w_mutex_lock(&atomic->mutex);
    retval = atomic->data;
    w_mutex_unlock(&atomic->mutex);

    return retval;
}

void atomic_int_set(atomic_int_t *atomic, int value) {
    assert(atomic != NULL);

    w_mutex_lock(&atomic->mutex);
    atomic->data = value;
    w_mutex_unlock(&atomic->mutex);
}

int atomic_int_inc(atomic_int_t *atomic) {
    assert(atomic != NULL);

    int retval = 0;
    w_mutex_lock(&atomic->mutex);
    atomic->data++;
    retval = atomic->data;
    w_mutex_unlock(&atomic->mutex);
    return retval;
};

int atomic_int_dec(atomic_int_t *atomic) {
    assert(atomic != NULL);

    int retval = 0;
    w_mutex_lock(&atomic->mutex);
    atomic->data--;
    retval = atomic->data;
    w_mutex_unlock(&atomic->mutex);
    return retval;
}
