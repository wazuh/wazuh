/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "indexed_queue_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

w_indexed_queue_t *__wrap_indexed_queue_init(size_t max_size) {
    check_expected(max_size);
    return mock_type(w_indexed_queue_t *);
}

void __wrap_indexed_queue_free(w_indexed_queue_t *queue) {
    check_expected_ptr(queue);
}

int __wrap_indexed_queue_push_ex(w_indexed_queue_t *queue, const char *key, void *data) {
    check_expected_ptr(queue);
    check_expected_ptr(key);
    check_expected_ptr(data);
    return mock_type(int);
}

int __wrap_indexed_queue_upsert_ex(w_indexed_queue_t *queue, const char *key, void *data) {
    check_expected_ptr(queue);
    check_expected_ptr(key);
    check_expected_ptr(data);
    return mock_type(int);
}

void *__wrap_indexed_queue_get_ex(w_indexed_queue_t *queue, const char *key) {
    check_expected_ptr(queue);
    check_expected_ptr(key);
    return mock_type(void *);
}

void *__wrap_indexed_queue_pop_ex(w_indexed_queue_t *queue) {
    check_expected_ptr(queue);
    return mock_type(void *);
}

void *__wrap_indexed_queue_pop_ex_timedwait(w_indexed_queue_t *queue, const struct timespec *abstime) {
    check_expected_ptr(queue);
    check_expected_ptr(abstime);
    return mock_type(void *);
}

int __wrap_indexed_queue_delete_ex(w_indexed_queue_t *queue, const char *key) {
    check_expected_ptr(queue);
    check_expected_ptr(key);
    return mock_type(int);
}

void *__wrap_indexed_queue_update_ex(w_indexed_queue_t *queue, const char *key, void *data) {
    check_expected_ptr(queue);
    check_expected_ptr(key);
    check_expected_ptr(data);
    return mock_type(void *);
}
