/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef INDEXED_QUEUE_OP_WRAPPERS_H
#define INDEXED_QUEUE_OP_WRAPPERS_H

#include "../../../../headers/indexed_queue_op.h"

w_indexed_queue_t *__wrap_indexed_queue_init(size_t max_size);

void __wrap_indexed_queue_free(w_indexed_queue_t *queue);

int __wrap_indexed_queue_push_ex(w_indexed_queue_t *queue, const char *key, void *data);

int __wrap_indexed_queue_upsert_ex(w_indexed_queue_t *queue, const char *key, void *data);

void *__wrap_indexed_queue_get_ex(w_indexed_queue_t *queue, const char *key);

void *__wrap_indexed_queue_pop_ex(w_indexed_queue_t *queue);

void *__wrap_indexed_queue_pop_ex_timedwait(w_indexed_queue_t *queue, const struct timespec *abstime);

int __wrap_indexed_queue_delete_ex(w_indexed_queue_t *queue, const char *key);

void *__wrap_indexed_queue_update_ex(w_indexed_queue_t *queue, const char *key, void *data);

#endif
