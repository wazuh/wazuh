/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef QUEUE_OP_WRAPPERS_H
#define QUEUE_OP_WRAPPERS_H

#include "headers/queue_op.h"

int __wrap_queue_push_ex(w_queue_t * queue, void * data);

int __wrap_queue_full(const w_queue_t * queue);

void * __wrap_queue_pop_ex(w_queue_t * queue);

void * __wrap_queue_pop_ex_timedwait(w_queue_t * queue, const struct timespec * abstime);

#endif
