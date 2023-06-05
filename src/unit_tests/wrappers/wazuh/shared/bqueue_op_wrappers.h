/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef BQUEUE_OP_WRAPPERS_H
#define BQUEUE_OP_WRAPPERS_H

#include "../../../../headers/shared.h"
#include "../../../../headers/bqueue_op.h"

int __wrap_bqueue_push(bqueue_t * queue, const void * data, size_t length, unsigned flags);

size_t __wrap_bqueue_peek(bqueue_t * queue, char * buffer, size_t length, unsigned flags);

int __wrap_bqueue_drop(bqueue_t * queue, size_t length);

void __wrap_bqueue_clear(bqueue_t * queue);

size_t __wrap_bqueue_used(bqueue_t * queue);

#endif
