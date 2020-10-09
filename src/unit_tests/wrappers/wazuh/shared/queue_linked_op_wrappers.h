/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef LINKED_QUEUE_OP_WRAPPERS_H
#define LINKED_QUEUE_OP_WRAPPERS_H

#include "headers/shared.h"
#include "headers/queue_linked_op.h"

w_linked_queue_node_t * __wrap_linked_queue_push_ex(w_linked_queue_t * queue, void * data);

void * __wrap_linked_queue_pop_ex(w_linked_queue_t * queue);
#endif
