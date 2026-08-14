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

#include "indexed_queue_op.h"

void* __wrap_indexed_queue_pop_ex(w_indexed_queue_t* queue);

#endif
