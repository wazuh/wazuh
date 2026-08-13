/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef BATCH_QUEUE_OP_WRAPPERS_H
#define BATCH_QUEUE_OP_WRAPPERS_H

#include "batch_queue_op.h"

/* ----------------------------- enqueue ---------------------------- */

int __wrap_batch_queue_enqueue_ex(w_rr_queue_t* sched, const char* agent_key, void* data);

#endif // BATCH_QUEUE_OP_WRAPPERS_H
