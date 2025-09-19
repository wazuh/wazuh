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

#include "../../headers/batch_queue_op.h"

w_rr_queue_t *__wrap_batch_queue_init(size_t max_items_global);

void __wrap_batch_queue_free(w_rr_queue_t *sched);

void __wrap_batch_queue_set_dispose(w_rr_queue_t *sched, void (*dispose)(void *));

void __wrap_batch_queue_set_agent_max(w_rr_queue_t *sched, size_t max_items_per_agent);

/* ----------------------------- enqueue ---------------------------- */

int __wrap_batch_queue_enqueue_ex(w_rr_queue_t *sched, const char *agent_key, void *data);

size_t __wrap_batch_queue_drain_next_ex(w_rr_queue_t *sched,
                                        const struct timespec *abstime,
                                        void (*consume)(void *data, void *user),
                                        void *user,
                                        const char **out_agent_key);

/* ----------------------------- metrics ---------------------------- */

size_t __wrap_batch_queue_ring_size(const w_rr_queue_t *sched);

int __wrap_batch_queue_empty(const w_rr_queue_t *sched);

size_t __wrap_batch_queue_size(const w_rr_queue_t *sched);

size_t __wrap_batch_queue_agent_size(w_rr_queue_t *sched, const char *agent_key);

/* ----------------------------- drop ------------------------------- */

int __wrap_batch_queue_drop_agent(w_rr_queue_t *sched, const char *agent_key);


#endif //BATCH_QUEUE_OP_WRAPPERS_H
