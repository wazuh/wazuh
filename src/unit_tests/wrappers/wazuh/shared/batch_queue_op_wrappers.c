/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>
#include <time.h>                 /* struct timespec */

#include "batch_queue_op_wrappers.h"

/* ---------------------- init / free / config ---------------------- */

w_rr_queue_t *__wrap_batch_queue_init(size_t max_items_global) {
    check_expected(max_items_global);
    return mock_ptr_type(w_rr_queue_t *);
}

void __wrap_batch_queue_free(w_rr_queue_t *sched) {
    check_expected(sched);
    function_called();
}

void __wrap_batch_queue_set_dispose(w_rr_queue_t *sched, void (*dispose)(void *)) {
    check_expected(sched);
    check_expected_ptr(dispose);
    function_called();
}

void __wrap_batch_queue_set_agent_max(w_rr_queue_t *sched, size_t max_items_per_agent) {
    check_expected(sched);
    check_expected(max_items_per_agent);
    function_called();
}

/* ----------------------------- enqueue ---------------------------- */

int __wrap_batch_queue_enqueue_ex(w_rr_queue_t *sched, const char *agent_key, void *data) {
    check_expected(sched);
    check_expected(agent_key);
    check_expected(data);

    return mock_type(int);
}

/* ----------------------------- drain ------------------------------ */

size_t __wrap_batch_queue_drain_next_ex(w_rr_queue_t *sched,
                                        const struct timespec *abstime,
                                        void (*consume)(void *data, void *user),
                                        void *user,
                                        const char **out_agent_key) {
    check_expected(sched);
    check_expected_ptr(abstime);
    check_expected_ptr(consume);
    check_expected(user);
    check_expected_ptr(out_agent_key);

    if (out_agent_key) {
        const char *out_key = mock_ptr_type(const char *);
        *out_agent_key = out_key;
    }

    return mock_type(size_t);
}

/* ----------------------------- metrics ---------------------------- */

size_t __wrap_batch_queue_ring_size(const w_rr_queue_t *sched) {
    check_expected(sched);
    return mock_type(size_t);
}

int __wrap_batch_queue_empty(const w_rr_queue_t *sched) {
    check_expected(sched);
    return mock_type(int);
}

size_t __wrap_batch_queue_size(const w_rr_queue_t *sched) {
    check_expected(sched);
    return mock_type(size_t);
}

size_t __wrap_batch_queue_agent_size(w_rr_queue_t *sched, const char *agent_key) {
    check_expected(sched);
    check_expected(agent_key);  /* expect_string/expect_any */
    return mock_type(size_t);
}

/* ----------------------------- drop ------------------------------- */

int __wrap_batch_queue_drop_agent(w_rr_queue_t *sched, const char *agent_key) {
    check_expected(sched);
    check_expected(agent_key);
    return mock_type(int);
}
