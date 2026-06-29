/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../wrappers/posix/pthread_wrappers.h"  // <- mocks estrictos de Wazuh

#include "shared.h"
#include "batch_queue_op.h"

/* =============================== Test Helpers =============================== */

typedef struct { int v; } payload_t;

static payload_t *make_payload(int v) {
    payload_t *p = (payload_t *)malloc(sizeof(payload_t));
    assert_non_null(p);
    p->v = v;
    return p;
}


/* Dispose hook that counts frees */
static int g_disposed = 0;
static void test_dispose(void *x) {
    if (x) { ++g_disposed; free(x); }
}

/* Consumer that accumulates values */
#define MAX_CONSUMED 128
static int consumed_vals[MAX_CONSUMED];
static size_t consumed_n;
static void reset_consumed(void) {
    consumed_n = 0;
    memset(consumed_vals, 0, sizeof(consumed_vals));
}
static void consumer_append(void *data, void *user) {
    (void)user;
    assert_true(consumed_n < MAX_CONSUMED);
    payload_t *p = (payload_t *)data;
    consumed_vals[consumed_n++] = p->v;
    free(p);
}

/* To “wake up” from the wrapper in cond_wait */
extern void (*pthread_callback_ptr)(void);
static w_rr_queue_t *g_sched = NULL;

static void callback_enqueue_A(void) {
    assert_non_null(g_sched);
    payload_t *p = make_payload(42);
    /* first enqueue must signal */
    expect_value(__wrap_pthread_cond_signal, cond, &g_sched->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(g_sched, "agent/A", p));
}

/* ============================ Setup / Teardown ============================= */

static int setup_sched(void **state) {
    w_rr_queue_t *q = batch_queue_init(/*max_items_global=*/0);
    assert_non_null(q);
    *state = q;
    g_sched = q;
    g_disposed = 0;
    batch_queue_set_dispose(q, test_dispose);
    reset_consumed();
    return 0;
}

static int teardown_sched(void **state) {
    w_rr_queue_t *q = (w_rr_queue_t *)*state;
    batch_queue_free(q);
    g_sched = NULL;
    return 0;
}

/* ================================ Test Cases =============================== */

/*
 * Verifies that a freshly initialized scheduler is empty:
 * - ring is empty
 * - global size is 0
 * - ring slot count is 0
 */
static void test_init_free_basic(void **state) {
    w_rr_queue_t *q = (w_rr_queue_t *)*state;
    assert_int_equal(1, batch_queue_empty(q));
    assert_int_equal(0, (int)batch_queue_size(q));
    assert_int_equal(0, (int)batch_queue_ring_size(q));
}

/*
 * Enqueueing the first item for an agent:
 * - emits a condition signal
 * - creates a slot and inserts it into the ring
 * - per-agent and global sizes become 1
 */
static void test_enqueue_creates_slot_and_ring(void **state) {
    w_rr_queue_t *q = (w_rr_queue_t *)*state;

    /* first insert for the agent → signal */
    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_payload(7)));

    assert_int_equal(0, batch_queue_empty(q));
    assert_int_equal(1, (int)batch_queue_ring_size(q));
    assert_int_equal(1, (int)batch_queue_agent_size(q, "agent/A"));
    assert_int_equal(1, (int)batch_queue_size(q));
}

/*
 * Two agents each enqueue one item:
 * - ring size becomes 2
 * - draining twice processes one item per agent in round-robin
 * - after draining both, the scheduler is empty (ring size and global size are 0)
 */
static void test_enqueue_two_agents_round_robin_and_drain(void **state) {
    w_rr_queue_t *q = (w_rr_queue_t *)*state;

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_payload(1)));

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/B", make_payload(2)));

    assert_int_equal(2, (int)batch_queue_ring_size(q));

    const char *agent = NULL;
    reset_consumed();

    size_t n1 = batch_queue_drain_next_ex(q, NULL, consumer_append, NULL, &agent);
    assert_int_equal(1, (int)n1);
    assert_non_null(agent);

    size_t n2 = batch_queue_drain_next_ex(q, NULL, consumer_append, NULL, &agent);
    assert_int_equal(1, (int)n2);
    assert_non_null(agent);

    assert_int_equal(1, batch_queue_empty(q));
    assert_int_equal(0, (int)batch_queue_ring_size(q));
    assert_int_equal(0, (int)batch_queue_size(q));
}

/*
 * Per-agent capacity:
 * - set cap to 1 for agent/C
 * - first enqueue succeeds and signals
 * - second enqueue is rejected with -ENOSPC and the payload is disposed
 * - draining consumes the single allowed item
 */
static void test_per_agent_cap_and_dispose(void **state) {
    w_rr_queue_t *q = (w_rr_queue_t *)*state;
    g_disposed = 0;
    batch_queue_set_dispose(q, test_dispose);
    batch_queue_set_agent_max(q, 1);

    /* first insert for the agent → signal */
    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/C", make_payload(10)));

    /* this one is rejected due to per-agent cap → no signal */
    int rc = batch_queue_enqueue_ex(q, "agent/C", make_payload(11));
    assert_int_equal(-ENOSPC, rc);
    assert_int_equal(1, g_disposed);

    const char *agent = NULL;
    size_t n = batch_queue_drain_next_ex(q, NULL, consumer_append, NULL, &agent);
    assert_int_equal(1, (int)n);
    assert_string_equal(agent, "agent/C");
}

/*
 * Global capacity:
 * - scheduler with global cap = 2
 * - first two enqueues succeed and signal
 * - third enqueue is rejected with -ENOSPC (no signal expected)
 */
static void test_global_cap_rejects_extra(void **state) {
    (void)state;
    w_rr_queue_t *q = batch_queue_init(/*max_items_global=*/2);
    assert_non_null(q);
    batch_queue_set_dispose(q, test_dispose);

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_payload(1)));

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/B", make_payload(2)));

    /* exceeds global cap → no signal, returns -ENOSPC */
    int rc = batch_queue_enqueue_ex(q, "agent/C", make_payload(3));
    assert_int_equal(-ENOSPC, rc);

    batch_queue_free(q);
}

/*
 * Dropping an agent:
 * - enqueue one item for agent/Z (signals, in ring)
 * - drop removes its slot, disposes pending item
 * - ring and per-agent sizes go back to 0
 */
static void test_drop_agent_removes_and_frees(void **state) {
    w_rr_queue_t *q = (w_rr_queue_t *)*state;
    g_disposed = 0;

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/Z", make_payload(100)));

    assert_int_equal(1, (int)batch_queue_agent_size(q, "agent/Z"));
    assert_int_equal(1, (int)batch_queue_ring_size(q));

    int dropped = batch_queue_drop_agent(q, "agent/Z");
    assert_int_equal(1, dropped);
    assert_int_equal(1, g_disposed);

    assert_int_equal(0, (int)batch_queue_agent_size(q, "agent/Z"));
    assert_int_equal(0, (int)batch_queue_ring_size(q));
}

/*
 * Invalid argument handling:
 * - NULL scheduler returns -EINVAL (test frees the payload)
 * - NULL agent key returns -EINVAL (test frees the payload)
 * - NULL data returns -EINVAL (no allocation to free)
 */
static void test_enqueue_invalid_args(void **state) {
    w_rr_queue_t *q = (w_rr_queue_t *)*state;

    payload_t *p1 = make_payload(1);
    assert_int_equal(-EINVAL, batch_queue_enqueue_ex(NULL, "x", p1));
    free(p1);   // free because the function returned -EINVAL

    payload_t *p2 = make_payload(1);
    assert_int_equal(-EINVAL, batch_queue_enqueue_ex(q, NULL, p2));
    free(p2);   // idem

    // this one allocates nothing: data == NULL
    assert_int_equal(-EINVAL, batch_queue_enqueue_ex(q, "x", NULL));
}

/*
 * Regression check: after draining the last remaining slot,
 * the ring slot counter should be 0 (i.e., ring truly empty).
 */
static void test_ring_slots_zero_after_last_removal(void **state) {
    w_rr_queue_t *q = (w_rr_queue_t *)*state;

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/solo", make_payload(1)));
    assert_int_equal(1, (int)batch_queue_ring_size(q));

    (void)batch_queue_drain_next_ex(q, NULL, consumer_append, NULL, NULL);

    assert_int_equal(0, (int)batch_queue_ring_size(q));
}

/* ====================== Byte-limit helpers ====================== */

typedef struct {
    int  v;
    size_t sz; ///< Byte size reported to the scheduler
} sized_payload_t;

static sized_payload_t *make_sized(int v, size_t sz) {
    sized_payload_t *p = (sized_payload_t *)malloc(sizeof(sized_payload_t));
    assert_non_null(p);
    p->v  = v;
    p->sz = sz;
    return p;
}

static size_t get_bytes_cb(const void *data) {
    const sized_payload_t *p = (const sized_payload_t *)data;
    return p ? p->sz : 0;
}

static void dispose_sized(void *x) {
    if (x) { ++g_disposed; free(x); }
}

static void consumer_sized(void *data, void *user) {
    (void)user;
    assert_true(consumed_n < MAX_CONSUMED);
    sized_payload_t *p = (sized_payload_t *)data;
    consumed_vals[consumed_n++] = p->v;
    free(p);
}

/* ====================== Byte-limit test cases ====================== */

/*
 * Byte limit reached:
 * - queue created with max_bytes = 100
 * - first two items (40 + 60 bytes) fit exactly
 * - third item is rejected with -ENOSPC and disposed
 * - batch_queue_bytes() reflects the accumulated usage
 */
static void test_byte_limit_global_rejects_extra(void **state) {
    (void)state;

    w_rr_queue_t *q = batch_queue_init(/*max_items_global=*/0);
    assert_non_null(q);
    batch_queue_set_dispose(q, dispose_sized);
    batch_queue_set_get_item_bytes(q, get_bytes_cb);
    batch_queue_set_bytes_limit(q, 100);

    g_disposed = 0;

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_sized(1, 40)));
    assert_int_equal(40, (int)batch_queue_bytes(q));

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/B", make_sized(2, 60)));
    assert_int_equal(100, (int)batch_queue_bytes(q));

    /* Third item exceeds byte quota → disposed, no signal */
    int rc = batch_queue_enqueue_ex(q, "agent/C", make_sized(3, 1));
    assert_int_equal(-ENOSPC, rc);
    assert_int_equal(1, g_disposed);
    assert_int_equal(100, (int)batch_queue_bytes(q)); /* unchanged */

    batch_queue_free(q);
}

/*
 * Oversized individual event:
 * - single item whose byte size exceeds the configured limit is rejected
 * - byte counter remains 0 after rejection
 */
static void test_byte_limit_oversized_item_rejected(void **state) {
    (void)state;

    w_rr_queue_t *q = batch_queue_init(/*max_items_global=*/0);
    assert_non_null(q);
    batch_queue_set_dispose(q, dispose_sized);
    batch_queue_set_get_item_bytes(q, get_bytes_cb);
    batch_queue_set_bytes_limit(q, 50);

    g_disposed = 0;

    /* Item of 51 bytes is larger than the limit (50) → rejected immediately */
    int rc = batch_queue_enqueue_ex(q, "agent/A", make_sized(1, 51));
    assert_int_equal(-ENOSPC, rc);
    assert_int_equal(1, g_disposed);
    assert_int_equal(0, (int)batch_queue_bytes(q));

    batch_queue_free(q);
}

/*
 * Byte quota recovery after dequeue:
 * - fill the queue to its byte limit
 * - drain one item to free its bytes
 * - a previously-rejected item can now be enqueued
 */
static void test_byte_limit_recovers_after_drain(void **state) {
    (void)state;

    w_rr_queue_t *q = batch_queue_init(/*max_items_global=*/0);
    assert_non_null(q);
    batch_queue_set_dispose(q, dispose_sized);
    batch_queue_set_get_item_bytes(q, get_bytes_cb);
    batch_queue_set_bytes_limit(q, 100);

    g_disposed = 0;
    reset_consumed();

    /* Fill exactly to the limit */
    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_sized(1, 60)));
    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/B", make_sized(2, 40)));
    assert_int_equal(100, (int)batch_queue_bytes(q));

    /* Byte quota full — 41-byte item cannot fit */
    int rc = batch_queue_enqueue_ex(q, "agent/C", make_sized(3, 41));
    assert_int_equal(-ENOSPC, rc);
    assert_int_equal(1, g_disposed);

    /* Drain agent/A (60 bytes) */
    const char *agent = NULL;
    (void)batch_queue_drain_next_ex(q, NULL, consumer_sized, NULL, &agent);
    assert_int_equal(40, (int)batch_queue_bytes(q)); /* 100 - 60 */

    /* Now the 41-byte item fits */
    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/C", make_sized(4, 41)));
    assert_int_equal(81, (int)batch_queue_bytes(q)); /* 40 + 41 */

    batch_queue_free(q);
}

/*
 * Drop-agent adjusts the byte counter:
 * - enqueue one item for an agent
 * - drop the agent; bytes_global must return to 0
 */
static void test_byte_limit_drop_agent_releases_bytes(void **state) {
    (void)state;

    w_rr_queue_t *q = batch_queue_init(/*max_items_global=*/0);
    assert_non_null(q);
    batch_queue_set_dispose(q, dispose_sized);
    batch_queue_set_get_item_bytes(q, get_bytes_cb);
    batch_queue_set_bytes_limit(q, 200);

    g_disposed = 0;

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/Z", make_sized(7, 75)));
    assert_int_equal(75, (int)batch_queue_bytes(q));

    assert_int_equal(1, batch_queue_drop_agent(q, "agent/Z"));
    assert_int_equal(1, g_disposed);
    assert_int_equal(0, (int)batch_queue_bytes(q));

    batch_queue_free(q);
}

/*
 * Byte limit and item-count limit coexist:
 * - scheduler created with max_items_global = 2 AND max_bytes = 100
 * - item-count limit triggers before byte limit is exhausted
 */
static void test_byte_limit_and_item_count_limit_coexist(void **state) {
    (void)state;

    w_rr_queue_t *q = batch_queue_init(/*max_items_global=*/2);
    assert_non_null(q);
    batch_queue_set_dispose(q, dispose_sized);
    batch_queue_set_get_item_bytes(q, get_bytes_cb);
    batch_queue_set_bytes_limit(q, 100);

    g_disposed = 0;

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_sized(1, 10)));
    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/B", make_sized(2, 10)));

    /* Item count (2) is reached; byte quota (20/100) is NOT exhausted */
    int rc = batch_queue_enqueue_ex(q, "agent/C", make_sized(3, 5));
    assert_int_equal(-ENOSPC, rc);
    assert_int_equal(1, g_disposed);
    assert_int_equal(20, (int)batch_queue_bytes(q)); /* unchanged */

    batch_queue_free(q);
}

/*
 * Byte counter stays consistent across many enqueue/drop cycles (simulates
 * the producer/consumer pattern that real concurrent code would exercise):
 * - enqueue N items for two agents, drop one agent, drain the other
 * - after all operations the byte counter must reach 0
 *
 * Note: the unit-test framework replaces pthread primitives with no-op stubs
 * so real multi-threaded tests cannot be conducted here.  The interleaving
 * below exercises the atomic byte accounting paths without spawning threads.
 */
static void test_byte_counter_consistent_enqueue_drop_drain(void **state) {
    (void)state;

    w_rr_queue_t *q = batch_queue_init(/*max_items_global=*/0);
    assert_non_null(q);
    batch_queue_set_dispose(q, dispose_sized);
    batch_queue_set_get_item_bytes(q, get_bytes_cb);

    g_disposed = 0;
    reset_consumed();

    /* Enqueue 3 items for agent/A (10 bytes each) and 2 for agent/B (25 bytes each) */
    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_sized(1, 10)));
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_sized(2, 10)));
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/A", make_sized(3, 10)));

    expect_value(__wrap_pthread_cond_signal, cond, &q->any_available);
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/B", make_sized(4, 25)));
    assert_int_equal(0, batch_queue_enqueue_ex(q, "agent/B", make_sized(5, 25)));

    assert_int_equal(80, (int)batch_queue_bytes(q)); /* 3*10 + 2*25 */
    assert_int_equal(5, (int)batch_queue_size(q));

    /* Drop agent/B (2 * 25 = 50 bytes freed) */
    assert_int_equal(1, batch_queue_drop_agent(q, "agent/B"));
    assert_int_equal(2, g_disposed);
    assert_int_equal(30, (int)batch_queue_bytes(q)); /* 80 - 50 */
    assert_int_equal(3, (int)batch_queue_size(q));

    /* Drain agent/A (3 * 10 = 30 bytes freed) */
    size_t drained = batch_queue_drain_next_ex(q, NULL, consumer_sized, NULL, NULL);
    assert_int_equal(3, (int)drained);
    assert_int_equal(0, (int)batch_queue_bytes(q));
    assert_int_equal(0, (int)batch_queue_size(q));

    batch_queue_free(q);
}

/* ================================ Test Suite ================================ */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_init_free_basic, setup_sched, teardown_sched),
        cmocka_unit_test_setup_teardown(test_enqueue_creates_slot_and_ring, setup_sched, teardown_sched),
        cmocka_unit_test_setup_teardown(test_enqueue_two_agents_round_robin_and_drain, setup_sched, teardown_sched),
        cmocka_unit_test_setup_teardown(test_per_agent_cap_and_dispose, setup_sched, teardown_sched),
        cmocka_unit_test(test_global_cap_rejects_extra),
        cmocka_unit_test_setup_teardown(test_drop_agent_removes_and_frees, setup_sched, teardown_sched),
        cmocka_unit_test_setup_teardown(test_enqueue_invalid_args, setup_sched, teardown_sched),
        cmocka_unit_test_setup_teardown(test_ring_slots_zero_after_last_removal, setup_sched, teardown_sched),
        /* Byte-limit tests */
        cmocka_unit_test(test_byte_limit_global_rejects_extra),
        cmocka_unit_test(test_byte_limit_oversized_item_rejected),
        cmocka_unit_test(test_byte_limit_recovers_after_drain),
        cmocka_unit_test(test_byte_limit_drop_agent_releases_bytes),
        cmocka_unit_test(test_byte_limit_and_item_count_limit_coexist),
        cmocka_unit_test(test_byte_counter_consistent_enqueue_drop_drain),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
