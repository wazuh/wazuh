/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Unit tests for the remoted input message queue (src/remoted/src/queue.c).
 *
 * Covers:
 *  - basic push / pop (event-count limit)
 *  - byte-limit enforcement (queue_max_bytes)
 *  - oversized individual events
 *  - byte quota recovery after dequeue
 *  - concurrent producers and consumer
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "remoted.h"   /* rem_msginit, rem_msgpush, rem_msgpop, rem_msgfree,
                        * rem_set_input_queue_max_bytes */
#include "state.h"     /* rem_inc_recv_discarded */

/* ── Mocks ────────────────────────────────────────────────────────────────── */

/*
 * Atomic counter instead of cmocka's function_called() so that the concurrent
 * test can trigger arbitrary discards (transient retries) without pre-declaring
 * every expected call.
 */
static atomic_int g_discard_count;

void __wrap_rem_inc_recv_discarded(void) {
    atomic_fetch_add(&g_discard_count, 1);
}

/* Suppress debug/warn output */
void __wrap__mdebug2(const char *msg, ...) { (void)msg; }
void __wrap__mwarn(const char *msg, ...)   { (void)msg; }

/* global_counter is referenced by queue.c */
size_t global_counter = 0;

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static struct sockaddr_storage dummy_addr(void) {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    addr.ss_family = AF_INET;
    return addr;
}

/* ── Setup / Teardown ─────────────────────────────────────────────────────── */

static int setup(void **state) {
    (void)state;
    global_counter = 0;
    atomic_store(&g_discard_count, 0);
    /* Re-initialize a small queue (8 slots → fits 7 messages) */
    rem_msginit(8);
    /* Disable the byte limit; individual tests override this */
    rem_set_input_queue_max_bytes(0);
    return 0;
}

static int teardown(void **state) {
    (void)state;
    rem_msgdestroy();
    return 0;
}

/* ── Test cases ───────────────────────────────────────────────────────────── */

/* Basic push and pop without any byte limit */
static void test_basic_push_pop(void **state) {
    (void)state;

    struct sockaddr_storage addr = dummy_addr();
    const char payload[] = "hello";

    int rc = rem_msgpush(payload, sizeof(payload) - 1, &addr, 1);
    assert_int_equal(0, rc);

    message_t *msg = rem_msgpop();
    assert_non_null(msg);
    assert_int_equal((int)(sizeof(payload) - 1), (int)msg->size);
    assert_memory_equal(payload, msg->buffer, msg->size);
    rem_msgfree(msg);

    assert_int_equal(0, atomic_load(&g_discard_count));
}

/* Event-count limit: 8-slot queue holds at most 7 messages */
static void test_event_count_limit(void **state) {
    (void)state;

    struct sockaddr_storage addr = dummy_addr();
    const char payload[] = "x";
    int rc;

    /* Fill 7 slots */
    for (int i = 0; i < 7; i++) {
        rc = rem_msgpush(payload, 1, &addr, 1);
        assert_int_equal(0, rc);
    }

    /* 8th push must fail (queue full) */
    rc = rem_msgpush(payload, 1, &addr, 1);
    assert_int_equal(-1, rc);
    assert_int_equal(1, atomic_load(&g_discard_count));

    /* Drain */
    for (int i = 0; i < 7; i++) {
        message_t *msg = rem_msgpop();
        assert_non_null(msg);
        rem_msgfree(msg);
    }
}

/* Byte limit: quota exhausted → new events are discarded */
static void test_byte_limit_exhausted_discards(void **state) {
    (void)state;

    rem_set_input_queue_max_bytes(20); /* 20-byte total cap */

    struct sockaddr_storage addr = dummy_addr();

    /* 10 bytes → fits */
    int rc = rem_msgpush("0123456789", 10, &addr, 1);
    assert_int_equal(0, rc);

    /* another 10 bytes → exactly fills the quota */
    rc = rem_msgpush("abcdefghij", 10, &addr, 1);
    assert_int_equal(0, rc);

    /* 1 more byte → quota exceeded → discarded */
    rc = rem_msgpush("!", 1, &addr, 1);
    assert_int_equal(-1, rc);
    assert_int_equal(1, atomic_load(&g_discard_count));

    /* Drain */
    for (int i = 0; i < 2; i++) {
        message_t *msg = rem_msgpop();
        assert_non_null(msg);
        rem_msgfree(msg);
    }
}

/* Oversized event: a single message larger than max_bytes is rejected */
static void test_byte_limit_oversized_event_rejected(void **state) {
    (void)state;

    rem_set_input_queue_max_bytes(5); /* only 5-byte cap */

    struct sockaddr_storage addr = dummy_addr();

    /* 6-byte message exceeds the entire limit → rejected */
    int rc = rem_msgpush("123456", 6, &addr, 1);
    assert_int_equal(-1, rc);
    assert_int_equal(1, atomic_load(&g_discard_count));

    /* Queue must still be empty; a small message still fits */
    rc = rem_msgpush("AB", 2, &addr, 1);
    assert_int_equal(0, rc);

    message_t *msg = rem_msgpop();
    assert_non_null(msg);
    assert_int_equal(2, (int)msg->size);
    rem_msgfree(msg);
}

/* Byte quota recovery: after popping an event its bytes are freed */
static void test_byte_limit_recovery_after_dequeue(void **state) {
    (void)state;

    rem_set_input_queue_max_bytes(10);

    struct sockaddr_storage addr = dummy_addr();

    /* Push exactly to the limit */
    assert_int_equal(0, rem_msgpush("1234567890", 10, &addr, 1));

    /* Next push must fail */
    assert_int_equal(-1, rem_msgpush("x", 1, &addr, 1));
    assert_int_equal(1, atomic_load(&g_discard_count));

    /* Pop frees 10 bytes */
    message_t *msg = rem_msgpop();
    assert_non_null(msg);
    rem_msgfree(msg);

    /* Now a 7-byte message fits */
    assert_int_equal(0, rem_msgpush("abcdefg", 7, &addr, 1));

    msg = rem_msgpop();
    assert_non_null(msg);
    assert_int_equal(7, (int)msg->size);
    rem_msgfree(msg);
}

/* ── Concurrent producers / consumer ─────────────────────────────────────── */

#define CONCURRENT_ITEMS   200
#define CONCURRENT_THREADS 4
#define PAYLOAD_SIZE       8
/* Byte cap: holds ~50 messages at a time so producers must retry */
#define CONCURRENT_BYTE_CAP (50 * PAYLOAD_SIZE)

static atomic_int concurrent_produced;
static atomic_int concurrent_consumed;

static void *concurrent_producer(void *arg) {
    (void)arg;
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    addr.ss_family = AF_INET;

    char payload[PAYLOAD_SIZE];
    memset(payload, 'x', PAYLOAD_SIZE);

    for (int i = 0; i < CONCURRENT_ITEMS; i++) {
        int rc;
        /* Retry until accepted; byte or count quota may be temporarily full */
        do {
            rc = rem_msgpush(payload, PAYLOAD_SIZE, &addr, 1);
        } while (rc != 0);
        atomic_fetch_add(&concurrent_produced, 1);
    }
    return NULL;
}

static void *concurrent_consumer(void *arg) {
    int total = *(int *)arg;
    int consumed = 0;
    while (consumed < total) {
        message_t *msg = rem_msgpop();
        if (msg) {
            rem_msgfree(msg);
            consumed++;
            atomic_fetch_add(&concurrent_consumed, 1);
        }
    }
    return NULL;
}

static int setup_concurrent(void **state) {
    (void)state;
    global_counter = 0;
    atomic_store(&g_discard_count, 0);
    atomic_store(&concurrent_produced, 0);
    atomic_store(&concurrent_consumed, 0);
    /* Larger queue to reduce count-limit contention */
    rem_msginit(256);
    rem_set_input_queue_max_bytes(CONCURRENT_BYTE_CAP);
    return 0;
}

static void test_concurrent_producers_consumer(void **state) {
    (void)state;

    int total_expected = CONCURRENT_THREADS * CONCURRENT_ITEMS;

    pthread_t producers[CONCURRENT_THREADS];
    pthread_t consumer;

    pthread_create(&consumer, NULL, concurrent_consumer, &total_expected);
    for (int i = 0; i < CONCURRENT_THREADS; i++) {
        pthread_create(&producers[i], NULL, concurrent_producer, NULL);
    }
    for (int i = 0; i < CONCURRENT_THREADS; i++) {
        pthread_join(producers[i], NULL);
    }
    pthread_join(consumer, NULL);

    assert_int_equal(total_expected, atomic_load(&concurrent_produced));
    assert_int_equal(total_expected, atomic_load(&concurrent_consumed));
}

/* ── Test Suite ───────────────────────────────────────────────────────────── */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_basic_push_pop,                      setup, teardown),
        cmocka_unit_test_setup_teardown(test_event_count_limit,                   setup, teardown),
        cmocka_unit_test_setup_teardown(test_byte_limit_exhausted_discards,       setup, teardown),
        cmocka_unit_test_setup_teardown(test_byte_limit_oversized_event_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(test_byte_limit_recovery_after_dequeue,   setup, teardown),
        cmocka_unit_test_setup_teardown(test_concurrent_producers_consumer, setup_concurrent, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
