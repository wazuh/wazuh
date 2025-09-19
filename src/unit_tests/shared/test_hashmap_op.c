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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "hashmap_op.h"

/* =============================== Test Helpers =============================== */

static int is_pow2(size_t x) { return x && ((x & (x - 1)) == 0); }

static void make_key(char *buf, size_t bufsz, const char *prefix, int i) {
    (void)snprintf(buf, bufsz, "%s%d", prefix, i);
}

/* ================================ Test Cases =============================== */

/*
 * test_init_destroy
 * Ensures hm_init() creates a map with power-of-two capacity, zero size/tombstones,
 * and hm_destroy() clears all internal fields safely.
 */
static void test_init_destroy(void **state) {
    (void)state;
    hashmap_t hm = {0};

    assert_int_equal(0, hm_init(&hm, /*initial_capacity=*/16));
    assert_true(hm.capacity >= 16);
    assert_true(is_pow2(hm.capacity));
    assert_int_equal(0, (int)hm.size);
    assert_int_equal(0, (int)hm.tombstones);

    hm_destroy(&hm);
    assert_null(hm.entries);
    assert_int_equal(0, (int)hm.capacity);
    assert_int_equal(0, (int)hm.size);
    assert_int_equal(0, (int)hm.tombstones);
}

/*
 * test_put_get_update
 * Verifies put() inserts new keys, get() retrieves them, and putting an
 * existing key updates its value without changing the map size.
 */
static void test_put_get_update(void **state) {
    (void)state;
    hashmap_t hm = {0};
    assert_int_equal(0, hm_init(&hm, 16));

    /* Insert new */
    assert_int_equal(0, hm_put(&hm, "alpha", (void *)(uintptr_t)1));
    assert_int_equal(1, (int)hm.size);

    void *out = NULL;
    assert_int_equal(1, hm_get(&hm, "alpha", &out));
    assert_int_equal(1, (int)(uintptr_t)out);

    /* Update existing */
    assert_int_equal(1, hm_put(&hm, "alpha", (void *)(uintptr_t)2));
    assert_int_equal(1, (int)hm.size);  // size unchanged
    out = NULL;
    assert_int_equal(1, hm_get(&hm, "alpha", &out));
    assert_int_equal(2, (int)(uintptr_t)out);

    hm_destroy(&hm);
}

/*
 * test_delete_and_chain_integrity
 * Inserts several keys, deletes one, and confirms:
 *  - size decreases and a tombstone is recorded
 *  - lookups still work across tombstones (deleted key missing, others found).
 */
static void test_delete_and_chain_integrity(void **state) {
    (void)state;
    hashmap_t hm = {0};
    assert_int_equal(0, hm_init(&hm, 16));

    char key[32];
    for (int i = 0; i < 8; ++i) {
        make_key(key, sizeof(key), "k", i);
        assert_int_equal(0, hm_put(&hm, key, (void *)(uintptr_t)(100 + i)));
    }

    /* Delete one key */
    assert_int_equal(1, hm_del(&hm, "k3"));
    assert_int_equal(7, (int)hm.size);
    assert_true(hm.tombstones >= 1);

    /* Lookup across the tombstone should still succeed */
    void *out = NULL;
    assert_int_equal(0, hm_get(&hm, "k3", &out));
    assert_int_equal(1, hm_get(&hm, "k4", &out));
    assert_int_equal(104, (int)(uintptr_t)out);

    hm_destroy(&hm);
}

/*
 * test_tombstone_reuse_same_key
 * Deletes a key to create a tombstone, then re-inserts the same key and
 * checks the tombstone is reused (size remains 1, tombstone count drops).
 */
static void test_tombstone_reuse_same_key(void **state) {
    (void)state;
    hashmap_t hm = {0};
    assert_int_equal(0, hm_init(&hm, 16));

    assert_int_equal(0, hm_put(&hm, "tkey", (void *)(uintptr_t)111));
    assert_int_equal(1, (int)hm.size);

    assert_int_equal(1, hm_del(&hm, "tkey"));
    size_t ts_before = hm.tombstones;
    assert_true(ts_before >= 1);

    /* Reinserting the same key should reuse the tombstone */
    assert_int_equal(0, hm_put(&hm, "tkey", (void *)(uintptr_t)222));

    assert_int_equal(1, (int)hm.size);
    assert_true(hm.tombstones <= ts_before - 1);

    void *out = NULL;
    assert_int_equal(1, hm_get(&hm, "tkey", &out));
    assert_int_equal(222, (int)(uintptr_t)out);

    hm_destroy(&hm);
}

/*
 * test_growth_threshold_doubles_capacity
 * Fills the map to the 0.75 load factor without growth, then one more insert
 * must trigger a capacity doubling before adding the element.
 */
static void test_growth_threshold_doubles_capacity(void **state) {
    (void)state;
    hashmap_t hm = {0};
    assert_int_equal(0, hm_init(&hm, 16));
    size_t cap0 = hm.capacity;
    assert_true(cap0 >= 16);

    /* Fill to load factor 0.75 (12/16) */
    char key[32];
    for (int i = 0; i < (int)(cap0 * 3 / 4); ++i) {
        make_key(key, sizeof(key), "x", i);
        assert_int_equal(0, hm_put(&hm, key, (void *)(uintptr_t)i));
    }
    /* At threshold, capacity should still be cap0 */
    assert_int_equal((int)cap0, (int)hm.capacity);

    /* Next insertion should trigger growth BEFORE inserting */
    make_key(key, sizeof(key), "x", (int)(cap0 * 3 / 4));
    assert_int_equal(0, hm_put(&hm, key, (void *)(uintptr_t)999));

    assert_int_equal((int)(cap0 << 1), (int)hm.capacity);

    hm_destroy(&hm);
}

/*
 * test_iteration_finds_all
 * Inserts three entries and iterates with hm_iter_* helpers, ensuring
 * every key/value pair is visited exactly once and matches expectations.
 */
static void test_iteration_finds_all(void **state) {
    (void)state;
    hashmap_t hm = {0};
    assert_int_equal(0, hm_init(&hm, 16));

    assert_int_equal(0, hm_put(&hm, "a", (void *)(uintptr_t)1));
    assert_int_equal(0, hm_put(&hm, "b", (void *)(uintptr_t)2));
    assert_int_equal(0, hm_put(&hm, "c", (void *)(uintptr_t)3));

    int seen_a = 0, seen_b = 0, seen_c = 0;

    hm_iter_t it;
    hm_iter_init(&hm, &it);

    const char *k = NULL; void *v = NULL;
    int count = 0;
    while (hm_iter_next(&it, &k, &v)) {
        ++count;
        if (strcmp(k, "a") == 0) { seen_a = 1; assert_int_equal(1, (int)(uintptr_t)v); }
        else if (strcmp(k, "b") == 0) { seen_b = 1; assert_int_equal(2, (int)(uintptr_t)v); }
        else if (strcmp(k, "c") == 0) { seen_c = 1; assert_int_equal(3, (int)(uintptr_t)v); }
    }

    assert_int_equal(3, count);
    assert_true(seen_a && seen_b && seen_c);

    hm_destroy(&hm);
}

/*
 * test_invalid_args
 * Validates defensive behavior:
 *  - hm_init(NULL) fails
 *  - put/get/del with NULL map/key behave safely
 *  - unknown key lookups/deletes are no-ops with the right return codes.
 */
static void test_invalid_args(void **state) {
    (void)state;
    /* hm_init NULL */
    assert_int_equal(-1, hm_init(NULL, 16));

    hashmap_t hm = {0};
    assert_int_equal(0, hm_init(&hm, 16));

    /* Null map or key */
    assert_int_equal(-1, hm_put(&hm, NULL, (void *)(uintptr_t)1));
    assert_int_equal(0, hm_get(&hm, NULL, NULL));
    assert_int_equal(0, hm_del(&hm, NULL));

    /* Unknown key */
    assert_int_equal(0, hm_del(&hm, "nope"));
    assert_int_equal(0, hm_get(&hm, "nope", NULL));

    hm_destroy(&hm);
}

/* ================================ Test Suite ================================ */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_init_destroy),
        cmocka_unit_test(test_put_get_update),
        cmocka_unit_test(test_delete_and_chain_integrity),
        cmocka_unit_test(test_tombstone_reuse_same_key),
        cmocka_unit_test(test_growth_threshold_doubles_capacity),
        cmocka_unit_test(test_iteration_finds_all),
        cmocka_unit_test(test_invalid_args),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
