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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "shared.h"
#include "indexed_queue_op.h"

static w_indexed_queue_t *queue_ptr = NULL;

/****************SETUP/TEARDOWN******************/

int setup_indexed_queue(void **state) {
    w_indexed_queue_t *queue = indexed_queue_init(5); // Limited size for testing
    *state = queue;
    queue_ptr = queue;
    return 0;
}

int setup_indexed_queue_unlimited(void **state) {
    w_indexed_queue_t *queue = indexed_queue_init(0); // Unlimited size
    *state = queue;
    queue_ptr = queue;
    return 0;
}

int teardown_indexed_queue(void **state) {
    w_indexed_queue_t *queue = *state;
    if (queue) {
        // Clean up any remaining data first
        void *data;
        while ((data = indexed_queue_pop(queue)) != NULL) {
            free(data);
        }
        // Use the proper destructor
        indexed_queue_free(queue);
    }
    queue_ptr = NULL;
    return 0;
}

void test_data_dispose(void *data) {
    free(data);
}

/****************SIMPLE PTHREAD WRAPPERS******************/
// No-op wrappers to avoid mock complexities

int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    (void)mutex; // Avoid unused parameter warning
    return 0; // Success
}

int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    (void)cond;
    (void)mutex;
    return 0;
}

int __wrap_pthread_cond_signal(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}

int __wrap_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) {
    (void)cond;
    (void)mutex;
    (void)abstime;
    return 0;
}

/****************TESTS******************/

void test_indexed_queue_init(void **state) {
    (void) state;

    w_indexed_queue_t *queue = indexed_queue_init(10);
    assert_non_null(queue);
    assert_int_equal(indexed_queue_size(queue), 0);
    assert_int_equal(indexed_queue_empty(queue), 1);
    assert_int_equal(indexed_queue_full(queue), 0);

    indexed_queue_free(queue);
}

void test_indexed_queue_init_unlimited(void **state) {
    (void) state;

    w_indexed_queue_t *queue = indexed_queue_init(0);
    assert_non_null(queue);
    assert_int_equal(indexed_queue_size(queue), 0);
    assert_int_equal(indexed_queue_empty(queue), 1);
    assert_int_equal(indexed_queue_full(queue), 0); // Never full when unlimited

    indexed_queue_free(queue);
}

void test_indexed_queue_push(void **state) {
    w_indexed_queue_t *queue = *state;
    int *data = malloc(sizeof(int));
    *data = 42;

    int result = indexed_queue_push(queue, "key1", data);
    assert_int_equal(result, 0);
    assert_int_equal(indexed_queue_size(queue), 1);
    assert_int_equal(indexed_queue_empty(queue), 0);

    // Test duplicate key
    int *data2 = malloc(sizeof(int));
    *data2 = 43;
    result = indexed_queue_push(queue, "key1", data2);
    assert_int_equal(result, -1); // Should fail
    assert_int_equal(indexed_queue_size(queue), 1); // Size unchanged

    free(data2);
}

void test_indexed_queue_push_full(void **state) {
    w_indexed_queue_t *queue = *state;

    // Fill queue to capacity (5 elements)
    for (int i = 0; i < 5; i++) {
        int *data = malloc(sizeof(int));
        *data = i;
        char key[10];
        snprintf(key, sizeof(key), "key%d", i);
        assert_int_equal(indexed_queue_push(queue, key, data), 0);
    }

    assert_int_equal(indexed_queue_full(queue), 1);

    // Try to push one more - should fail
    int *data = malloc(sizeof(int));
    *data = 99;
    int result = indexed_queue_push(queue, "key99", data);
    assert_int_equal(result, -1);

    free(data);
}

void test_indexed_queue_get(void **state) {
    w_indexed_queue_t *queue = *state;
    int *data = malloc(sizeof(int));
    *data = 42;

    indexed_queue_push(queue, "test_key", data);

    int *retrieved = (int *)indexed_queue_get(queue, "test_key");
    assert_non_null(retrieved);
    assert_int_equal(*retrieved, 42);

    // Test non-existent key
    void *not_found = indexed_queue_get(queue, "non_existent");
    assert_null(not_found);
}

void test_indexed_queue_upsert(void **state) {
    w_indexed_queue_t *queue = *state;

    // Insert new element
    int *data1 = malloc(sizeof(int));
    *data1 = 42;
    int result = indexed_queue_upsert(queue, "key1", data1);
    assert_int_equal(result, 0);
    assert_int_equal(indexed_queue_size(queue), 1);

    // Update existing element - upsert will handle the old data cleanup
    // but since we don't have dispose function set, we need to handle manually
    indexed_queue_set_dispose(queue, test_data_dispose);

    int *data2 = malloc(sizeof(int));
    *data2 = 99;
    result = indexed_queue_upsert(queue, "key1", data2);
    assert_int_equal(result, 0);
    assert_int_equal(indexed_queue_size(queue), 1); // Size should remain the same

    // Verify updated value
    int *retrieved = (int *)indexed_queue_get(queue, "key1");
    assert_non_null(retrieved);
    assert_int_equal(*retrieved, 99);

    // Reset dispose to NULL to avoid issues in teardown
    indexed_queue_set_dispose(queue, NULL);
}

void test_indexed_queue_pop(void **state) {
    w_indexed_queue_t *queue = *state;

    // Add some elements
    for (int i = 0; i < 3; i++) {
        int *data = malloc(sizeof(int));
        *data = i;
        char key[10];
        snprintf(key, sizeof(key), "key%d", i);
        indexed_queue_push(queue, key, data);
    }

    // Pop should return in FIFO order
    int *popped = (int *)indexed_queue_pop(queue);
    assert_non_null(popped);
    assert_int_equal(*popped, 0); // First element
    assert_int_equal(indexed_queue_size(queue), 2);

    // Verify element was removed from index too
    void *not_found = indexed_queue_get(queue, "key0");
    assert_null(not_found);

    free(popped);
}

void test_indexed_queue_peek(void **state) {
    w_indexed_queue_t *queue = *state;

    // Empty queue peek
    void *peeked = indexed_queue_peek(queue);
    assert_null(peeked);

    // Add element and peek
    int *data = malloc(sizeof(int));
    *data = 42;
    indexed_queue_push(queue, "peek_key", data);

    peeked = indexed_queue_peek(queue);
    assert_non_null(peeked);
    assert_int_equal(*(int *)peeked, 42);

    // Verify element is still in queue
    assert_int_equal(indexed_queue_size(queue), 1);
    void *still_there = indexed_queue_get(queue, "peek_key");
    assert_non_null(still_there);
}

void test_indexed_queue_delete(void **state) {
    w_indexed_queue_t *queue = *state;

    // Set dispose function to handle cleanup automatically
    indexed_queue_set_dispose(queue, test_data_dispose);

    // Add some elements
    for (int i = 0; i < 3; i++) {
        int *data = malloc(sizeof(int));
        *data = i;
        char key[10];
        snprintf(key, sizeof(key), "key%d", i);
        indexed_queue_push(queue, key, data);
    }

    // Delete middle element
    int result = indexed_queue_delete(queue, "key1");
    assert_int_equal(result, 1);
    assert_int_equal(indexed_queue_size(queue), 2);

    // Verify element was removed
    void *not_found = indexed_queue_get(queue, "key1");
    assert_null(not_found);

    // Delete non-existent element
    result = indexed_queue_delete(queue, "non_existent");
    assert_int_equal(result, 0);
    assert_int_equal(indexed_queue_size(queue), 2); // Size unchanged

    // Reset dispose to NULL to avoid issues in teardown
    indexed_queue_set_dispose(queue, NULL);
}

void test_indexed_queue_update(void **state) {
    w_indexed_queue_t *queue = *state;

    // Add element
    int *data1 = malloc(sizeof(int));
    *data1 = 42;
    indexed_queue_push(queue, "update_key", data1);

    // Update element
    int *data2 = malloc(sizeof(int));
    *data2 = 99;
    void *old_data = indexed_queue_update(queue, "update_key", data2);
    assert_non_null(old_data);
    assert_int_equal(*(int *)old_data, 42);

    // Verify new value
    int *retrieved = (int *)indexed_queue_get(queue, "update_key");
    assert_non_null(retrieved);
    assert_int_equal(*retrieved, 99);

    // Update non-existent key
    int *data3 = malloc(sizeof(int));
    *data3 = 123;
    old_data = indexed_queue_update(queue, "non_existent", data3);
    assert_null(old_data);

    free(data1);
    free(data3);
}

void test_indexed_queue_fifo_order(void **state) {
    w_indexed_queue_t *queue = *state;

    // Add elements
    for (int i = 0; i < 3; i++) {
        int *data = malloc(sizeof(int));
        *data = i;
        char key[10];
        snprintf(key, sizeof(key), "key%d", i);
        indexed_queue_push(queue, key, data);
    }

    // Pop all elements and verify FIFO order
    for (int i = 0; i < 3; i++) {
        int *popped = (int *)indexed_queue_pop(queue);
        assert_non_null(popped);
        assert_int_equal(*popped, i);
        free(popped);
    }

    // Queue should be empty now
    assert_int_equal(indexed_queue_empty(queue), 1);
    void *empty_pop = indexed_queue_pop(queue);
    assert_null(empty_pop);
}

void test_indexed_queue_mixed_operations(void **state) {
    w_indexed_queue_t *queue = *state;

    // Set dispose function to handle memory cleanup automatically
    indexed_queue_set_dispose(queue, test_data_dispose);

    // Insert some elements
    for (int i = 0; i < 3; i++) {
        int *data = malloc(sizeof(int));
        *data = i;
        char key[10];
        snprintf(key, sizeof(key), "key%d", i);
        indexed_queue_push(queue, key, data);
    }

    // Get by key
    int *retrieved = (int *)indexed_queue_get(queue, "key1");
    assert_non_null(retrieved);
    assert_int_equal(*retrieved, 1);

    // Delete middle element (dispose will free the data automatically)
    indexed_queue_delete(queue, "key1");

    // Pop should skip deleted element
    int *popped1 = (int *)indexed_queue_pop(queue);
    assert_non_null(popped1);
    assert_int_equal(*popped1, 0); // First element (key0)
    free(popped1); // Manual free since pop doesn't call dispose

    int *popped2 = (int *)indexed_queue_pop(queue);
    assert_non_null(popped2);
    assert_int_equal(*popped2, 2); // Third element (key2), key1 was deleted
    free(popped2); // Manual free since pop doesn't call dispose

    // Reset dispose to NULL to avoid issues in teardown
    indexed_queue_set_dispose(queue, NULL);
}

void test_indexed_queue_null_parameters(void **state) {
    (void) state;

    // Test with NULL queue
    assert_int_equal(indexed_queue_push(NULL, "key", NULL), -1);
    assert_null(indexed_queue_get(NULL, "key"));
    assert_int_equal(indexed_queue_delete(NULL, "key"), 0);

    w_indexed_queue_t *queue = indexed_queue_init(5);

    // Test with NULL key/data
    assert_int_equal(indexed_queue_push(queue, NULL, NULL), -1);
    assert_int_equal(indexed_queue_push(queue, "key", NULL), -1);
    assert_null(indexed_queue_get(queue, NULL));

    indexed_queue_free(queue);
}

/****************MAIN******************/

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_indexed_queue_init),
        cmocka_unit_test(test_indexed_queue_init_unlimited),
        cmocka_unit_test_setup_teardown(test_indexed_queue_push, setup_indexed_queue, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_push_full, setup_indexed_queue, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_get, setup_indexed_queue, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_upsert, setup_indexed_queue, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_pop, setup_indexed_queue, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_peek, setup_indexed_queue, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_delete, setup_indexed_queue, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_update, setup_indexed_queue, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_fifo_order, setup_indexed_queue_unlimited, teardown_indexed_queue),
        cmocka_unit_test_setup_teardown(test_indexed_queue_mixed_operations, setup_indexed_queue_unlimited, teardown_indexed_queue),
        cmocka_unit_test(test_indexed_queue_null_parameters),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
