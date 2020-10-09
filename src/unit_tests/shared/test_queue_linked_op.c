/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "../wrappers/posix/pthread_wrappers.h"

#include "shared.h"

static w_linked_queue_t *queue_ptr = NULL; // Local ptr to queue
/****************SETUP/TEARDOWN******************/
void callback_queue_push_ex() {
    int *ptr = malloc(sizeof(int));
    *ptr = 0;
    linked_queue_push_ex(queue_ptr, ptr);   
}

int setup_queue(void **state) {
    w_linked_queue_t *queue = linked_queue_init();
    *state = queue;
    queue_ptr = queue;
    return 0;
}

int teardown_queue(void **state) {
    w_linked_queue_t *queue = *state;
    int *data = linked_queue_pop(queue);
    while(data) {
        os_free(data);
        data = linked_queue_pop(queue);
    }
    linked_queue_free(queue);
    queue_ptr = NULL;
    return 0;
}

int setup_queue_with_values(void **state) {
    w_linked_queue_t *queue = linked_queue_init();
    *state = queue;
    int *ptr = malloc(sizeof(int));
    *ptr = 3;
    linked_queue_push(queue, ptr);
    int *ptr2 = malloc(sizeof(int));
    *ptr2 = 5;
    linked_queue_push(queue, ptr2);
    queue_ptr = queue;
    return 0;
}

/****************TESTS***************************/
void test_linked_queue_push(void **state) {
    w_linked_queue_t *queue = *state;
    int *ptr = malloc(sizeof(int));
    *ptr = 2;
    linked_queue_push(queue, ptr);
    assert_ptr_equal(queue->first->data, ptr);
    assert_ptr_equal(queue->last->data, ptr);
    int *ptr2 = malloc(sizeof(int));
    *ptr2 = 5;
    linked_queue_push(queue, ptr2);
    assert_ptr_equal(queue->first->data, ptr);
    assert_ptr_equal(queue->last->data, ptr2);
    assert_int_equal(queue->elements, 2);
}

void test_linked_queue_push_ex(void **state) {
    w_linked_queue_t *queue = *state;
    int *ptr = malloc(sizeof(int));
    *ptr = 2;
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_value_count(__wrap_pthread_cond_signal, cond, &queue->available, 2);
    linked_queue_push_ex(queue, ptr);
    assert_ptr_equal(queue->first->data, ptr);
    assert_ptr_equal(queue->last->data, ptr);
    int *ptr2 = malloc(sizeof(int));
    *ptr2 = 5;
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    linked_queue_push_ex(queue, ptr2);
    assert_ptr_equal(queue->first->data, ptr);
    assert_ptr_equal(queue->last->data, ptr2);
    assert_int_equal(queue->elements, 2);
}


void test_linked_pop_empty(void **state) {
    w_linked_queue_t *queue = *state;
    void *data = linked_queue_pop(queue);
    assert_ptr_equal(data, NULL);
}

void test_linked_pop(void **state) {
    w_linked_queue_t *queue = *state;
    assert_int_equal(queue->elements, 2);
    int *data = linked_queue_pop(queue);
    assert_int_equal(queue->elements, 1);
    assert_ptr_not_equal(data, NULL);
    assert_int_equal(*data, 3);
    os_free(data);
    data = linked_queue_pop(queue);
    assert_int_equal(queue->elements, 0);
    assert_ptr_not_equal(data, NULL);
    assert_int_equal(*data, 5);
    // Check queue is now empty
    assert_ptr_equal(queue->first, NULL);
    assert_ptr_equal(queue->last, NULL);
    os_free(data);
}

void test_linked_pop_ex(void **state) {
    w_linked_queue_t *queue = *state;
    assert_int_equal(queue->elements, 2);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    int *data = linked_queue_pop_ex(queue);
    assert_int_equal(queue->elements, 1);
    assert_ptr_not_equal(data, NULL);
    assert_int_equal(*data, 3);
    os_free(data);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    data = linked_queue_pop_ex(queue);
    assert_int_equal(queue->elements, 0);
    assert_ptr_not_equal(data, NULL);
    assert_int_equal(*data, 5);
    // Check queue is now empty
    assert_ptr_equal(queue->first, NULL);
    assert_ptr_equal(queue->last, NULL);
    os_free(data);
    expect_function_calls(__wrap_pthread_mutex_lock, 2);
    expect_function_calls(__wrap_pthread_mutex_unlock, 2);
    expect_value(__wrap_pthread_cond_wait, cond, &queue->available);
    expect_value(__wrap_pthread_cond_wait, mutex, &queue->mutex);
    expect_value(__wrap_pthread_cond_signal, cond, &queue->available);
    pthread_callback_ptr = callback_queue_push_ex;
    data = linked_queue_pop_ex(queue);
    os_free(data);
}

void test_linked_queue_unlink_and_push_mid(void **state) {
    w_linked_queue_t *queue = *state;
    int *ptr, *ptr2, *ptr3;
    ptr = malloc(sizeof(int));
    *ptr = 1;
    w_linked_queue_node_t *node1 = linked_queue_push(queue, ptr);
    ptr2 = malloc(sizeof(int));
    *ptr2 = 2;
    w_linked_queue_node_t *node2 = linked_queue_push(queue, ptr2);
    ptr3 = malloc(sizeof(int));
    *ptr3 = 3;
    w_linked_queue_node_t *node3 = linked_queue_push(queue, ptr3);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    linked_queue_unlink_and_push_node(queue, node2);
    assert_int_equal(3, queue->elements);
    int *ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr, ret);
    ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr3, ret);
    ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr2, ret);
    os_free(ptr);
    os_free(ptr2);
    os_free(ptr3);
}

void test_linked_queue_unlink_and_push_start(void **state) {
    w_linked_queue_t *queue = *state;
    int *ptr, *ptr2, *ptr3;
    ptr = malloc(sizeof(int));
    *ptr = 1;
    w_linked_queue_node_t *node1 = linked_queue_push(queue, ptr);
    ptr2 = malloc(sizeof(int));
    *ptr2 = 2;
    w_linked_queue_node_t *node2 = linked_queue_push(queue, ptr2);
    ptr3 = malloc(sizeof(int));
    *ptr3 = 3;
    w_linked_queue_node_t *node3 = linked_queue_push(queue, ptr3);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    linked_queue_unlink_and_push_node(queue, node1);
    assert_int_equal(3, queue->elements);
    int *ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr2, ret);
    ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr3, ret);
    ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr, ret);
    os_free(ptr);
    os_free(ptr2);
    os_free(ptr3);
}

void test_linked_queue_unlink_and_push_end(void **state) {
    w_linked_queue_t *queue = *state;
    int *ptr, *ptr2, *ptr3;
    ptr = malloc(sizeof(int));
    *ptr = 1;
    w_linked_queue_node_t *node1 = linked_queue_push(queue, ptr);
    ptr2 = malloc(sizeof(int));
    *ptr2 = 2;
    w_linked_queue_node_t *node2 = linked_queue_push(queue, ptr2);
    ptr3 = malloc(sizeof(int));
    *ptr3 = 3;
    w_linked_queue_node_t *node3 = linked_queue_push(queue, ptr3);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    linked_queue_unlink_and_push_node(queue, node3);
    assert_int_equal(3, queue->elements);
    int *ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr, ret);
    ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr2, ret);
    ret = linked_queue_pop(queue);
    assert_ptr_equal(ptr3, ret);
    os_free(ptr);
    os_free(ptr2);
    os_free(ptr3);
}
/************************************************/
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_linked_queue_push, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_linked_queue_push_ex, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_linked_pop_empty, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_linked_pop, setup_queue_with_values, teardown_queue),
        cmocka_unit_test_setup_teardown(test_linked_pop_ex, setup_queue_with_values, teardown_queue),
        cmocka_unit_test_setup_teardown(test_linked_queue_unlink_and_push_mid, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_linked_queue_unlink_and_push_start, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_linked_queue_unlink_and_push_end, setup_queue, teardown_queue),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
