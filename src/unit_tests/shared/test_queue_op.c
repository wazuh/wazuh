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

#include "shared.h"

static const int QUEUE_SIZE = 5;
static void (*callback_ptr)(void) = NULL;
static w_queue_t *queue_ptr = NULL; // Local ptr to queue
/****************SETUP/TEARDOWN******************/
int setup_queue(void **state) {
    w_queue_t *queue = queue_init(QUEUE_SIZE);
    *state = queue;
    queue_ptr = queue;
    return 0;
}

int teardown_queue(void **state) {
    w_queue_t *queue = *state;
    queue_free(queue);
    callback_ptr = NULL;
    queue_ptr = NULL;
    return 0;
}

//Unlocks blocked queue
void callback_queue_pop_ex() {
    queue_pop_ex(queue_ptr);
}

void callback_queue_push_ex() {
    int *ptr = malloc(sizeof(int));
    *ptr = 0;
    queue_push_ex(queue_ptr, ptr);
}
/*****************WRAPS********************/
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    check_expected_ptr(mutex);
    return 0;
}

int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    check_expected_ptr(mutex);
    return 0;
}

int __wrap_pthread_cond_wait(pthread_cond_t *cond,pthread_mutex_t *mutex) {
    check_expected_ptr(cond);
    check_expected_ptr(mutex);
    // callback function to avoid infinite loops when testing
    if (callback_ptr)
        callback_ptr();
    return 0;
}

int __wrap_pthread_cond_timedwait(pthread_cond_t *cond,pthread_mutex_t *mutex, const struct timespec * abstime) {
    check_expected_ptr(cond);
    check_expected_ptr(mutex);
    check_expected_ptr(abstime);
    // callback function to avoid infinite loops when testing
    if (callback_ptr)
        callback_ptr();
    return mock_type(int);
}

int __wrap_pthread_cond_signal(pthread_cond_t *cond) {
    check_expected_ptr(cond);
    return 0;
}

/****************TESTS***************************/
void test_queue_full(void **state){
    w_queue_t *queue = *state;
    for (int i=0; i < QUEUE_SIZE - 1; i++){
        assert_int_equal(queue_full(queue), 0);
        queue->begin++;
    }
    assert_int_equal(queue_full(queue), 1);
}

void test_queue_empty(void **state){
    w_queue_t *queue = *state;
    assert_int_equal(queue_empty(queue), 1);
    queue->begin++;
    assert_int_equal(queue_empty(queue), 0);
    queue->begin--;
    assert_int_equal(queue_empty(queue), 1);
}

void test_queue_get_percentage_ex(void ** state) {

    w_queue_t * queue = *state;

    // empty
    expect_value(__wrap_pthread_mutex_lock, mutex, &queue->mutex);
    expect_value(__wrap_pthread_mutex_unlock, mutex, &queue->mutex);
    assert_float_equal(queue_get_percentage_ex(queue), 0.0f, 0.01f);

    // quarter full
    for (int i = 0; i < QUEUE_SIZE / 4; i++) {
        queue_push(queue, NULL);
    }
    expect_value(__wrap_pthread_mutex_lock, mutex, &queue->mutex);
    expect_value(__wrap_pthread_mutex_unlock, mutex, &queue->mutex);
    assert_float_equal(queue_get_percentage_ex(queue), 0.25f, 0.01f);

    // half full
    for (int i = 0; i < QUEUE_SIZE / 4; i++) {
        queue_push(queue, NULL);
    }
    expect_value(__wrap_pthread_mutex_lock, mutex, &queue->mutex);
    expect_value(__wrap_pthread_mutex_unlock, mutex, &queue->mutex);
    assert_float_equal(queue_get_percentage_ex(queue), 0.5f, 0.01f);

    // three quarters full
    for (int i = 0; i < QUEUE_SIZE / 4; i++) {
        queue_push(queue, NULL);
    }
    expect_value(__wrap_pthread_mutex_lock, mutex, &queue->mutex);
    expect_value(__wrap_pthread_mutex_unlock, mutex, &queue->mutex);
    assert_float_equal(queue_get_percentage_ex(queue), 0.75f, 0.01f);

    // full
    for (int i = 0; i < QUEUE_SIZE / 4; i++) {
        queue_push(queue, NULL);
    }
    expect_value(__wrap_pthread_mutex_lock, mutex, &queue->mutex);
    expect_value(__wrap_pthread_mutex_unlock, mutex, &queue->mutex);
    assert_float_equal(queue_get_percentage_ex(queue), 1.0f, 0.01f);

    // empty
    for (int i = 0; i < QUEUE_SIZE; i++) {
        queue_pop(queue);
    }

    expect_value(__wrap_pthread_mutex_lock, mutex, &queue->mutex);
    expect_value(__wrap_pthread_mutex_unlock, mutex, &queue->mutex);
    assert_float_equal(queue_get_percentage_ex(queue), 0.0f, 0.01f);
}

void test_queue_push(void **state) {
    w_queue_t *queue = *state;
    int i;
    int *ptr = NULL;
    for (i=0; i < QUEUE_SIZE - 1; i++){
        ptr = malloc(sizeof(int));
        *ptr = i;
        // Should fit QUEUE_SIZE - 1 elements
        assert_int_equal(queue_push(queue, ptr), 0);
    }
    // Should now be full
    assert_int_equal(queue_push(queue, ptr), -1);
    // Validate elements are in queue
    for(i=0; i < QUEUE_SIZE - 1; i++) {
        ptr = queue->data[i];
        assert_int_equal(*ptr, i);
        os_free(ptr);
    }
}

void test_queue_push_ex(void **state) {
    w_queue_t *queue = *state;
    int i;
    int *ptr = NULL;
    expect_value_count(__wrap_pthread_mutex_lock, mutex,  &queue->mutex, QUEUE_SIZE);
    expect_value_count(__wrap_pthread_cond_signal, cond, &queue->available, QUEUE_SIZE - 1);
    expect_value_count(__wrap_pthread_mutex_unlock, mutex, &queue->mutex, QUEUE_SIZE);

    for (i=0; i < QUEUE_SIZE - 1; i++){
        ptr = malloc(sizeof(int));
        *ptr = i;
        // Should fit QUEUE_SIZE - 1 elements
        assert_int_equal(queue_push_ex(queue, ptr), 0);
    }
    // Should now be full
    assert_int_equal(queue_push_ex(queue, ptr), -1);
    // Validate elements are in queue
    for(i=0; i < QUEUE_SIZE - 1; i++) {
        ptr = queue->data[i];
        assert_int_equal(*ptr, i);
        os_free(ptr);
    }
}

void test_queue_push_ex_block(void **state) {
    w_queue_t *queue = *state;
    int i;
    int *ptr = NULL;
    expect_value_count(__wrap_pthread_mutex_lock, mutex,  &queue->mutex, QUEUE_SIZE + 1);
    expect_value_count(__wrap_pthread_mutex_unlock, mutex, &queue->mutex, QUEUE_SIZE + 1);

    // Set callback and wait
    expect_value(__wrap_pthread_cond_wait, cond, &queue->available_not_empty);
    expect_value(__wrap_pthread_cond_wait, mutex, &queue->mutex);
    callback_ptr = callback_queue_pop_ex;

    for (i=0; i < QUEUE_SIZE - 1; i++){
        ptr = malloc(sizeof(int));
        *ptr = i;
        // Should fit QUEUE_SIZE - 1 elements
        expect_value(__wrap_pthread_cond_signal, cond, &queue->available_not_empty);
        expect_value(__wrap_pthread_cond_signal, cond, &queue->available);
        assert_int_equal(queue_push_ex_block(queue, ptr), 0);
    }
    // Should now be full
    expect_value(__wrap_pthread_cond_signal, cond, &queue->available_not_empty);
    expect_value(__wrap_pthread_cond_signal, cond, &queue->available_not_empty);
    expect_value(__wrap_pthread_cond_signal, cond, &queue->available);
    assert_int_equal(queue_push_ex_block(queue, ptr), 0);
    // Validate elements are in queue
    for(i=0; i < QUEUE_SIZE - 1; i++) {
        ptr = queue->data[i];
        assert_int_equal(*ptr, i);
        os_free(ptr);
    }
}

void test_queue_pop(void **state) {
    w_queue_t *queue = *state;
    int i;
    int *ptr = NULL;
    for (i=0; i < QUEUE_SIZE - 1; i++){
        ptr = malloc(sizeof(int));
        *ptr = i;
        queue_push(queue, ptr);
    }
    // Pop items from full queue
    for(i=0; i < QUEUE_SIZE - 1; i++) {
        ptr = queue_pop(queue);
        assert_int_equal(*ptr, i);
        os_free(ptr);
    }
    // Should be empty now
    ptr = queue_pop(queue);
    assert_ptr_equal(ptr, NULL);
    os_free(ptr);
}

void test_queue_pop_ex(void **state) {
    w_queue_t *queue = *state;
    int i;
    int *ptr = NULL;
    for (i=0; i < QUEUE_SIZE - 1; i++){
        ptr = malloc(sizeof(int));
        *ptr = i;
        queue_push(queue, ptr);
    }
    // Pop items from full queue
    expect_value_count(__wrap_pthread_mutex_lock, mutex,  &queue->mutex, QUEUE_SIZE + 1);
    expect_value_count(__wrap_pthread_mutex_unlock, mutex, &queue->mutex, QUEUE_SIZE + 1);
    expect_value_count(__wrap_pthread_cond_signal, cond, &queue->available_not_empty, QUEUE_SIZE - 1);
    for(i=0; i < QUEUE_SIZE - 1; i++) {
        ptr = queue_pop_ex(queue);
        assert_int_equal(*ptr, i);
        os_free(ptr);
    }
    // Should be empty now until some push event
    expect_value(__wrap_pthread_cond_wait, mutex, &queue->mutex);
    expect_value(__wrap_pthread_cond_wait, cond, &queue->available);
    expect_value(__wrap_pthread_cond_signal, cond, &queue->available);
    expect_value(__wrap_pthread_cond_signal, cond, &queue->available_not_empty);
    callback_ptr = callback_queue_push_ex;
    ptr = queue_pop_ex(queue);
    assert_ptr_not_equal(ptr, NULL);
    os_free(ptr);
}

void test_queue_pop_ex_timedwait_timeout(void **state) {
    w_queue_t *queue = *state;
    struct timespec abstime;
    int i;
    int *ptr = NULL;
    for (i=0; i < QUEUE_SIZE - 1; i++){
        ptr = malloc(sizeof(int));
        *ptr = i;
        queue_push(queue, ptr);
    }
    // Pop items from full queue
    expect_value_count(__wrap_pthread_mutex_lock, mutex,  &queue->mutex, QUEUE_SIZE);
    expect_value_count(__wrap_pthread_mutex_unlock, mutex, &queue->mutex, QUEUE_SIZE);
    expect_value_count(__wrap_pthread_cond_signal, cond, &queue->available_not_empty, QUEUE_SIZE - 1);
    for(i=0; i < QUEUE_SIZE - 1; i++) {
        ptr = queue_pop_ex_timedwait(queue, &abstime);
        assert_int_equal(*ptr, i);
        os_free(ptr);
    }
    // Should be empty now until some push event
    expect_value(__wrap_pthread_cond_timedwait, mutex, &queue->mutex);
    expect_value(__wrap_pthread_cond_timedwait, cond, &queue->available);
    expect_value(__wrap_pthread_cond_timedwait, abstime, &abstime);
    will_return(__wrap_pthread_cond_timedwait, ETIMEDOUT);
    ptr = queue_pop_ex_timedwait(queue, &abstime);
    assert_ptr_equal(ptr, NULL);
}

void test_queue_pop_ex_timedwait_no_timeout(void **state) {
    w_queue_t *queue = *state;
    struct timespec abstime;
    int i;
    int *ptr = NULL;
    for (i=0; i < QUEUE_SIZE - 1; i++){
        ptr = malloc(sizeof(int));
        *ptr = i;
        queue_push(queue, ptr);
    }
    // Pop items from full queue
    expect_value_count(__wrap_pthread_mutex_lock, mutex,  &queue->mutex, QUEUE_SIZE + 1);
    expect_value_count(__wrap_pthread_mutex_unlock, mutex, &queue->mutex, QUEUE_SIZE + 1);
    expect_value_count(__wrap_pthread_cond_signal, cond, &queue->available_not_empty, QUEUE_SIZE - 1);
    for(i=0; i < QUEUE_SIZE - 1; i++) {
        ptr = queue_pop_ex_timedwait(queue, &abstime);
        assert_int_equal(*ptr, i);
        os_free(ptr);
    }
    // Should be empty now until some push event
    expect_value(__wrap_pthread_cond_timedwait, mutex, &queue->mutex);
    expect_value(__wrap_pthread_cond_timedwait, cond, &queue->available);
    expect_value(__wrap_pthread_cond_timedwait, abstime, &abstime);
    will_return(__wrap_pthread_cond_timedwait, 0);
    expect_value(__wrap_pthread_cond_signal, cond, &queue->available);
    expect_value(__wrap_pthread_cond_signal, cond, &queue->available_not_empty);
    callback_ptr = callback_queue_push_ex;
    ptr = queue_pop_ex_timedwait(queue, &abstime);
    assert_ptr_not_equal(ptr, NULL);
    os_free(ptr);
}
/************************************************/
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_queue_full, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_empty, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_get_percentage_ex, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_push, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_push_ex, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_push_ex_block, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_pop, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_pop_ex, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_pop_ex_timedwait_timeout, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_queue_pop_ex_timedwait_no_timeout, setup_queue, teardown_queue),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
