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

#include "../../config/client-config.h"

#include "../wrappers/posix/pthread_wrappers.h"

int w_agentd_get_buffer_lenght();
int buffer_append(const char *msg);
int w_agentd_buffer_resize(unsigned int current_capacity, unsigned int desired_capacity);
void w_agentd_buffer_free(unsigned int current_capacity);
void buffer_init();

extern agent *agt;
extern int i;
extern int j;
extern char **buffer;

/* setup/teardown */

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

// The mock function for getDefine_Int
int __wrap_getDefine_Int(const char *category, const char *name, int min, int max) {
    function_called();

    return mock_type(int);
}

void __wrap__minfo(const char *file, int line, const char *func, const char *format, ...) {
        function_called();
}

void __wrap__mwarn(const char *file, int line, const char *func, const char *format, ...) {
        function_called();
}


/* tests */

/* w_agentd_get_buffer_lenght */

void test_w_agentd_get_buffer_lenght_buffer_disabled(void ** state)
{
    os_calloc(1, sizeof(agent), agt);
    agt->buffer = 0;

    int retval = w_agentd_get_buffer_lenght();

    assert_int_equal(retval, -1);

    os_free(agt);

}

void test_w_agentd_get_buffer_lenght_buffer_empty(void ** state)
{
    os_calloc(1, sizeof(agent), agt);
    agt->buffer = 1;
    agt->buflength = 10;
    i = 1;
    j = 1;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = w_agentd_get_buffer_lenght();

    assert_int_equal(retval, 0);

    os_free(agt);

}

void test_w_agentd_get_buffer_lenght_buffer(void ** state)
{
    os_calloc(1, sizeof(agent), agt);
    agt->buffer = 1;
    agt->buflength = 5;
    i = 1;
    j = 5;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = w_agentd_get_buffer_lenght();

    assert_int_equal(retval, 2);

    os_free(agt);

}

void test_buffer_append(void **state)
{
    os_calloc(1, sizeof(agent), agt);
    agt->buffer = 1;
    agt->buflength = 5;
    i = 0;
    j = 0;
    char var[] = "Testing";

    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 90);

    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 80);

    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 15);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    buffer_init();
    buffer_append("Testing");

    assert_int_equal(1, w_agentd_get_buffer_lenght());

    // Required for w_agentd_buffer_free
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    // expect_function_call(__wrap__mwarn);
    expect_function_call(__wrap__minfo);

    w_agentd_buffer_free(agt->buflength);

    os_free(agt);
}

void test_w_agentd_buffer_resize_shrink(void **state)
{
    os_calloc(1, sizeof(agent), agt);
    agt->buffer = 1;
    agt->buflength = 5;
    i = 0;
    j = 0;
    char var[] = "Testing";

    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 90);
    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 80);
    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 15);

    buffer_init();

    for (int k = 0; k < agt->buflength; k++) {
        // Loock w_agentd_buffer_resize
        expect_function_call(__wrap_pthread_mutex_lock);
        // Look and unlock w_agentd_get_buffer_lenght
        expect_function_call(__wrap_pthread_mutex_lock);
        expect_function_call(__wrap_pthread_mutex_unlock);
        // Unloock w_agentd_buffer_resize
        expect_function_call(__wrap_pthread_mutex_unlock);
        buffer_append("Testing");
    }

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap__mwarn);
    expect_function_call(__wrap__minfo);

    // Loock, unloock the mutex for the w_agentd_state_update
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap__minfo);

    int new_capacity = 2;
    int retval = w_agentd_buffer_resize(agt->buflength, new_capacity);

    assert_int_equal(retval, 0);

    // Required for w_agentd_get_buffer_lenght
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    assert_int_equal(2, w_agentd_get_buffer_lenght());

    // Required for w_agentd_buffer_free
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap__minfo);

    w_agentd_buffer_free(new_capacity);
    os_free(agt);
}

void test_w_agentd_buffer_resize_grow_continue(void **state)
{
    os_calloc(1, sizeof(agent), agt);
    agt->buffer = 1;
    agt->buflength = 2;
    i = 0;
    j = 0;
    char var[] = "Testing";

    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 90);
    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 80);
    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 15);

    buffer_init();

    for (int k = 0; k < agt->buflength; k++) {
        // Loock w_agentd_buffer_resize
        expect_function_call(__wrap_pthread_mutex_lock);
        // Look and unlock w_agentd_get_buffer_lenght
        expect_function_call(__wrap_pthread_mutex_lock);
        expect_function_call(__wrap_pthread_mutex_unlock);
        // Unloock w_agentd_buffer_resize
        expect_function_call(__wrap_pthread_mutex_unlock);
        buffer_append("Testing");
    }

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap__minfo);

    int new_capacity = 5;
    int retval = w_agentd_buffer_resize(agt->buflength, new_capacity);

    assert_int_equal(retval, 0);

    // Required for w_agentd_get_buffer_lenght
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    assert_int_equal(2, w_agentd_get_buffer_lenght());

    // Required for w_agentd_buffer_free
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    // expect_function_call(__wrap__mwarn);
    expect_function_call(__wrap__minfo);

    w_agentd_buffer_free(new_capacity);
    os_free(agt);
}

void test_w_agentd_buffer_resize_grow_two_parts(void **state)
{
    os_calloc(1, sizeof(agent), agt);
    agt->buffer = 1;
    agt->buflength = 2;
    i = 1;
    j = 1;
    char var[] = "Testing";

    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 90);
    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 80);
    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 15);

    buffer_init();

    for (int k = 0; k < agt->buflength; k++) {
        // Loock w_agentd_buffer_resize
        expect_function_call(__wrap_pthread_mutex_lock);
        // Look and unlock w_agentd_get_buffer_lenght
        expect_function_call(__wrap_pthread_mutex_lock);
        expect_function_call(__wrap_pthread_mutex_unlock);
        // Unloock w_agentd_buffer_resize
        expect_function_call(__wrap_pthread_mutex_unlock);
        buffer_append("Testing");
    }

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_lock);

    // Loock, unloock the mutex for the w_agentd_state_update
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap__minfo);

    int new_capacity = 5;
    int retval = w_agentd_buffer_resize(agt->buflength, new_capacity);
    agt->buflength = new_capacity;
    assert_int_equal(retval, 0);

    // Required for w_agentd_get_buffer_lenght
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    assert_int_equal(2, w_agentd_get_buffer_lenght());

    // Required for w_agentd_buffer_free
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap__minfo);

    w_agentd_buffer_free(new_capacity);
    os_free(agt);
}

void test_w_agentd_buffer_free(void **state)
{
    os_calloc(1, sizeof(agent), agt);
    agt->buffer = 1;
    agt->buflength = 5;
    i = 0;
    j = 0;
    char var[] = "Testing";

    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 90);
    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 80);
    expect_function_call(__wrap_getDefine_Int);
    will_return(__wrap_getDefine_Int, 15);

    buffer_init();

    for (int k = 0; k < agt->buflength; k++) {
        // Loock w_agentd_buffer_resize
        expect_function_call(__wrap_pthread_mutex_lock);
        // Look and unlock w_agentd_get_buffer_lenght
        expect_function_call(__wrap_pthread_mutex_lock);
        expect_function_call(__wrap_pthread_mutex_unlock);
        // Unloock w_agentd_buffer_resize
        expect_function_call(__wrap_pthread_mutex_unlock);
        buffer_append("Testing");
    }

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap__minfo);

    w_agentd_buffer_free(agt->buflength);

    assert_int_equal(agt->buflength, 0);
    assert_int_equal(i, 0);
    assert_int_equal(j, 0);

    os_free(agt);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests w_agentd_get_buffer_lenght
        cmocka_unit_test(test_w_agentd_get_buffer_lenght_buffer_disabled),
        cmocka_unit_test(test_w_agentd_get_buffer_lenght_buffer_empty),
        cmocka_unit_test(test_w_agentd_get_buffer_lenght_buffer),
        cmocka_unit_test(test_buffer_append),
        cmocka_unit_test(test_w_agentd_buffer_free),
        cmocka_unit_test(test_w_agentd_buffer_resize_shrink),
        cmocka_unit_test(test_w_agentd_buffer_resize_grow_continue),
        cmocka_unit_test(test_w_agentd_buffer_resize_grow_two_parts),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
