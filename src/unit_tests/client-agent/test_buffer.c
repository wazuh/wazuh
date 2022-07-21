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

extern agent *agt;
extern int i;
extern int j;

/* setup/teardown */

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
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

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests w_agentd_get_buffer_lenght
        cmocka_unit_test(test_w_agentd_get_buffer_lenght_buffer_disabled),
        cmocka_unit_test(test_w_agentd_get_buffer_lenght_buffer_empty),
        cmocka_unit_test(test_w_agentd_get_buffer_lenght_buffer),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}