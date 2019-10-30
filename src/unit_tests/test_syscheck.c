/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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

#include "../syscheckd/syscheck.h"


/* redefinitons/wrapping */

int __wrap_OSHash_Create() {
    return 1;
}

int __wrap_OSHash_setSize() {
    return mock();
}

/* tests */

void test_fim_initialize(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_OSHash_setSize, 1);

    ret = fim_initialize();

    assert_int_equal(ret, 0);
}


void test_fim_initialize_warn(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_OSHash_setSize, 0);

    ret = fim_initialize();

    assert_int_equal(ret, 0);
}


void test_read_internal(void **state)
{
    (void) state;

    read_internal(0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fim_initialize),
        cmocka_unit_test(test_fim_initialize_warn),
        cmocka_unit_test(test_read_internal),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
