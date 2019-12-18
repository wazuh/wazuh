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

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}


/* tests */

void test_fim_initialize(void **state)
{
    (void) state;

    will_return(__wrap_OSHash_setSize, 1);

    fim_initialize();

    assert_non_null(syscheck.fim_entry);
    assert_non_null(syscheck.fim_inode);
}


void test_fim_initialize_warn(void **state)
{
    (void) state;

    will_return(__wrap_OSHash_setSize, 0);

    expect_string(__wrap__mwarn, formatted_msg, LIST_ERROR);

    fim_initialize();

    assert_non_null(syscheck.fim_entry);
    assert_non_null(syscheck.fim_inode);
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
