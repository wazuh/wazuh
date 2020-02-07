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

int __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}


/* tests */

void test_log_realtime_status(void **state)
{
    (void) state;

    expect_string(__wrap__minfo, msg, FIM_REALTIME_STARTED);
    log_realtime_status(1);

    expect_string(__wrap__minfo, msg, FIM_REALTIME_PAUSED);
    log_realtime_status(2);

    expect_string(__wrap__minfo, msg, FIM_REALTIME_RESUMED);
    log_realtime_status(1);
}


void test_fim_whodata_initialize(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    ret = fim_whodata_initialize();

    assert_int_equal(ret, 0);
}



int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_log_realtime_status),
        cmocka_unit_test(test_fim_whodata_initialize),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
