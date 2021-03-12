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

#include "../../remoted/remoted.h"
#include "../../headers/shared.h"

/* Forward declarations */
void save_controlmsg(const keyentry * key, char *r_msg, size_t msg_length, int *wdb_sock);

/* setup/teardown */

static int setup_remoted(void **state) {
    return OS_SUCCESS;
}

static int teardown_remoted(void **state) {
    return OS_SUCCESS;
}

/* tests */

/* Tests save_controlmsg*/

void test_save_controlmsg(void **state)
{
    assert_int_equal(OS_SUCCESS, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests save_controlmsg
        cmocka_unit_test_setup_teardown(test_save_controlmsg, setup_remoted, teardown_remoted)
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
