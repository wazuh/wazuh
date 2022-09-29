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

#include "shared.h"
#include "../../os_execd/execd.h"

static void test_custom_command(void **state) {
    (void)state;

    int timeout = 100;
    char * r = GetCommandbyName("!custom.sh", &timeout);

    assert_int_equal(timeout, 0);
    assert_string_equal(r, AR_BINDIR "/custom.sh");
}

static void test_path_traversal(void **state) {
    (void)state;
    int timeout = 100;

    expect_string(__wrap__mwarn, formatted_msg, "Active response command '../custom.sh' vulnerable to directory traversal attack. Ignoring.");

    char * r = GetCommandbyName("!../custom.sh", &timeout);
    assert_null(r);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_custom_command),
        cmocka_unit_test(test_path_traversal),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
