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
#include <stdlib.h>
#include <string.h>

#include "../../headers/shared.h"
#include "../wrappers/common.h"

// Tests

static int compare(const struct file_system_type * statfs) {
    for (int i = 0; network_file_systems[i].name; i++) {
        if (network_file_systems[i].f_type == statfs->f_type) {
            return 1;
        }
    }

    for (int i = 0; skip_file_systems[i].name; i++) {
        if (skip_file_systems[i].f_type == statfs->f_type) {
            return 1;
        }
    }

    return 0;
}

void test_fs_magic(void **state)
{
    struct file_system_type statfs = {.f_type = 0x6969};
    assert_int_equal(compare(&statfs), 1);

    statfs.f_type = 0xFF534D42;
    assert_int_equal(compare(&statfs), 1);

    statfs.f_type = 0x9123683E;
    assert_int_equal(compare(&statfs), 1);

    statfs.f_type = 0x61756673;
    assert_int_equal(compare(&statfs), 1);

    statfs.f_type = 0x794c7630;
    assert_int_equal(compare(&statfs), 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_fs_magic),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
