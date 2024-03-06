/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "../../os_crypto/md5/md5_op.h"
#include "../../wrappers/common.h"
#include "../headers/shared.h"

/* setups/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}


// Tests

void test_md5_string(void **state) {
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    os_md5 buffer;

    assert_int_equal(OS_MD5_Str(string, -1, buffer), 0);

    assert_string_equal(buffer, string_md5);
}

void test_md5_file(void **state) {
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";

    char path[] = "path/to/file";

    expect_value(__wrap_wfopen, path, path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fread, string);
    will_return(__wrap_fread, strlen(string));

    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    os_md5 buffer;
    assert_int_equal(OS_MD5_File(path, buffer, OS_TEXT), 0);

    assert_string_equal(buffer, string_md5);
}

void test_md5_file_fail(void **state) {
    char path[] = "path/to/non-existing/file";

    expect_value(__wrap_wfopen, path, path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    os_md5 buffer;
    assert_int_equal(OS_MD5_File(path, buffer, OS_TEXT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_md5_string),
        cmocka_unit_test_setup_teardown(test_md5_file, setup_group, teardown_group),
        cmocka_unit_test_setup_teardown(test_md5_file_fail, setup_group, teardown_group)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
