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

#include "../../os_crypto/sha256/sha256_op.h"
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

void test_sha256_string() {
    const char *string = "teststring";
    const char *string_sha256 = "3c8727e019a42b444667a587b6001251becadabbb36bfed8087a92c18882d111";
    os_sha256 buffer;

    OS_SHA256_String(string, buffer);

    assert_string_equal(buffer, string_sha256);
}

void test_sha256_string_sized() {
    const char *string = "teststring";
    const char *string_sha256_chopped = "3c8727e019";
    int chopped_size = 10;
    os_sha256 buffer;

    OS_SHA256_String_sized(string, buffer, chopped_size);

    assert_string_equal(buffer, string_sha256_chopped);
}

void test_sha256_file() {
    const char *string = "teststring";
    const char *string_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    char path[] = "path/to/file";

    expect_value(__wrap_wfopen, path, path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fread, string);
    will_return(__wrap_fread, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    os_sha256 buffer;
    assert_int_equal(OS_SHA256_File(path, buffer, OS_TEXT), 0);

    assert_string_equal(buffer, string_sha256);
}

void test_sha256_file_fail() {
    char path[] = "path/to/non-existing/file";

    expect_value(__wrap_wfopen, path, path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    os_sha256 buffer;
    assert_int_equal(OS_SHA256_File(path, buffer, OS_TEXT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sha256_string),
        cmocka_unit_test(test_sha256_string_sized),
        cmocka_unit_test_setup_teardown(test_sha256_file, setup_group, teardown_group),
        cmocka_unit_test_setup_teardown(test_sha256_file_fail, setup_group, teardown_group),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
