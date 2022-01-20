/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
    const char *string_sha256 = "3c8727e019a42b444667a587b6001251becadabbb36bfed8087a92c18882d111";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_sha256 buffer;
    assert_int_equal(OS_SHA256_File(file_name, buffer, OS_TEXT), 0);

    assert_string_equal(buffer, string_sha256);
}

void test_sha256_file_fail() {
    os_sha256 buffer;
    assert_int_equal(OS_SHA256_File("not_existing_file", buffer, OS_TEXT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sha256_string),
        cmocka_unit_test(test_sha256_string_sized),
        cmocka_unit_test(test_sha256_file),
        cmocka_unit_test(test_sha256_file_fail),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
