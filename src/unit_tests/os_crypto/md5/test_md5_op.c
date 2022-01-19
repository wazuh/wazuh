/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../headers/shared.h"
#include "../../os_crypto/md5/md5_op.h"
#include "../../wrappers/common.h"

// Tests

void test_md5_string(void **state)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    os_md5 buffer;

    OS_MD5_Str(string, -1, buffer);

    assert_string_equal(buffer, string_md5);
}

void test_md5_file(void **state)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 buffer;
    assert_int_equal(OS_MD5_File(file_name, buffer, OS_TEXT), 0);

    assert_string_equal(buffer, string_md5);
}

void test_md5_file_fail(void **state)
{
    os_md5 buffer;
    assert_int_equal(OS_MD5_File("not_existing_file", buffer, OS_TEXT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_md5_string),
        cmocka_unit_test(test_md5_file),
        cmocka_unit_test(test_md5_file_fail),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
