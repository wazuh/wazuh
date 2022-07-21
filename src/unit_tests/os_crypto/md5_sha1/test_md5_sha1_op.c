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
#include "../../os_crypto/md5_sha1/md5_sha1_op.h"
#include "../../wrappers/common.h"

// Tests

void test_md5_sha1_file(void **state)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 md5buffer;
    os_sha1 sha1buffer;

    assert_int_equal(OS_MD5_SHA1_File(file_name, NULL, md5buffer, sha1buffer, OS_TEXT), 0);

    assert_string_equal(md5buffer, string_md5);
    assert_string_equal(sha1buffer, string_sha1);
}

void test_md5_sha1_cmd_file(void **state)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 md5buffer;
    os_sha1 sha1buffer;

    assert_int_equal(OS_MD5_SHA1_File(file_name, "cat ", md5buffer, sha1buffer, OS_TEXT), 0);

    assert_string_equal(md5buffer, string_md5);
    assert_string_equal(sha1buffer, string_sha1);
}

void test_md5_sha1_cmd_file_fail(void **state)
{
    os_md5 md5buffer;
    os_sha1 sha1buffer;

    assert_int_equal(OS_MD5_SHA1_File("not_existing_file", NULL, md5buffer, sha1buffer, OS_TEXT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_md5_sha1_file),
        cmocka_unit_test(test_md5_sha1_cmd_file),
        cmocka_unit_test(test_md5_sha1_cmd_file_fail),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
