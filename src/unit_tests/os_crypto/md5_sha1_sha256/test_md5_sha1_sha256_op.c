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
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"

#include "../../wrappers/common.h"

// Tests

void test_md5_sha1_sha256_file(void **state)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";
    const char *string_sha256 = "3c8727e019a42b444667a587b6001251becadabbb36bfed8087a92c18882d111";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 md5buffer;
    os_sha1 sha1buffer;
    os_sha256 sha256buffer;


    assert_int_equal(OS_MD5_SHA1_SHA256_File(file_name, NULL, md5buffer, sha1buffer, sha256buffer, OS_TEXT, 20), 0);

    assert_string_equal(md5buffer, string_md5);
    assert_string_equal(sha1buffer, string_sha1);
}

void test_md5_sha1_sha256_cmd_file(void **state)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";
    const char *string_sha256 = "3c8727e019a42b444667a587b6001251becadabbb36bfed8087a92c18882d111";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 md5buffer;
    os_sha1 sha1buffer;
    os_sha256 sha256buffer;
    char *command [] = {"cat", NULL};

    assert_int_equal(OS_MD5_SHA1_SHA256_File(file_name, command, md5buffer, sha1buffer, sha256buffer, OS_TEXT, 20), 0);

    assert_string_equal(md5buffer, string_md5);
    assert_string_equal(sha1buffer, string_sha1);
    assert_string_equal(sha1buffer, string_sha1);

}

void test_md5_sha1_sha256_cmd_file_fail(void **state)
{
    os_md5 md5buffer;
    os_sha1 sha1buffer;
    os_sha256 sha256buffer;

    char *command [] = {"cat", NULL};

    assert_int_equal(OS_MD5_SHA1_SHA256_File("file_name", command, md5buffer, sha1buffer, sha256buffer, OS_TEXT, 20), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_md5_sha1_sha256_file),
        cmocka_unit_test(test_md5_sha1_sha256_cmd_file),
        cmocka_unit_test(test_md5_sha1_sha256_cmd_file_fail),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
