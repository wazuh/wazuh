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
#include "../os_crypto/md5_sha1/md5_sha1_op.h"
#include "../os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"

#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"

static int setup_group(void ** state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void ** state) {
    test_mode = 0;
    return 0;
}

// Tests

void test_md5_sha1_sha256_file(void **state)
{
    char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";
    const char *string_sha256 = "3c8727e019a42b444667a587b6001251becadabbb36bfed8087a92c18882d111";

    /* create tmp file */
    char file_name[256] = "/tmp/tmp_file-XXXXXX";

    FILE * fp = 0x1;
    expect_wfopen(file_name, "r", fp);
    expect_fread(string, strlen(string));
    expect_fread(string, 0);
    expect_fclose(fp, 0);

    os_md5 md5buffer;
    os_sha1 sha1buffer;
    os_sha256 sha256buffer;

    assert_int_equal(OS_MD5_SHA1_SHA256_File(file_name, NULL, md5buffer, sha1buffer, sha256buffer, OS_TEXT, 20), 0);

    assert_string_equal(md5buffer, string_md5);
    assert_string_equal(sha1buffer, string_sha1);
}

void test_md5_sha1_sha256_cmd_file(void **state)
{
    char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";
    const char *string_sha256 = "3c8727e019a42b444667a587b6001251becadabbb36bfed8087a92c18882d111";

    char file_name[256] = "/tmp/tmp_file-XXXXXX";

    os_md5 md5buffer;
    os_sha1 sha1buffer;
    os_sha256 sha256buffer;
    char *command [] = {"cat", NULL};

    wfd_t wfd = { NULL, NULL, 0 };
    will_return(__wrap_wpopenv, &wfd);
    expect_fread(string, strlen(string));
    expect_fread(string, 0);
    will_return(__wrap_wpclose, 0);

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

    will_return(__wrap_wpopenv, NULL);

    assert_int_equal(OS_MD5_SHA1_SHA256_File("file_name", command, md5buffer, sha1buffer, sha256buffer, OS_TEXT, 20), -1);
}

void test_md5_sha1_sha256_file_fail(void **state)
{
    os_md5 md5buffer;
    os_sha1 sha1buffer;
    os_sha256 sha256buffer;

    expect_wfopen("file_name", "r", NULL);

    assert_int_equal(OS_MD5_SHA1_SHA256_File("file_name", NULL, md5buffer, sha1buffer, sha256buffer, OS_TEXT, 20), -1);
}

void test_md5_sha1_sha256_cmd_file_max_size_fail(void **state)
{
    char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";
    const char *string_sha256 = "3c8727e019a42b444667a587b6001251becadabbb36bfed8087a92c18882d111";

    /* create tmp file */
    char file_name[256] = "/tmp/tmp_file-XXXXXX";

    FILE * fp = 0x1;
    expect_fread(string, strlen(string));

    os_md5 md5buffer;
    os_sha1 sha1buffer;
    os_sha256 sha256buffer;

    char *command [] = {"cat", NULL};

    wfd_t wfd = { NULL, NULL, 0 };
    will_return(__wrap_wpopenv, &wfd);
    will_return(__wrap_wpclose, 0);

    expect_string(__wrap__mwarn, formatted_msg, "'/tmp/tmp_file-XXXXXX' filesize is larger than the maximum allowed (0 MB). File skipped.");

    assert_int_equal(OS_MD5_SHA1_SHA256_File(file_name, command, md5buffer, sha1buffer, sha256buffer, OS_TEXT, 1), -1);
}

void test_md5_sha1_sha256_file_max_size_fail(void **state)
{
    char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";
    const char *string_sha256 = "3c8727e019a42b444667a587b6001251becadabbb36bfed8087a92c18882d111";

    /* create tmp file */
    char file_name[256] = "/tmp/tmp_file-XXXXXX";

    FILE * fp = 0x1;
    expect_wfopen(file_name, "r", fp);
    expect_fread(string, strlen(string));
    expect_fclose(fp, 0);

    os_md5 md5buffer;
    os_sha1 sha1buffer;
    os_sha256 sha256buffer;

    expect_string(__wrap__mwarn, formatted_msg, "'/tmp/tmp_file-XXXXXX' filesize is larger than the maximum allowed (0 MB). File skipped.");

    assert_int_equal(OS_MD5_SHA1_SHA256_File(file_name, NULL, md5buffer, sha1buffer, sha256buffer, OS_TEXT, 1), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_md5_sha1_sha256_file),
        cmocka_unit_test(test_md5_sha1_sha256_cmd_file),
        cmocka_unit_test(test_md5_sha1_sha256_cmd_file_fail),
        cmocka_unit_test(test_md5_sha1_sha256_file_fail),
        cmocka_unit_test(test_md5_sha1_sha256_cmd_file_max_size_fail),
        cmocka_unit_test(test_md5_sha1_sha256_file_max_size_fail),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
