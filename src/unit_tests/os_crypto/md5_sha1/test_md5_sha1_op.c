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
#include "../../wrappers/libc/stdio_wrappers.h"

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

void test_md5_sha1_cmd_file_snprintf_fail(void **state)
{
    const char *string = "teststring";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 md5buffer;
    os_sha1 sha1buffer;

    expect_value(__wrap_snprintf, __maxlen, OS_MAXSTR);
    expect_string(__wrap_snprintf, __format, "%s %s");

    will_return(__wrap_snprintf, -1);

    assert_int_equal(OS_MD5_SHA1_File(file_name, "cat ", md5buffer, sha1buffer, OS_TEXT), -1);
}

void test_md5_sha1_cmd_file_popen_fail(void **state)
{
    const char *string = "teststring";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 md5buffer;
    os_sha1 sha1buffer;

    expect_value(__wrap_snprintf, __maxlen, OS_MAXSTR);
    expect_string(__wrap_snprintf, __format, "%s %s");

    will_return(__wrap_snprintf, 25);

    expect_popen("", "r", NULL);

    assert_int_equal(OS_MD5_SHA1_File(file_name, "cat ", md5buffer, sha1buffer, OS_TEXT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_md5_sha1_file),
            cmocka_unit_test(test_md5_sha1_cmd_file),
            cmocka_unit_test(test_md5_sha1_cmd_file_fail),
            cmocka_unit_test_setup_teardown(test_md5_sha1_cmd_file_snprintf_fail, setup_group, teardown_group),
            cmocka_unit_test_setup_teardown(test_md5_sha1_cmd_file_popen_fail, setup_group, teardown_group),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
