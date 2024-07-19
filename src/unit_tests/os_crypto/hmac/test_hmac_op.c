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
#include "../../os_crypto/hmac/hmac.h"
#include "../../wrappers/common.h"

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

void test_hmac_string(void **state)
{
    const char *key = "test_key";
    const char *string = "test string";
    const char *string_hmac = "bcbf151b282a23e0849453f2b5732bfd8226e16a";

    os_sha1 buffer;

    assert_int_equal(OS_HMAC_SHA1_Str(key, string, buffer), 0);

    assert_string_equal(buffer, string_hmac);
}

void test_hmac_file(void **state)
{
    const char *key = "test_key";
    const char *string = "test string";
    const char *string_hmac = "bcbf151b282a23e0849453f2b5732bfd8226e16a";

    os_sha1 buffer;

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    assert_int_equal(OS_HMAC_SHA1_File(key, file_name, buffer, OS_TEXT), 0);

    assert_string_equal(buffer, string_hmac);
}

void test_hmac_string_length_key(void **state)
{
    const char *key = "test_key_abcdefghijklmnopqrstvwxzabcdefghijklmnopqrstvwxzabcdefgh";
    const char *string = "test string";
    const char *string_hmac = "11ff0061a90ab6490f35994b044fb281fd4dfa6a";

    os_sha1 buffer;

    assert_int_equal(OS_HMAC_SHA1_Str(key, string, buffer), 0);

    assert_string_equal(buffer, string_hmac);
}

void test_hmac_file_length_key(void **state)
{
    const char *key = "test_key_abcdefghijklmnopqrstvwxzabcdefghijklmnopqrstvwxzabcdefgh";
    const char *string = "test string";
    const char *string_hmac = "11ff0061a90ab6490f35994b044fb281fd4dfa6a";

    os_sha1 buffer;

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    assert_int_equal(OS_HMAC_SHA1_File(key, file_name, buffer, OS_TEXT), 0);

    assert_string_equal(buffer, string_hmac);
}

void test_hmac_file_popen_fail(void **state)
{
    const char *key = "test_key";
    const char *string = "test string";

    os_sha1 buffer;

    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);

    expect_value(__wrap_fopen, path, file_name);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    assert_int_equal(OS_HMAC_SHA1_File(key, file_name, buffer, OS_TEXT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_hmac_string),
        cmocka_unit_test(test_hmac_string_length_key),
        cmocka_unit_test(test_hmac_file_length_key),
        cmocka_unit_test(test_hmac_file),
        cmocka_unit_test_setup_teardown(test_hmac_file_popen_fail, setup_group, teardown_group),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
