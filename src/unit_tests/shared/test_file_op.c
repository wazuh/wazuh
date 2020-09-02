/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "headers/defs.h"

#include "../wrappers/common.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../headers/file_op.h"


#ifdef TEST_SERVER
int __wrap_bzip2_uncompress(const char *filebz2, const char *file) {

    check_expected_ptr(filebz2);
    check_expected_ptr(file);
    return mock();
}
#endif


/* setups/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

void test_CreatePID_success(void **state)
{
    (void) state;
    int ret;
    char* content = NULL;

    *state = content;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/var/run/test-2345.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fprintf, __stream, 1);
    expect_string(__wrap_fprintf, formatted_msg, "2345\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_chmod, path, "/var/run/test-2345.pid");
    will_return(__wrap_chmod, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    ret = CreatePID("test", 2345);
    assert_int_equal(0, ret);
}

void test_CreatePID_failure_chmod(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/var/run/test-2345.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fprintf, __stream, 1);
    expect_string(__wrap_fprintf, formatted_msg, "2345\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object '/var/run/test-2345.pid' due to [(0)-(Success)].");

    expect_string(__wrap_chmod, path, "/var/run/test-2345.pid");
    will_return(__wrap_chmod, -1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    ret = CreatePID("test", 2345);
    assert_int_equal(-1, ret);
}

void test_CreatePID_failure_fopen(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/var/run/test-2345.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, NULL);

    ret = CreatePID("test", 2345);
    assert_int_equal(-1, ret);
}

void test_DeletePID_success(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);
    expect_string(__wrap_unlink, file, "/var/run/test-2345.pid");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_stat, __file, "/var/run/test-2345.pid");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, 0);

    ret = DeletePID("test");
    assert_int_equal(0, ret);
}


void test_DeletePID_failure(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_unlink, file, "/var/ossec/var/run/test-2345.pid");
    will_return(__wrap_unlink, 1);

    expect_string(__wrap_stat, __file, "/var/ossec/var/run/test-2345.pid");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, 0);

    expect_string(__wrap__mferror, formatted_msg,
        "(1129): Could not unlink file '/var/ossec/var/run/test-2345.pid' due to [(0)-(Success)].");

    ret = DeletePID("test");
    assert_int_equal(-1, ret);
}

// w_is_compressed_gz_file

void test_w_is_compressed_gz_file_uncompressed(void **state) {

    char * path = "/test/file.gz";
    int ret = 0;

    expect_string(__wrap_fopen, path, "/test/file.gz");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "fake");
    will_return(__wrap_fread, 2);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    ret = w_is_compressed_gz_file(path);
    assert_int_equal(ret, 0);
}

// w_is_compressed_bz2_file

void test_w_is_compressed_bz2_file_compressed(void **state) {

    char * path = "/test/file.bz2";
    int ret = 0;

    expect_string(__wrap_fopen, path, "/test/file.bz2");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    // BZh is 0x42 0x5a 0x68
    will_return(__wrap_fread, "BZh");
    will_return(__wrap_fread, 3);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    ret = w_is_compressed_bz2_file(path);
    assert_int_equal(ret, 1);
}

void test_w_is_compressed_bz2_file_uncompressed(void **state) {

    char * path = "/test/file.bz2";
    int ret = 0;

    expect_string(__wrap_fopen, path, "/test/file.bz2");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "fake");
    will_return(__wrap_fread, 3);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    ret = w_is_compressed_bz2_file(path);
    assert_int_equal(ret, 0);
}

// w_uncompress_bz2_gz_file

#ifdef TEST_SERVER

void test_w_uncompress_bz2_gz_file_bz2(void **state) {

    char * path = "/test/file.bz2";
    char * dest = "/test/file";
    int ret;

    expect_string(__wrap_fopen, path, "/test/file.bz2");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "BZh");
    will_return(__wrap_fread, 3);

    expect_string(__wrap_bzip2_uncompress, filebz2, "/test/file.bz2");
    expect_string(__wrap_bzip2_uncompress, file, "/test/file");
    will_return(__wrap_bzip2_uncompress, 0);

    expect_string(__wrap_fopen, path, "/test/file.bz2");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 0);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    ret = w_uncompress_bz2_gz_file(path, dest);
    assert_int_equal(ret, 0);

}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_CreatePID_success),
        cmocka_unit_test(test_CreatePID_failure_chmod),
        cmocka_unit_test(test_CreatePID_failure_fopen),
        cmocka_unit_test(test_DeletePID_success),
        cmocka_unit_test(test_DeletePID_failure),
        cmocka_unit_test(test_w_is_compressed_gz_file_uncompressed),
        cmocka_unit_test(test_w_is_compressed_bz2_file_compressed),
        cmocka_unit_test(test_w_is_compressed_bz2_file_uncompressed),
#ifdef TEST_SERVER
        cmocka_unit_test(test_w_uncompress_bz2_gz_file_bz2)
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
