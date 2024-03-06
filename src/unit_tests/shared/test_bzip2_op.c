/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "../wrappers/common.h"
#include "shared.h"
#include "../headers/bzip2_op.h"
#include "../wrappers/externals/bzip2/bzlib_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* setups/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

void test_bzip2_compress_nullfile(void **state) {
    int ret;

    ret = bzip2_compress(NULL, "test");
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_nullfilebz2(void **state) {
    int ret;

    ret = bzip2_compress("test", NULL);
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_firstfopenfail(void **state) {
    int ret;
    char *string = "testfile";

    expect_value(__wrap_wfopen, path, string);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(1103): Could not open file 'testfile' due to [(0)-(Success)].");
    ret = bzip2_compress(string, "testbz2");
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_secondfopenfail(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_wfopen, path, file1);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_wfopen, path, file2);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(1103): Could not open file 'testfile2' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = bzip2_compress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_bzWriteOpen(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_wfopen, path, file1);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_wfopen, path, file2);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 2);

    expect_value(__wrap_BZ2_bzWriteOpen, f, 2);
    will_return(__wrap_BZ2_bzWriteOpen, BZ_MEM_ERROR);
    will_return(__wrap_BZ2_bzWriteOpen, NULL);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Could not open to write bz2 file (-3)'testfile2': (0)-Success");

    expect_value(__wrap_BZ2_bzWriteClose, f, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 2);
    will_return(__wrap_fclose, 1);

    ret = bzip2_compress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_BZ2_bzWrite(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_wfopen, path, file1);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_wfopen, path, file2);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 2);

    expect_value(__wrap_BZ2_bzWriteOpen, f, 2);
    will_return(__wrap_BZ2_bzWriteOpen, BZ_OK);
    will_return(__wrap_BZ2_bzWriteOpen, 3);

    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);

    expect_value(__wrap_BZ2_bzWrite, f, 3);
    expect_string(__wrap_BZ2_bzWrite, buf, "teststring");
    expect_value(__wrap_BZ2_bzWrite, len, 10);
    will_return(__wrap_BZ2_bzWrite, BZ_MEM_ERROR);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Could not write bz2 file (-3)'testfile2': (0)-Success");

    expect_value(__wrap_BZ2_bzWriteClose, f, 3);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 2);
    will_return(__wrap_fclose, 1);

    ret = bzip2_compress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_success(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_wfopen, path, file1);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_wfopen, path, file2);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 2);

    expect_value(__wrap_BZ2_bzWriteOpen, f, 2);
    will_return(__wrap_BZ2_bzWriteOpen, BZ_OK);
    will_return(__wrap_BZ2_bzWriteOpen, 3);

    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);

    expect_value(__wrap_BZ2_bzWrite, f, 3);
    expect_string(__wrap_BZ2_bzWrite, buf, "teststring");
    expect_value(__wrap_BZ2_bzWrite, len, 10);
    will_return(__wrap_BZ2_bzWrite, BZ_OK);

    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_BZ2_bzWriteClose, f, 3);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 2);
    will_return(__wrap_fclose, 1);

    ret = bzip2_compress(file1, file2);
    assert_int_equal(ret, 0);
}


void test_bzip2_uncompress_nullfile(void **state) {
    int ret;

    ret = bzip2_uncompress(NULL, "test");
    assert_int_equal(ret, -1);
}

void test_bzip2_uncompress_nullfilebz2(void **state) {
    int ret;

    ret = bzip2_uncompress("test", NULL);
    assert_int_equal(ret, -1);
}

void test_bzip2_uncompress_firstfopenfail(void **state) {
    int ret;
    char *string = "testfile";

    expect_value(__wrap_wfopen, path, string);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(1103): Could not open file 'testfile' due to [(0)-(Success)].");
    ret = bzip2_uncompress(string, "testbz2");
    assert_int_equal(ret, -1);
}

void test_bzip2_uncompress_secondfopenfail(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_wfopen, path, file1);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_wfopen, path, file2);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(1103): Could not open file 'testfile2' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = bzip2_uncompress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_uncompress_bzReadOpen(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_wfopen, path, file1);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_wfopen, path, file2);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 2);

    expect_value(__wrap_BZ2_bzReadOpen, f, 1);
    will_return(__wrap_BZ2_bzReadOpen, BZ_MEM_ERROR);
    will_return(__wrap_BZ2_bzReadOpen, NULL);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "BZ2_bzReadOpen(-3)'testfile': (0)-Success");

    expect_value(__wrap_BZ2_bzReadClose, f, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 2);
    will_return(__wrap_fclose, 1);

    ret = bzip2_uncompress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_uncompress_bzReadsuccess(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_wfopen, path, file1);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_wfopen, path, file2);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 2);

    expect_value(__wrap_BZ2_bzReadOpen, f, 1);
    will_return(__wrap_BZ2_bzReadOpen, BZ_OK);
    will_return(__wrap_BZ2_bzReadOpen, 3);

    expect_value(__wrap_BZ2_bzRead, f, 3);
    will_return(__wrap_BZ2_bzRead, BZ_OK);
    will_return(__wrap_BZ2_bzRead, 11);
    will_return(__wrap_BZ2_bzRead, "teststring");

    will_return(__wrap_fwrite, 11);

    expect_value(__wrap_BZ2_bzRead, f, 3);
    will_return(__wrap_BZ2_bzRead, BZ_STREAM_END);
    will_return(__wrap_BZ2_bzRead, 0);
    will_return(__wrap_BZ2_bzRead, "");

    will_return(__wrap_fwrite, 0);

    expect_value(__wrap_BZ2_bzReadClose, f, 3);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 2);
    will_return(__wrap_fclose, 1);

    ret = bzip2_uncompress(file1, file2);
    assert_int_equal(ret, 0);
}

void test_bzip2_uncompress_bzReadfail(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_wfopen, path, file1);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_wfopen, path, file2);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 2);

    expect_value(__wrap_BZ2_bzReadOpen, f, 1);
    will_return(__wrap_BZ2_bzReadOpen, BZ_OK);
    will_return(__wrap_BZ2_bzReadOpen, 3);

    expect_value(__wrap_BZ2_bzRead, f, 3);
    will_return(__wrap_BZ2_bzRead, BZ_OK);
    will_return(__wrap_BZ2_bzRead, 11);
    will_return(__wrap_BZ2_bzRead, "teststring");

    will_return(__wrap_fwrite, 4);

    expect_value(__wrap_BZ2_bzRead, f, 3);
    will_return(__wrap_BZ2_bzRead, BZ_MEM_ERROR);
    will_return(__wrap_BZ2_bzRead, 0);
    will_return(__wrap_BZ2_bzRead, "");
    expect_string(__wrap__mdebug2, formatted_msg,
                  "BZ2_bzRead(-3)'testfile': (0)-Success");

    expect_value(__wrap_BZ2_bzReadClose, f, 3);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 2);
    will_return(__wrap_fclose, 1);

    ret = bzip2_uncompress(file1, file2);
    assert_int_equal(ret, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bzip2_compress_nullfile),
        cmocka_unit_test(test_bzip2_compress_nullfilebz2),
        cmocka_unit_test(test_bzip2_compress_firstfopenfail),
        cmocka_unit_test(test_bzip2_compress_secondfopenfail),
        cmocka_unit_test(test_bzip2_compress_bzWriteOpen),
        cmocka_unit_test(test_bzip2_compress_BZ2_bzWrite),
        cmocka_unit_test(test_bzip2_compress_success),
        cmocka_unit_test(test_bzip2_uncompress_nullfile),
        cmocka_unit_test(test_bzip2_uncompress_nullfilebz2),
        cmocka_unit_test(test_bzip2_uncompress_firstfopenfail),
        cmocka_unit_test(test_bzip2_uncompress_secondfopenfail),
        cmocka_unit_test(test_bzip2_uncompress_bzReadOpen),
        cmocka_unit_test(test_bzip2_uncompress_bzReadsuccess),
        cmocka_unit_test(test_bzip2_uncompress_bzReadfail),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
