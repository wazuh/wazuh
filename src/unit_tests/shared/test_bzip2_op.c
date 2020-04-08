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
#include "shared.h"

#include "../headers/bzip2_op.h"

static int unit_testing;


extern FILE* __real_fopen(const char* path, const char* mode);
FILE* __wrap_fopen(const char* path, const char* mode) {
    if(unit_testing) {
        check_expected_ptr(path);
        check_expected(mode);
        return mock_ptr_type(FILE*);
    }
    return __real_fopen(path, mode);
}

size_t __real_fread(void *ptr, size_t size, size_t n, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t n, FILE *stream) {
    if (unit_testing) {
        strncpy((char *) ptr, mock_type(char *), n);
        return mock();
    }
    return __real_fread(ptr, size, n, stream);
}

size_t __real_fwrite(const void * ptr, size_t size, size_t count, FILE * stream);
size_t __wrap_fwrite(const void * ptr, size_t size, size_t count, FILE * stream) {
    if (unit_testing) {
        return mock();
    }
    return __real_fwrite(ptr, size, count, stream);
}

int __wrap_fclose() {
    return 0;
}

BZFILE* __wrap_BZ2_bzWriteOpen(int* bzerror,
                               FILE* f,
                               int blockSize100k,
                               int verbosity,
                               int workFactor) {
    check_expected_ptr(f);
    *bzerror = mock();

    return mock_type(BZFILE*);
}

void __wrap_BZ2_bzReadClose(int* bzerror,
                            BZFILE* f,
                            int abandon,
                            unsigned int* nbytes_in,
                            unsigned int* nbytes_out) {
    return;
}

void __wrap_BZ2_bzWriteClose64(int* bzerror,
                               BZFILE* f,
                               int abandon,
                               unsigned int* nbytes_in_lo32,
                               unsigned int* nbytes_in_hi32,
                               unsigned int* nbytes_out_lo32,
                               unsigned int* nbytes_out_hi32) {
    check_expected_ptr(f);
    *bzerror = mock();
}

BZFILE* __wrap_BZ2_bzReadOpen(int* bzerror,
                          FILE* f,
                          int verbosity,
                          int small,
                          void* unused,
                          int nUnused) {
    check_expected_ptr(f);
    *bzerror = mock();

    return mock_type(BZFILE*);
}

int __wrap_BZ2_bzRead(int* bzerror,
                      BZFILE* f,
                      void* buf,
                      int len) {
    check_expected_ptr(f);
    *bzerror = mock();
    int n = mock();
    if(n <= len) {
        memcpy(buf, mock_type(void*), n);
    }
    return n;
}

void __wrap_BZ2_bzWrite(int* bzerror,
                       BZFILE* f,
                       void* buf,
                       int len) {
    check_expected_ptr(f);
    check_expected(buf);
    check_expected(len);
    *bzerror = mock();
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;
    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);
    check_expected(formatted_msg);
}

/* setups/teardowns */
static int setup_group(void **state) {
    unit_testing = 1;
    return 0;
}

static int teardown_group(void **state) {
    unit_testing = 0;
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

    expect_value(__wrap_fopen, path, string);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(1103): Could not open file 'testfile' due to [(0)-(Success)].");
    ret = bzip2_compress(string, "testbz2");
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_secondfopenfail(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(1103): Could not open file 'testfile2' due to [(0)-(Success)].");
    ret = bzip2_compress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_bzWriteOpen(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 2);

    expect_value(__wrap_BZ2_bzWriteOpen, f, 2);
    will_return(__wrap_BZ2_bzWriteOpen, BZ_MEM_ERROR);
    will_return(__wrap_BZ2_bzWriteOpen, NULL);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Could not open to write bz2 file (-3)'testfile2': (0)-Success");

    ret = bzip2_compress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_BZ2_bzWrite(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 2);

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

    ret = bzip2_compress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_bzWriteClose64(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 2);

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

    expect_value(__wrap_BZ2_bzWriteClose64, f, 3);
    will_return(__wrap_BZ2_bzWriteClose64, BZ_MEM_ERROR);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "BZ2_bzWriteClose64(-3)'testfile2': (0)-Success");

    ret = bzip2_compress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_compress_success(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 2);

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

    expect_value(__wrap_BZ2_bzWriteClose64, f, 3);
    will_return(__wrap_BZ2_bzWriteClose64, BZ_OK);

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

    expect_value(__wrap_fopen, path, string);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(1103): Could not open file 'testfile' due to [(0)-(Success)].");
    ret = bzip2_uncompress(string, "testbz2");
    assert_int_equal(ret, -1);
}

void test_bzip2_uncompress_secondfopenfail(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(1103): Could not open file 'testfile2' due to [(0)-(Success)].");
    ret = bzip2_uncompress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_uncompress_bzReadOpen(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 2);

    expect_value(__wrap_BZ2_bzReadOpen, f, 1);
    will_return(__wrap_BZ2_bzReadOpen, BZ_MEM_ERROR);
    will_return(__wrap_BZ2_bzReadOpen, NULL);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "BZ2_bzReadOpen(-3)'testfile': (0)-Success");

    ret = bzip2_uncompress(file1, file2);
    assert_int_equal(ret, -1);
}

void test_bzip2_uncompress_bzReadsuccess(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 2);

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

    ret = bzip2_uncompress(file1, file2);
    assert_int_equal(ret, 0);
}

void test_bzip2_uncompress_bzReadfail(void **state) {
    int ret;
    char *file1 = "testfile";
    char *file2 = "testfile2";

    expect_value(__wrap_fopen, path, file1);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fopen, path, file2);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 2);

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
        cmocka_unit_test(test_bzip2_compress_bzWriteClose64),
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
