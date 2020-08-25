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

#include "../headers/file_op.h"

static int unit_testing;

/* redefinitons/wrapping */

int __wrap_isChroot() {
    return mock();
}

int __wrap_chmod(const char *path)
{
    check_expected_ptr(path);
    return mock();
}

int __wrap_getpid()
{
    return 42;
}

int __wrap_File_DateofChange(const char *file)
{
    return 1;
}

int __wrap_stat(const char * path, struct stat * buf)
{
    memset(buf, 0, sizeof(struct stat));
    return 0;
}

int __wrap_unlink(const char *file)
{
    check_expected_ptr(file);
    return mock();
}

int __wrap__merror()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

int __wrap__minfo()
{
    return 0;
}

int __wrap__mferror(const char * file, int line, const char * func, const char *msg, ...){
    return 0;
}

extern FILE* __real_fopen(const char* path, const char* mode);
FILE* __wrap_fopen(const char* path, const char* mode) {
    if(unit_testing) {
        check_expected_ptr(path);
        check_expected(mode);
        return mock_ptr_type(FILE*);
    } else {
        return __real_fopen(path, mode);
    }
}

size_t __real_fread(void *ptr, size_t size, size_t n, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t n, FILE *stream) {
    if (unit_testing) {
        strncpy((char *) ptr, mock_type(char *), n);
        return mock();
    }
    return __real_fread(ptr, size, n, stream);
}

extern int __real_fclose ( FILE * stream );
int __wrap_fclose ( FILE * stream ) {
    if(!unit_testing)
        return __real_fclose(stream);
    return 0;
}

int __wrap_bzip2_uncompress(const char *filebz2, const char *file) {

    check_expected_ptr(filebz2);
    check_expected_ptr(file);
    return mock();
}

extern int __real_fprintf ( FILE * stream, const char * format, ... );
int __wrap_fprintf ( FILE * stream, const char * format, ... ) {
    char formatted_msg[60];
    va_list args;

    va_start(args, format);
    vsnprintf(formatted_msg, 60, format, args);
    va_end(args);

    if(!unit_testing)
        return __real_fprintf(stream, formatted_msg);

    check_expected(stream);
    check_expected(formatted_msg);
    return 0;
}

int __wrap__mdebug1() {
    return 0;
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

static int CreatePID_teardown(void **state) {
    remove("./test_file.tmp");

    if(*state) {
        free(*state);
    }
    return 0;
}

void test_CreatePID_success(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_chmod, path, "/var/run/test-42.pid");
    will_return(__wrap_chmod, 0);

    expect_string(__wrap_fopen, path, "/var/run/test-42.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fprintf, stream, 1);
    expect_string(__wrap_fprintf, formatted_msg, "42\n");

    ret = CreatePID("test", 42);
    assert_int_equal(0, ret);
}

void test_CreatePID_failure_chmod(void **state)
{
    (void) state;
    int ret;
    FILE* fp = __real_fopen("./test_file.tmp", "a");

    assert_non_null(fp);

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_chmod, path, "/var/run/test-42.pid");
    will_return(__wrap_chmod, -1);

    expect_string(__wrap_fopen, path, "/var/run/test-42.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, fp);

    expect_value(__wrap_fprintf, stream, fp);
    expect_string(__wrap_fprintf, formatted_msg, "42\n");

    ret = CreatePID("test", 42);
    assert_int_equal(-1, ret);
}

void test_CreatePID_failure_fopen(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/var/run/test-42.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, NULL);

    ret = CreatePID("test", 42);
    assert_int_equal(-1, ret);
}

void test_DeletePID_success(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);
    expect_string(__wrap_unlink, file, "/var/run/test-42.pid");
    will_return(__wrap_unlink, 0);

    ret = DeletePID("test");
    assert_int_equal(0, ret);
}


void test_DeletePID_failure(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_unlink, file, "/var/ossec/var/run/test-42.pid");
    will_return(__wrap_unlink, 1);

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

    ret = w_is_compressed_bz2_file(path);
    assert_int_equal(ret, 0);
}

// w_uncompress_bz2_gz_file

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

    ret = w_uncompress_bz2_gz_file(path, dest);
    assert_int_equal(ret, 0);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_CreatePID_success, CreatePID_teardown),
        cmocka_unit_test_teardown(test_CreatePID_failure_chmod, CreatePID_teardown),
        cmocka_unit_test(test_CreatePID_failure_fopen),
        cmocka_unit_test(test_DeletePID_success),
        cmocka_unit_test(test_DeletePID_failure),
        cmocka_unit_test(test_w_is_compressed_gz_file_uncompressed),
        cmocka_unit_test(test_w_is_compressed_bz2_file_compressed),
        cmocka_unit_test(test_w_is_compressed_bz2_file_uncompressed),
        cmocka_unit_test(test_w_uncompress_bz2_gz_file_bz2)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
