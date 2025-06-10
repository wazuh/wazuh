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
#include <stdlib.h>
#include <string.h>
#include "../headers/defs.h"
#include "../headers/file_op.h"
#include "../error_messages/error_messages.h"
#include "../wrappers/common.h"
#include "../wrappers/libc/stdlib_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/externals/zlib/zlib_wrappers.h"
#ifdef WIN32
#include "../wrappers/windows/fileapi_wrappers.h"
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

#ifdef TEST_WINAGENT

#define N_PATHS 5

static void expect_find_first_file(const char *file_path, const char *name, DWORD attrs, HANDLE handle) {
    expect_string(wrap_FindFirstFile, lpFileName, file_path);
    will_return(wrap_FindFirstFile, name);
    if (name != NULL) {
        will_return(wrap_FindFirstFile, attrs);
    }

    will_return(wrap_FindFirstFile, handle);
}

static void expect_find_next_file(HANDLE handle, const char *name, DWORD attrs, BOOL ret) {
    expect_value(wrap_FindNextFile, hFindFile, handle);
    will_return(wrap_FindNextFile, name);
    if (name != NULL) {
        will_return(wrap_FindNextFile, attrs);
    }
    will_return(wrap_FindNextFile, ret);
}

static int teardown_win32_wildcards(void **state) {
    char **vector = *state;

    for (int i = 0; vector[i]; i++) {
        free(vector[i]);
    }
    free(vector);
    return 0;
}
#else

extern char * __real_getenv(const char *name);
char * __wrap_getenv(const char *name) {
    if (!test_mode) {
        return __real_getenv(name);
    }
    check_expected(name);
    return mock_type(char *);
}

void test_CreatePID_success(void **state)
{
    (void) state;
    int ret;
    char* content = NULL;

    *state = content;

    expect_string(__wrap_fopen, path, "var/run/test-2345.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fprintf, __stream, 1);
    expect_string(__wrap_fprintf, formatted_msg, "2345\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_chmod, path, "var/run/test-2345.pid");
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

    expect_string(__wrap_fopen, path, "var/run/test-2345.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fprintf, __stream, 1);
    expect_string(__wrap_fprintf, formatted_msg, "2345\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_chmod, path, "var/run/test-2345.pid");
    will_return(__wrap_chmod, 1);

    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object 'var/run/test-2345.pid' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    ret = CreatePID("test", 2345);
    assert_int_equal(-1, ret);
}

void test_CreatePID_failure_fopen(void **state)
{
    (void) state;
    int ret;

    expect_string(__wrap_fopen, path, "var/run/test-2345.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, NULL);

    ret = CreatePID("test", 2345);
    assert_int_equal(-1, ret);
}

void test_DeletePID_success(void **state)
{
    (void) state;
    int ret = 0;

    struct stat stat_delete = { .st_mode = 0 };

    expect_string(__wrap_unlink, file, "var/run/test-2345.pid");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_stat, __file, "var/run/test-2345.pid");
    will_return(__wrap_stat, &stat_delete);
    will_return(__wrap_stat, 0);

    ret = DeletePID("test");
    assert_int_equal(0, ret);
}

void test_DeletePID_failure(void **state)
{
    (void) state;
    int ret = 0;
    struct stat stat_delete = { .st_mode = 0 };

    expect_string(__wrap_unlink, file, "var/run/test-2345.pid");
    will_return(__wrap_unlink, 1);

    expect_string(__wrap_stat, __file, "var/run/test-2345.pid");
    will_return(__wrap_stat, &stat_delete);
    will_return(__wrap_stat, 0);

    expect_string(__wrap__mferror, formatted_msg, "(1129): Could not unlink file 'var/run/test-2345.pid' due to [(0)-(Success)].");

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

// is_program_available

void test_is_program_available_success(void **state) {
    char * program = "test_program";
    char * path = "/bin:/usr/bin:/usr/local/bin";
    int ret = 0;

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_access, __name, "/bin/test_program");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 1);

    expect_string(__wrap_access, __name, "/usr/bin/test_program");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 0);

    ret = is_program_available(program);
    assert_int_equal(ret, 1);
}

void test_is_program_available_failure(void **state) {
    char * program = "test_program";
    int ret = 0;

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, NULL);

    ret = is_program_available(program);
    assert_int_equal(ret, 0);
}

void test_is_program_available_null(void **state) {
    char * program = NULL;
    int ret = 0;

    ret = is_program_available(program);
    assert_int_equal(ret, 0);
}

void test_is_program_available_not_found(void **state) {
    char * program = "test_program";
    char * path = "/bin:/usr/bin:/usr/local/bin";
    int ret = 0;

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_access, __name, "/bin/test_program");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 1);

    expect_string(__wrap_access, __name, "/usr/bin/test_program");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 1);

    expect_string(__wrap_access, __name, "/usr/local/bin/test_program");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 1);

    ret = is_program_available(program);
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

    expect_string(__wrap__mdebug1, formatted_msg, "The file '/test/file.bz2' was successfully uncompressed into '/test/file'");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    ret = w_uncompress_bz2_gz_file(path, dest);
    assert_int_equal(ret, 0);
}

void test_MergeAppendFile_open_fail(void **state) {

    FILE * finalfp = (FILE *)5;
    char * file = "test.txt";
    int path_offset = -1;
    int ret;

    expect_string(__wrap_fopen, path, file);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "Unable to open file: 'test.txt' due to [(0)-(Success)].");

    ret = MergeAppendFile(finalfp, file, path_offset);
    assert_int_equal(ret, 0);
}

void test_MergeAppendFile_fseek_fail(void **state) {

    FILE * finalfp = (FILE *)5;
    char * file = "test.txt";
    int path_offset = -1;
    int ret;

    expect_string(__wrap_fopen, path, file);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 6);

    will_return(__wrap_fseek, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to set EOF offset in file: 'test.txt', due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 6);
    will_return(__wrap_fclose, 1);

    ret = MergeAppendFile(finalfp, file, path_offset);
    assert_int_equal(ret, 0);
}

void test_MergeAppendFile_fseek2_fail(void **state) {

    FILE * finalfp = (FILE *)5;
    char * file = "/test/shared/default/test.txt";
    int path_offset = -1;
    int ret;

    expect_string(__wrap_fopen, path, file);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 6);

    will_return(__wrap_fseek, 0);

    will_return(__wrap_ftell, 0);
    expect_string(__wrap__mwarn, formatted_msg, "File '/test/shared/default/test.txt' is empty.");

    expect_value(__wrap_fprintf, __stream, finalfp);
    expect_string(__wrap_fprintf, formatted_msg, "!0 test.txt\n");
    will_return(__wrap_fprintf, 0);

    will_return(__wrap_fseek, -2);

    expect_string(__wrap__merror, formatted_msg, "Unable to set the offset in file: '/test/shared/default/test.txt', due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 6);
    will_return(__wrap_fclose, 1);

    ret = MergeAppendFile(finalfp, file, path_offset);
    assert_int_equal(ret, 0);
}

void test_MergeAppendFile_diff_ftell(void **state) {

    FILE * finalfp = (FILE *)5;
    char * file = "/test/shared/default/test.txt";
    int path_offset = 0;
    int ret;

    expect_string(__wrap_fopen, path, file);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 6);

    will_return(__wrap_fseek, 0);

    will_return(__wrap_ftell, 25);

    expect_value(__wrap_fprintf, __stream, finalfp);
    expect_string(__wrap_fprintf, formatted_msg, "!25 /test/shared/default/test.txt\n");
    will_return(__wrap_fprintf, 0);

    will_return(__wrap_fseek, 0);

    will_return(__wrap_fread, "test.txt");
    will_return(__wrap_fread, 1);

    will_return(__wrap_fwrite, 0);

    will_return(__wrap_fread, "test.txt");
    will_return(__wrap_fread, 0);

    will_return(__wrap_ftell, 33);

    expect_value(__wrap_fclose, _File, 6);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__merror, formatted_msg, "File '/test/shared/default/test.txt' was modified after getting its size.");

    ret = MergeAppendFile(finalfp, file, path_offset);
    assert_int_equal(ret, 0);
}

void test_MergeAppendFile_success(void **state) {

    FILE * finalfp = (FILE *)5;
    char * file = "/test/shared/default/test.txt";
    int path_offset = 0;
    int ret;

    expect_string(__wrap_fopen, path, file);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 6);

    will_return(__wrap_fseek, 0);

    will_return(__wrap_ftell, 25);

    expect_value(__wrap_fprintf, __stream, finalfp);
    expect_string(__wrap_fprintf, formatted_msg, "!25 /test/shared/default/test.txt\n");
    will_return(__wrap_fprintf, 0);

    will_return(__wrap_fseek, 0);

    will_return(__wrap_fread, "test.txt");
    will_return(__wrap_fread, 1);

    will_return(__wrap_fwrite, 0);

    will_return(__wrap_fread, "test.txt");
    will_return(__wrap_fread, 0);

    will_return(__wrap_ftell, 25);

    expect_value(__wrap_fclose, _File, 6);
    will_return(__wrap_fclose, 1);

    ret = MergeAppendFile(finalfp, file, path_offset);
    assert_int_equal(ret, 1);
}

#endif

// w_compress_gzfile

void test_w_compress_gzfile_wfopen_fail(void **state){

    int ret;
    char *srcfile = "testfilesrc";
    char *dstfile = "testfiledst.gz";

    expect_string(__wrap_fopen, path, srcfile);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "in w_compress_gzfile(): fopen error testfilesrc (0):'Success'");

    ret = w_compress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, -1);
}

void test_w_compress_gzfile_gzopen_fail(void **state){

    int ret;
    char *srcfile = "testfilesrc";
    char *dstfile = "testfiledst.gz";

    expect_string(__wrap_fopen, path, srcfile);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_gzopen, path, dstfile);
    expect_string(__wrap_gzopen, mode, "w");
    will_return(__wrap_gzopen, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__merror, formatted_msg, "in w_compress_gzfile(): gzopen error testfiledst.gz (0):'Success'");

    ret = w_compress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, -1);
}

void test_w_compress_gzfile_write_error(void **state){

    int ret;
    char *srcfile = "testfilesrc";
    char *dstfile = "testfiledst.gz";

    expect_string(__wrap_fopen, path, srcfile);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_gzopen, path, dstfile);
    expect_string(__wrap_gzopen, mode, "w");
    will_return(__wrap_gzopen, 2);

    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);

    expect_value(__wrap_gzwrite, file, 2);
    expect_string(__wrap_gzwrite, buf, "teststring");
    expect_value(__wrap_gzwrite, len, 10);
    will_return(__wrap_gzwrite, Z_ERRNO);

    expect_value(__wrap_gzerror, file, 2);
    will_return(__wrap_gzerror, Z_ERRNO);
    will_return(__wrap_gzerror, "Test error");
    expect_string(__wrap__merror, formatted_msg, "in w_compress_gzfile(): Compression error: Test error");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_gzclose, file, 2);
    will_return(__wrap_gzclose, 1);

    ret = w_compress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, -1);
}

void test_w_compress_gzfile_success(void **state){

    int ret;
    char *srcfile = "testfilesrc";
    char *dstfile = "testfiledst.gz";

    expect_string(__wrap_fopen, path, srcfile);
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_gzopen, path, dstfile);
    expect_string(__wrap_gzopen, mode, "w");
    will_return(__wrap_gzopen, 2);

    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);

    expect_value(__wrap_gzwrite, file, 2);
    expect_string(__wrap_gzwrite, buf, "teststring");
    expect_value(__wrap_gzwrite, len, 10);
    will_return(__wrap_gzwrite, 10);

    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_gzclose, file, 2);
    will_return(__wrap_gzclose, 1);

    ret = w_compress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, 0);
}

// w_uncompress_gzfile

void test_w_uncompress_gzfile_lstat_fail(void **state) {
    int ret;
    struct stat buf = { .st_mode = S_IFREG };
    char *srcfile = "testfile.gz";
    char *dstfile = "testfiledst";

    expect_string(__wrap_lstat, filename, srcfile);
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, -1);

    ret = w_uncompress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, -1);
}

void test_w_uncompress_gzfile_fopen_fail(void **state) {
    int ret;
    struct stat buf = { .st_mode = S_IFREG };
    char *srcfile = "testfile.gz";
    char *dstfile = "testfiledst";

    expect_string(__wrap_lstat, filename, srcfile);
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_fopen, path, dstfile);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "in w_uncompress_gzfile(): fopen error testfiledst (0):'Success'");

    ret = w_uncompress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, -1);
}

void test_w_uncompress_gzfile_gzopen_fail(void **state) {
    int ret;
    struct stat buf = { .st_mode = S_IFREG };
    char *srcfile = "testfile.gz";
    char *dstfile = "testfiledst";

    expect_string(__wrap_lstat, filename, srcfile);
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_fopen, path, dstfile);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_gzopen, path, srcfile);
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "in w_uncompress_gzfile(): gzopen error testfile.gz (0):'Success'");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = w_uncompress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, -1);
}

void test_w_uncompress_gzfile_first_read_fail(void **state) {
    int ret;
    struct stat buf = { .st_mode = S_IFREG };
    char *srcfile = "testfile.gz";
    char *dstfile = "testfiledst";

    expect_string(__wrap_lstat, filename, srcfile);
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_fopen, path, dstfile);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_gzopen, path, srcfile);
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 2);

    expect_value(__wrap_gzread, gz_fd, 2);
    will_return(__wrap_gzread, strlen("failstring"));
    will_return(__wrap_gzread, "failstring");

    will_return(__wrap_fwrite, 0);

    expect_value(__wrap_gzeof, file, 2);
    will_return(__wrap_gzeof, 0);

    expect_value(__wrap_gzerror, file, 2);
    will_return(__wrap_gzerror, Z_BUF_ERROR);
    will_return(__wrap_gzerror, "Test error");

    expect_string(__wrap__merror, formatted_msg, "in w_uncompress_gzfile(): gzread error: 'Test error'");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_gzclose, file, 2);
    will_return(__wrap_gzclose, 1);

    ret = w_uncompress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, -1);
}

void test_w_uncompress_gzfile_first_read_success(void **state) {
    int ret;
    struct stat buf = { .st_mode = S_IFREG };
    char *srcfile = "testfile.gz";
    char *dstfile = "testfiledst";

    char buffer[OS_SIZE_8192] = {"teststring"};

    expect_string(__wrap_lstat, filename, srcfile);
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_fopen, path, dstfile);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_gzopen, path, srcfile);
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 2);

    expect_value(__wrap_gzread, gz_fd, 2);
    will_return(__wrap_gzread, OS_SIZE_8192);
    will_return(__wrap_gzread, buffer);

    will_return(__wrap_fwrite, OS_SIZE_8192);

    expect_value(__wrap_gzread, gz_fd, 2);
    will_return(__wrap_gzread, strlen(buffer));
    will_return(__wrap_gzread, buffer);

    will_return(__wrap_fwrite, 0);

    expect_value(__wrap_gzeof, file, 2);
    will_return(__wrap_gzeof, 0);

    expect_value(__wrap_gzerror, file, 2);
    will_return(__wrap_gzerror, Z_BUF_ERROR);
    will_return(__wrap_gzerror, "Test error");

    expect_string(__wrap__merror, formatted_msg, "in w_uncompress_gzfile(): gzread error: 'Test error'");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_gzclose, file, 2);
    will_return(__wrap_gzclose, 1);

    ret = w_uncompress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, -1);
}

void test_w_uncompress_gzfile_success(void **state) {
    int ret;
    struct stat buf = { .st_mode = S_IFREG };
    char *srcfile = "testfile.gz";
    char *dstfile = "testfiledst";

    expect_string(__wrap_lstat, filename, srcfile);
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_fopen, path, dstfile);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_gzopen, path, srcfile);
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 2);

    expect_value(__wrap_gzread, gz_fd, 2);
    will_return(__wrap_gzread, 10);
    will_return(__wrap_gzread, "teststring");

    will_return(__wrap_fwrite, 10);

    expect_value(__wrap_gzeof, file, 2);
    will_return(__wrap_gzeof, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_gzclose, file, 2);
    will_return(__wrap_gzclose, 1);

    ret = w_uncompress_gzfile(srcfile, dstfile);
    assert_int_equal(ret, 0);
}

// w_homedir

void test_w_homedir_first_attempt(void **state)
{
    char *argv0 = "/usr/share/wazuh/bin/test";
    struct stat stat_buf = { .st_mode = 0040000 }; // S_IFDIR
    char *val = NULL;

    expect_string(__wrap_realpath, path, "/proc/self/exe");
    will_return(__wrap_realpath, argv0);

    expect_string(__wrap_stat, __file, "/usr/share/wazuh");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    val = w_homedir(argv0);
    assert_string_equal(val, "/usr/share/wazuh");
    free(val);
}

void test_w_homedir_second_attempt(void **state)
{
    char *argv0 = "/usr/share/wazuh/bin/test";
    struct stat stat_buf = { .st_mode = 0040000 }; // S_IFDIR
    char *val = NULL;

    expect_string(__wrap_realpath, path, "/proc/self/exe");
    will_return(__wrap_realpath, NULL);

    expect_string(__wrap_realpath, path, "/proc/curproc/file");
    will_return(__wrap_realpath, argv0);

    expect_string(__wrap_stat, __file, "/usr/share/wazuh");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    val = w_homedir(argv0);
    assert_string_equal(val, "/usr/share/wazuh");
    free(val);
}

void test_w_homedir_third_attempt(void **state)
{
    char *argv0 = "/usr/share/wazuh/bin/test";
    struct stat stat_buf = { .st_mode = 0040000 }; // S_IFDIR
    char *val = NULL;

    expect_string(__wrap_realpath, path, "/proc/self/exe");
    will_return(__wrap_realpath, NULL);

    expect_string(__wrap_realpath, path, "/proc/curproc/file");
    will_return(__wrap_realpath, NULL);

    expect_string(__wrap_realpath, path, "/proc/self/path/a.out");
    will_return(__wrap_realpath, argv0);

    expect_string(__wrap_stat, __file, "/usr/share/wazuh");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    val = w_homedir(argv0);
    assert_string_equal(val, "/usr/share/wazuh");
    free(val);
}

void test_w_homedir_check_argv0(void **state)
{
    char *argv0 = "/usr/share/wazuh/bin/test";
    struct stat stat_buf = { .st_mode = 0040000 }; // S_IFDIR
    char *val = NULL;

    expect_string(__wrap_realpath, path, "/proc/self/exe");
    will_return(__wrap_realpath, NULL);
    expect_string(__wrap_realpath, path, "/proc/curproc/file");
    will_return(__wrap_realpath, NULL);

    expect_string(__wrap_realpath, path, "/proc/self/path/a.out");
    will_return(__wrap_realpath, NULL);

    expect_string(__wrap_realpath, path, argv0);
    will_return(__wrap_realpath, argv0);

    expect_string(__wrap_stat, __file, "/usr/share/wazuh");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    val = w_homedir(argv0);
    assert_string_equal(val, "/usr/share/wazuh");
    free(val);
}

void test_w_homedir_env_var(void **state)
{
    char *val = NULL;
    char *argv0 = "bin/test";
    struct stat stat_buf = { .st_mode = 0040000 }; // S_IFDIR

    expect_string(__wrap_realpath, path, "/proc/self/exe");
    will_return(__wrap_realpath, NULL);
    expect_string(__wrap_realpath, path, "/proc/curproc/file");
    will_return(__wrap_realpath, NULL);
    expect_string(__wrap_realpath, path, "/proc/self/path/a.out");
    will_return(__wrap_realpath, NULL);
    expect_string(__wrap_realpath, path, argv0);
    will_return(__wrap_realpath, NULL);

    expect_string(__wrap_getenv, name, WAZUH_HOME_ENV);
    will_return(__wrap_getenv, "/home/wazuh");

    expect_string(__wrap_stat, __file, "/home/wazuh");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    val = w_homedir(argv0);
    assert_string_equal(val, "/home/wazuh");
    free(val);
}

void test_w_homedir_stat_fail(void **state)
{
    char *argv0 = "/fake/dir/bin";
    struct stat stat_buf = { .st_mode = 0040000 }; // S_IFDIR

    expect_string(__wrap_realpath, path, "/proc/self/exe");
    will_return(__wrap_realpath, argv0);

    expect_string(__wrap_stat, __file, "/fake/dir");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, -1);

    expect_string(__wrap__merror_exit, formatted_msg, "(1108): Unable to find Wazuh install directory. Export it to WAZUH_HOME environment variable.");

    expect_assert_failure(w_homedir(argv0));
}
#endif

void test_get_file_content(void **state)
{
    int max_size = 300;
    char * content;
    const char * expected = "test string";
    const char * file_name = "test_file.txt";

    expect_string(__wrap_fopen, path, file_name);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_ftell, 0);
    will_return(__wrap_fseek, 0);
    will_return(__wrap_ftell, 11); // Content size
    will_return(__wrap_fseek, 0);

    will_return(__wrap_fread, expected);
    will_return(__wrap_fread, strlen(expected));

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    content = w_get_file_content(file_name, max_size);

    assert_string_equal(content, expected);

    free(content);
}

void test_get_file_pointer_NULL(void **state)
{
    const char * path = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot open NULL path");

    FILE * fp = w_get_file_pointer(path);

    assert_int_equal(NULL, fp);
}

void test_get_file_pointer_invalid(void **state)
{
    const char * file_name = "test_file.txt";
    expect_string(__wrap_fopen, path, file_name);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "(1103): Could not open file 'test_file.txt' due to [(0)-(Success)].");

    FILE * fp = w_get_file_pointer(file_name);

    assert_int_equal(NULL, fp);
}

void test_get_file_pointer_success(void **state)
{
    const char * file_name = "test_file.txt";
    expect_string(__wrap_fopen, path, file_name);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    FILE * fp = w_get_file_pointer(file_name);

    assert_int_equal(fp, fp);
}

#ifdef TEST_WINAGENT
void test_get_UTC_modification_time_success(void **state) {
    HANDLE hdle = (HANDLE)1234;
    FILETIME modification_date;
    modification_date.dwLowDateTime = (DWORD)1234;
    modification_date.dwHighDateTime = (DWORD)4321;

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, hdle);

    expect_value(wrap_GetFileTime, hFile, hdle);
    will_return(wrap_GetFileTime, &modification_date);
    will_return(wrap_GetFileTime, 1);

    expect_value(wrap_CloseHandle, hObject, hdle);
    will_return(wrap_CloseHandle, 0);

    expect_value(__wrap_get_windows_file_time_epoch, ftime.dwLowDateTime, modification_date.dwLowDateTime);
    expect_value(__wrap_get_windows_file_time_epoch, ftime.dwHighDateTime, modification_date.dwHighDateTime);
    will_return(__wrap_get_windows_file_time_epoch, 123456);

    time_t ret = get_UTC_modification_time("C:\\a\\path");
    assert_int_equal(ret, 123456);
}

void test_get_UTC_modification_time_fail_get_handle(void **state) {
    char buffer[OS_SIZE_128];
    char *path = "C:\\a\\path";

    expect_string(wrap_CreateFile, lpFileName, path);
    will_return(wrap_CreateFile, INVALID_HANDLE_VALUE);

    snprintf(buffer, OS_SIZE_128, FIM_WARN_OPEN_HANDLE_FILE, path, 2);
    expect_string(__wrap__mferror, formatted_msg, buffer);

    time_t ret = get_UTC_modification_time(path);
    assert_int_equal(ret, 0);
}

void test_get_UTC_modification_time_fail_get_filetime(void **state) {
    char buffer[OS_SIZE_128];
    char *path = "C:\\a\\path";

    HANDLE hdle = (HANDLE)1234;
    FILETIME modification_date;
    modification_date.dwLowDateTime = (DWORD)1234;
    modification_date.dwHighDateTime = (DWORD)4321;

    expect_string(wrap_CreateFile, lpFileName, path);
    will_return(wrap_CreateFile, (HANDLE)1234);

    expect_value(wrap_GetFileTime, hFile, (HANDLE)1234);
    will_return(wrap_GetFileTime, &modification_date);
    will_return(wrap_GetFileTime, 0);

    snprintf(buffer, OS_SIZE_128, FIM_WARN_GET_FILETIME, path, 2);
    expect_string(__wrap__mferror, formatted_msg, buffer);

    expect_value(wrap_CloseHandle, hObject, (HANDLE)1234);
    will_return(wrap_CloseHandle, 0);

    time_t ret = get_UTC_modification_time(path);
    assert_int_equal(ret, 0);
}

void test_expand_win32_wildcards_no_wildcards(void **state) {
    char *path = "C:\\path\\without\\wildcards";
    char **result;

    result = expand_win32_wildcards(path);

    *state = result;
    assert_string_equal(path, result[0]);
    assert_null(result[1]);
}

void test_expand_win32_wildcards_invalid_handle(void **state) {
    char *path = "C:\\wildcards*";
    char **result;
    expect_find_first_file(path, NULL, (DWORD) 0,  INVALID_HANDLE_VALUE);
    expect_any(__wrap__mdebug2, formatted_msg);
    result = expand_win32_wildcards(path);
    *state = result;

    assert_null(result[0]);
}

void test_expand_win32_wildcards_back_link(void **state) {
    char *path = "C:\\.*";
    char **result;

    expect_find_first_file(path, ".", (DWORD) 0, (HANDLE) 1);
    expect_find_next_file((HANDLE) 1, "..", (DWORD) 0, (BOOL) 1);
    expect_find_next_file((HANDLE) 1, NULL, (DWORD) 0, (BOOL) 0);

    result = expand_win32_wildcards(path);
    *state = result;

    assert_null(result[0]);
}

void test_expand_win32_wildcards_directories(void **state) {
    char *path = "C:\\test*";
    char **result;
    char vectors[N_PATHS][MAX_PATH] = { '\0' };
    char buffer[OS_SIZE_128] = {0};

    snprintf(vectors[0], OS_SIZE_128, "testdir_%d", 0);
    expect_find_first_file(path, vectors[0], FILE_ATTRIBUTE_DIRECTORY, (HANDLE) 1);

    for (int i = 1; i < N_PATHS; i++) {
        snprintf(vectors[i], OS_SIZE_128, "testdir_%d", i);
        expect_find_next_file((HANDLE) 1, vectors[i], FILE_ATTRIBUTE_DIRECTORY, (BOOL) 1);
    }

    expect_find_next_file((HANDLE) 1, NULL, (DWORD) 0, (BOOL) 0);

    result = expand_win32_wildcards(path);
    *state = result;
    int i;
    for (i = 0; result[i]; i++) {
        snprintf(buffer, OS_SIZE_128, "%s%s", "C:\\", vectors[i]);
        assert_string_equal(buffer, result[i]);
    }
    assert_int_equal(N_PATHS, i);
}

void test_expand_win32_wildcards_directories_reparse_point(void **state) {
    char *path = "C:\\reparse*";
    char **result;
    char vectors[N_PATHS][MAX_PATH] = { '\0' };

    snprintf(vectors[0], OS_SIZE_128, "reparse_%d", 0);
    expect_find_first_file(path, vectors[0], FILE_ATTRIBUTE_REPARSE_POINT, (HANDLE) 1);

    for (int i = 1; i < 5; i++) {
        snprintf(vectors[i], OS_SIZE_128, "reparse_%d", i);
        expect_find_next_file((HANDLE) 1, vectors[i], FILE_ATTRIBUTE_REPARSE_POINT, (BOOL) 1);
    }

    expect_find_next_file((HANDLE) 1, NULL, (DWORD) 0, (BOOL) 0);

    result = expand_win32_wildcards(path);
    *state = result;

    assert_null(result[0]);
}

void test_expand_win32_wildcards_file_with_next_glob(void **state) {
    char *path = "C:\\ignored_*\\test?";
    char **result;
    char vectors[N_PATHS][MAX_PATH] = { '\0' };
    char buffer[OS_SIZE_128] = {0};

    // Begining to expand the first wildcard
    // files that matches the first wildcard must be ignored
    expect_find_first_file("C:\\ignored_*", "ignored_file", FILE_ATTRIBUTE_NORMAL, (HANDLE) 1);

    expect_find_next_file((HANDLE) 1, "test_folder", FILE_ATTRIBUTE_DIRECTORY, (BOOL) 1);
    // Ending to expand the first wildcard
    expect_find_next_file((HANDLE) 1, NULL, 0, (BOOL) 0);

    // Beggining to expand the second wildcard
    snprintf(vectors[0], OS_SIZE_128, "test_%d", 0);
    expect_find_first_file("C:\\test_folder\\test?", vectors[0], FILE_ATTRIBUTE_NORMAL, (HANDLE) 1);

    for (int i = 1; i < N_PATHS; i++) {
        snprintf(vectors[i], OS_SIZE_128, "test_%d", i);
        expect_find_next_file((HANDLE) 1, vectors[i], FILE_ATTRIBUTE_DIRECTORY, (BOOL) 1);
    }
    // Ending to expand the second wildcard
    expect_find_next_file((HANDLE) 1, NULL, 0, (BOOL) 0);

    result = expand_win32_wildcards(path);
    *state = result;
    for (int i = 0; result[i]; i++) {
        snprintf(buffer, OS_SIZE_128, "C:\\test_folder\\%s", vectors[i]);
        assert_string_equal(buffer, result[i]);
    }
}

void test_is_network_path_null(void **state) {
    char *path = NULL;
    int ret = is_network_path(path);
    assert_int_equal(ret, 0);

    path = "";
    ret = is_network_path(path);
    assert_int_equal(ret, 0);
}

void test_is_network_path_unc(void **state) {
    char *path = "\\\\server\\share";
    int ret = is_network_path(path);
    assert_int_equal(ret, 1);
}

void test_is_network_path_network(void **state) {
    char *path = "Z:\\file.txt";
    int ret = is_network_path(path);
    assert_int_equal(ret, 1);
}

void test_is_network_path_local(void **state) {
    char *path = "C:\\file.txt";
    int ret = is_network_path(path);
    assert_int_equal(ret, 0);
}

void test_wfopen_local_path(void **state) {
    errno = 0;
    char *path = "C:\\file.txt";
    expect_CreateFile_call(path, INVALID_HANDLE_VALUE);
    SetLastError(0);
    FILE *fp = wfopen(path, "r");
    assert_int_equal(fp, NULL);
    assert_int_equal(errno, 0);
}

void test_wfopen_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    FILE *fp = wfopen(path, "r");
    assert_int_equal(fp, NULL);
    assert_int_equal(errno, EACCES);
}

void test_waccess_local_path(void **state) {
    errno = 0;
    char *path = "C:\\file.txt";

    expect_string(__wrap_access, __name, path);
    expect_value(__wrap_access, __type, "r");
    will_return(__wrap_access, 0);

    int ret = waccess(path, "r");
    assert_int_equal(ret, 0);
    assert_int_equal(errno, 0);
}

void test_waccess_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    int ret = waccess(path, "r");
    assert_int_equal(ret, -1);
    assert_int_equal(errno, EACCES);
}

void test_wCreateFile_local_path(void **state) {
    errno = 0;
    HANDLE hdle = (HANDLE)1234;
    char *path = "C:\\file.txt";

    expect_string(wrap_CreateFile, lpFileName, path);
    will_return(wrap_CreateFile, hdle);

    HANDLE ret = wCreateFile(path, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(ret, hdle);
    assert_int_equal(errno, 0);
}

void test_wCreateFile_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    HANDLE ret = wCreateFile(path, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(ret, INVALID_HANDLE_VALUE);
    assert_int_equal(errno, EACCES);
}

void test_wCreateProcessW_local_path(void **state) {
    errno = 0;
    char *path = "C:\\file.txt";

    expect_string(wrap_CreateProcessW, lpCommandLine, path);
    will_return(wrap_CreateProcessW, TRUE);

    bool ret = wCreateProcessW(NULL, path, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_true(ret);
    assert_int_equal(errno, 0);
}

void test_wCreateProcessW_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    bool ret = wCreateProcessW(NULL, path, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_false(ret);
    assert_int_equal(errno, EACCES);
}

void test_wopendir_local_path(void **state) {
    errno = 0;
    char *path = "C:\\file.txt";
    DIR *dir = (DIR *)1;

    will_return(__wrap_opendir, dir);

    DIR *ret = wopendir(path);
    assert_ptr_equal(ret, dir);
    assert_int_equal(errno, 0);
}

void test_wopendir_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    DIR *ret = wopendir(path);
    assert_ptr_equal(ret, NULL);
    assert_int_equal(errno, EACCES);
}

void test_w_stat_local_path(void **state) {
    errno = 0;
    char *path = "C:\\file.txt";

    expect_string(__wrap_stat, __file, path);
    will_return(__wrap_stat, NULL);
    will_return(__wrap_stat, 0);

    int ret = w_stat(path, NULL);
    assert_int_equal(ret, 0);
    assert_int_equal(errno, 0);
}

void test_w_stat_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    int ret = w_stat(path, NULL);
    assert_int_equal(ret, -1);
    assert_int_equal(errno, EACCES);
}

void test_w_stat64_local_path(void **state) {
    errno = 0;
    char *path = "C:\\file.txt";

    expect_string(wrap__stat64, __file, path);
    will_return(wrap__stat64, NULL);
    will_return(wrap__stat64, 0);

    int ret = w_stat64(path, NULL);
    assert_int_equal(ret, 0);
    assert_int_equal(errno, 0);
}

void test_w_stat64_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    int ret = w_stat64(path, NULL);
    assert_int_equal(ret, -1);
    assert_int_equal(errno, EACCES);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifndef TEST_WINAGENT
        cmocka_unit_test(test_CreatePID_success),
        cmocka_unit_test(test_CreatePID_failure_chmod),
        cmocka_unit_test(test_CreatePID_failure_fopen),
        cmocka_unit_test(test_DeletePID_success),
        cmocka_unit_test(test_DeletePID_failure),
        cmocka_unit_test(test_w_is_compressed_gz_file_uncompressed),
        cmocka_unit_test(test_w_is_compressed_bz2_file_compressed),
        cmocka_unit_test(test_w_is_compressed_bz2_file_uncompressed),
        cmocka_unit_test(test_is_program_available_success),
        cmocka_unit_test(test_is_program_available_failure),
        cmocka_unit_test(test_is_program_available_null),
        cmocka_unit_test(test_is_program_available_not_found),
#ifdef TEST_SERVER
        cmocka_unit_test(test_w_uncompress_bz2_gz_file_bz2),
        // MergeAppendFile
        cmocka_unit_test(test_MergeAppendFile_open_fail),
        cmocka_unit_test(test_MergeAppendFile_fseek_fail),
        cmocka_unit_test(test_MergeAppendFile_fseek2_fail),
        cmocka_unit_test(test_MergeAppendFile_diff_ftell),
        cmocka_unit_test(test_MergeAppendFile_success),
#endif
        // w_compress_gzfile
        cmocka_unit_test(test_w_compress_gzfile_wfopen_fail),
        cmocka_unit_test(test_w_compress_gzfile_gzopen_fail),
        cmocka_unit_test(test_w_compress_gzfile_write_error),
        cmocka_unit_test(test_w_compress_gzfile_success),
        // w_uncompress_gzfile
        cmocka_unit_test(test_w_uncompress_gzfile_lstat_fail),
        cmocka_unit_test(test_w_uncompress_gzfile_fopen_fail),
        cmocka_unit_test(test_w_uncompress_gzfile_gzopen_fail),
        cmocka_unit_test(test_w_uncompress_gzfile_first_read_fail),
        cmocka_unit_test(test_w_uncompress_gzfile_first_read_success),
        cmocka_unit_test(test_w_uncompress_gzfile_success),
        // w_homedir
        cmocka_unit_test(test_w_homedir_first_attempt),
        cmocka_unit_test(test_w_homedir_second_attempt),
        cmocka_unit_test(test_w_homedir_third_attempt),
        cmocka_unit_test(test_w_homedir_check_argv0),
        cmocka_unit_test(test_w_homedir_env_var),
        cmocka_unit_test(test_w_homedir_stat_fail),
        // w_get_file_pointer
        cmocka_unit_test(test_get_file_pointer_NULL),
        cmocka_unit_test(test_get_file_pointer_invalid),
        cmocka_unit_test(test_get_file_pointer_success),
#else
        cmocka_unit_test(test_get_UTC_modification_time_success),
        cmocka_unit_test(test_get_UTC_modification_time_fail_get_handle),
        cmocka_unit_test(test_get_UTC_modification_time_fail_get_filetime),
        cmocka_unit_test_teardown(test_expand_win32_wildcards_no_wildcards, teardown_win32_wildcards),
        cmocka_unit_test_teardown(test_expand_win32_wildcards_invalid_handle, teardown_win32_wildcards),
        cmocka_unit_test_teardown(test_expand_win32_wildcards_back_link, teardown_win32_wildcards),
        cmocka_unit_test_teardown(test_expand_win32_wildcards_directories, teardown_win32_wildcards),
        cmocka_unit_test_teardown(test_expand_win32_wildcards_directories_reparse_point, teardown_win32_wildcards),
        cmocka_unit_test_teardown(test_expand_win32_wildcards_file_with_next_glob, teardown_win32_wildcards),
        cmocka_unit_test(test_is_network_path_null),
        cmocka_unit_test(test_is_network_path_unc),
        cmocka_unit_test(test_is_network_path_network),
        cmocka_unit_test(test_is_network_path_local),
        cmocka_unit_test(test_wfopen_local_path),
        cmocka_unit_test(test_wfopen_network_path),
        cmocka_unit_test(test_waccess_local_path),
        cmocka_unit_test(test_waccess_network_path),
        cmocka_unit_test(test_wCreateFile_local_path),
        cmocka_unit_test(test_wCreateFile_network_path),
        cmocka_unit_test(test_wCreateProcessW_local_path),
        cmocka_unit_test(test_wCreateProcessW_network_path),
        cmocka_unit_test(test_wopendir_local_path),
        cmocka_unit_test(test_wopendir_network_path),
        cmocka_unit_test(test_w_stat_local_path),
        cmocka_unit_test(test_w_stat_network_path),
        cmocka_unit_test(test_w_stat64_local_path),
        cmocka_unit_test(test_w_stat64_network_path),

#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
