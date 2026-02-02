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
#include <dirent.h>
#include <errno.h>
#include "../headers/defs.h"
#include "../headers/file_op.h"
#include "../error_messages/error_messages.h"
#include "../wrappers/common.h"
#include "../wrappers/libc/stdlib_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/string_op_wrappers.h"
#include "../wrappers/wazuh/shared/utf8_winapi_wrapper_wrappers.h"
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

static void expect_find_first_file(const wchar_t *file_path, const char *name, DWORD attrs, HANDLE handle) {
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

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, hdle);

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

    SetLastError(2);

    expect_string(__wrap_utf8_CreateFile, utf8_path, path);
    will_return(__wrap_utf8_CreateFile, INVALID_HANDLE_VALUE);

    snprintf(buffer, OS_SIZE_128, FIM_WARN_OPEN_HANDLE_FILE, path, 2);
    expect_string(__wrap__mdebug2, formatted_msg, buffer);

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

    expect_string(__wrap_utf8_CreateFile, utf8_path, path);
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    SetLastError(2);

    expect_value(wrap_GetFileTime, hFile, (HANDLE)1234);
    will_return(wrap_GetFileTime, &modification_date);
    will_return(wrap_GetFileTime, 0);

    snprintf(buffer, OS_SIZE_128, FIM_WARN_GET_FILETIME, path, 2);
    expect_string(__wrap__mdebug2, formatted_msg, buffer);

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
    wchar_t *path = L"C:\\wildcards*";
    char **result;
    expect_find_first_file(path, NULL, (DWORD) 0,  INVALID_HANDLE_VALUE);
    expect_any(__wrap__mdebug2, formatted_msg);
    result = expand_win32_wildcards("C:\\wildcards*");
    *state = result;

    assert_null(result[0]);
}

void test_expand_win32_wildcards_back_link(void **state) {
    wchar_t *path = L"C:\\.*";
    char **result;

    expect_find_first_file(path, ".", (DWORD) 0, (HANDLE) 1);
    expect_find_next_file((HANDLE) 1, "..", (DWORD) 0, (BOOL) 1);
    expect_find_next_file((HANDLE) 1, NULL, (DWORD) 0, (BOOL) 0);

    result = expand_win32_wildcards("C:\\.*");
    *state = result;

    assert_null(result[0]);
}

void test_expand_win32_wildcards_directories(void **state) {
    wchar_t *path = L"C:\\test*";
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

    result = expand_win32_wildcards("C:\\test*");
    *state = result;
    int i;
    for (i = 0; result[i]; i++) {
        snprintf(buffer, OS_SIZE_128, "%s%s", "C:\\", vectors[i]);
        assert_string_equal(buffer, result[i]);
    }
    assert_int_equal(N_PATHS, i);
}

void test_expand_win32_wildcards_directories_reparse_point(void **state) {
    wchar_t *path = L"C:\\reparse*";
    char **result;
    char vectors[N_PATHS][MAX_PATH] = { '\0' };

    snprintf(vectors[0], OS_SIZE_128, "reparse_%d", 0);
    expect_find_first_file(path, vectors[0], FILE_ATTRIBUTE_REPARSE_POINT, (HANDLE) 1);

    for (int i = 1; i < 5; i++) {
        snprintf(vectors[i], OS_SIZE_128, "reparse_%d", i);
        expect_find_next_file((HANDLE) 1, vectors[i], FILE_ATTRIBUTE_REPARSE_POINT, (BOOL) 1);
    }

    expect_find_next_file((HANDLE) 1, NULL, (DWORD) 0, (BOOL) 0);

    result = expand_win32_wildcards("C:\\reparse*");
    *state = result;

    assert_null(result[0]);
}

void test_expand_win32_wildcards_file_with_next_glob(void **state) {
    wchar_t *path = L"C:\\ignored_*\\test?";
    char **result;
    char vectors[N_PATHS][MAX_PATH] = { '\0' };
    char buffer[OS_SIZE_128] = {0};

    // Begining to expand the first wildcard
    // files that matches the first wildcard must be ignored
    expect_find_first_file(L"C:\\ignored_*", "ignored_file", FILE_ATTRIBUTE_NORMAL, (HANDLE) 1);

    expect_find_next_file((HANDLE) 1, "test_folder", FILE_ATTRIBUTE_DIRECTORY, (BOOL) 1);
    // Ending to expand the first wildcard
    expect_find_next_file((HANDLE) 1, NULL, 0, (BOOL) 0);

    // Beggining to expand the second wildcard
    snprintf(vectors[0], OS_SIZE_128, "test_%d", 0);
    expect_find_first_file(L"C:\\test_folder\\test?", vectors[0], FILE_ATTRIBUTE_NORMAL, (HANDLE) 1);

    for (int i = 1; i < N_PATHS; i++) {
        snprintf(vectors[i], OS_SIZE_128, "test_%d", i);
        expect_find_next_file((HANDLE) 1, vectors[i], FILE_ATTRIBUTE_DIRECTORY, (BOOL) 1);
    }
    // Ending to expand the second wildcard
    expect_find_next_file((HANDLE) 1, NULL, 0, (BOOL) 0);

    result = expand_win32_wildcards("C:\\ignored_*\\test?");
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

void test_is_network_path_extended_length_unc(void **state) {
    char *path = "\\\\?\\UNC\\server\\share";
    int ret = is_network_path(path);
    assert_int_equal(ret, 1);
}

void test_is_network_path_device(void **state) {
    char *path = "\\\\.\\device";
    int ret = is_network_path(path);
    assert_int_equal(ret, 1);
}

void test_is_network_path_extended_length_local(void **state) {
    char *path = "\\\\?\\C:\\file.txt";
    int ret = is_network_path(path);
    assert_int_equal(ret, 1);
}

void test_wfopen_local_path(void **state) {
    errno = 0;
    char *path = "C:\\file.txt";
    expect_string(__wrap_utf8_CreateFile, utf8_path, path);
    will_return(__wrap_utf8_CreateFile, INVALID_HANDLE_VALUE);
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

    int ret = waccess(path, (int)"r");
    assert_int_equal(ret, 0);
    assert_int_equal(errno, 0);
}

void test_waccess_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    int ret = waccess(path, (int)"r");
    assert_int_equal(ret, -1);
    assert_int_equal(errno, EACCES);
}

void test_wCreateFile_local_path(void **state) {
    errno = 0;
    HANDLE hdle = (HANDLE)1234;
    char *path = "C:\\file.txt";

    expect_string(__wrap_utf8_CreateFile, utf8_path, path);
    will_return(__wrap_utf8_CreateFile, hdle);

    HANDLE ret = wCreateFile(path, (DWORD)NULL, (DWORD)NULL, (LPSECURITY_ATTRIBUTES)NULL, (DWORD)NULL, (DWORD)NULL, (HANDLE)NULL);
    assert_int_equal(ret, hdle);
    assert_int_equal(errno, 0);
}

void test_wCreateFile_network_path(void **state) {
    errno = 0;
    char *path = "Z:\\file.txt";

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    HANDLE ret = wCreateFile(path, (DWORD)NULL, (DWORD)NULL, (LPSECURITY_ATTRIBUTES)NULL, (DWORD)NULL, (DWORD)NULL, (HANDLE)NULL);
    assert_int_equal(ret, INVALID_HANDLE_VALUE);
    assert_int_equal(errno, EACCES);
}

void test_wCreateProcessW_local_path(void **state) {
    errno = 0;
    wchar_t path[] = L"C:\\file.txt";

    expect_value(__wrap_convert_windows_string, string, path);
    will_return(__wrap_convert_windows_string, strdup("C:\\file.txt"));

    expect_value(wrap_CreateProcessW, lpCommandLine, path);
    will_return(wrap_CreateProcessW, TRUE);

    bool ret = wCreateProcessW(NULL, path, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_true(ret);
    assert_int_equal(errno, 0);
}

void test_wCreateProcessW_network_path(void **state) {
    errno = 0;
    wchar_t path[] = L"Z:\\file.txt";

    expect_value(__wrap_convert_windows_string, string, path);
    will_return(__wrap_convert_windows_string, strdup("Z:\\file.txt"));

    expect_string(__wrap__mwarn, formatted_msg, "(9800): File access denied. Network path usage is not allowed: 'Z:\\file.txt'.");

    bool ret = wCreateProcessW(NULL, path, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_false(ret);
    assert_int_equal(errno, EACCES);
}

void test_wCreateProcessW_conversion_failure(void **state) {
    errno = 0;
    wchar_t path[] = L"C:\\file.txt";

    expect_value(__wrap_convert_windows_string, string, path);
    will_return(__wrap_convert_windows_string, NULL);

    bool ret = wCreateProcessW(NULL, path, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_false(ret);
    assert_int_equal(errno, EINVAL);
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

    expect_string(__wrap_utf8_stat64, pathname, path);
    will_return(__wrap_utf8_stat64, NULL);
    will_return(__wrap_utf8_stat64, 0);

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

/* ===================== Tests for cldir_ex and cldir_ex_ignore ===================== */

#ifndef TEST_WINAGENT

/* Macro to create mock dirent entries on the stack */
#define CREATE_MOCK_DIRENT(var_name, name_str) \
    struct dirent var_name; \
    memset(&var_name, 0, sizeof(var_name)); \
    strncpy(var_name.d_name, name_str, sizeof(var_name.d_name) - 1)

/* Test cldir_ex with NULL ignore list (should delete everything) */
void test_cldir_ex_empty_directory(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Return NULL to indicate end of directory
    will_return(__wrap_readdir, NULL);

    // closedir returns 0 on success
    will_return(__wrap_closedir, 0);

    int ret = cldir_ex("/test/dir");
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore with NULL ignore list */
void test_cldir_ex_ignore_null_ignore(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    int ret = cldir_ex_ignore("/test/dir", NULL);
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore with single file to delete */
void test_cldir_ex_ignore_delete_single_file(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Mock readdir to return one file
    CREATE_MOCK_DIRENT(entry_1, "file_to_delete.txt");
    will_return(__wrap_readdir, &entry_1);

    expect_string(__wrap_rmdir, path, "/test/dir/file_to_delete.txt");
    will_return(__wrap_rmdir, 0);

    // End of directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    const char *ignore[] = { NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore preserves file in ignore list */
void test_cldir_ex_ignore_preserve_file_in_ignore(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Mock readdir to return two files
    CREATE_MOCK_DIRENT(entry_2, "keep_me.txt");
    will_return(__wrap_readdir, &entry_2);

    // lstat for keep_me.txt
    expect_string(__wrap_stat, __file, "/test/dir/keep_me.txt");
    struct stat mock_stat = { .st_mode = S_IFREG };
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    // keep_me.txt should NOT call rmdir_ex (it's in ignore list)

    CREATE_MOCK_DIRENT(entry_3, "delete_me.txt");
    will_return(__wrap_readdir, &entry_3);

    // delete_me.txt should be deleted
    expect_string(__wrap_rmdir, path, "/test/dir/delete_me.txt");
    will_return(__wrap_rmdir, 0);

    // End of directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    const char *ignore[] = { "keep_me.txt", NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore with subdirectory path in ignore list */
void test_cldir_ex_ignore_preserve_subdirectory_file(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Mock readdir to return "subfolder"
    CREATE_MOCK_DIRENT(entry_4, "subfolder");
    will_return(__wrap_readdir, &entry_4);

    // lstat for subfolder - it's a directory
    expect_string(__wrap_stat, __file, "/test/dir/subfolder");
    struct stat mock_stat_dir = { .st_mode = S_IFDIR };
    will_return(__wrap_stat, &mock_stat_dir);
    will_return(__wrap_stat, 0);

    // Because "subfolder/file1.txt" is in ignore, should_preserve_path returns 1
    // This means we recurse into subfolder

    // Recursive call: opendir("/test/dir/subfolder")
    will_return(__wrap_opendir, (DIR *)2);

    // Inside subfolder: return "file1.txt"
    CREATE_MOCK_DIRENT(entry_5, "file1.txt");
    will_return(__wrap_readdir, &entry_5);

    // lstat for file1.txt
    expect_string(__wrap_stat, __file, "/test/dir/subfolder/file1.txt");
    struct stat mock_stat_file = { .st_mode = S_IFREG };
    will_return(__wrap_stat, &mock_stat_file);
    will_return(__wrap_stat, 0);

    // file1.txt is in ignore list (subfolder/file1.txt), so should NOT be deleted

    // Return "file2.txt"
    CREATE_MOCK_DIRENT(entry_6, "file2.txt");
    will_return(__wrap_readdir, &entry_6);

    // file2.txt NOT in ignore, should be deleted
    expect_string(__wrap_rmdir, path, "/test/dir/subfolder/file2.txt");
    will_return(__wrap_rmdir, 0);

    // End of subfolder directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    // Try to rmdir the subfolder (will fail because file1.txt is still there)
    expect_string(__wrap_rmdir, path, "/test/dir/subfolder");
    will_return(__wrap_rmdir, -1);
    errno = ENOTEMPTY;

    // End of main directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    const char *ignore[] = { "subfolder/file1.txt", NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore removes empty subdirectory */
void test_cldir_ex_ignore_remove_empty_subdirectory(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Mock readdir to return "empty_folder"
    CREATE_MOCK_DIRENT(entry_7, "empty_folder");
    will_return(__wrap_readdir, &entry_7);

    // empty_folder NOT in ignore, so call rmdir_ex
    expect_string(__wrap_rmdir, path, "/test/dir/empty_folder");
    will_return(__wrap_rmdir, 0);

    // End of directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    const char *ignore[] = { NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore with nested subdirectory paths */
void test_cldir_ex_ignore_nested_subdirectory_paths(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Mock readdir to return "subfolder"
    CREATE_MOCK_DIRENT(entry_8, "subfolder");
    will_return(__wrap_readdir, &entry_8);

    // lstat for subfolder - it's a directory
    expect_string(__wrap_stat, __file, "/test/dir/subfolder");
    struct stat mock_stat_dir = { .st_mode = S_IFDIR };
    will_return(__wrap_stat, &mock_stat_dir);
    will_return(__wrap_stat, 0);

    // Recurse into subfolder
    will_return(__wrap_opendir, (DIR *)2);

    // Inside subfolder: return "nested"
    CREATE_MOCK_DIRENT(entry_9, "nested");
    will_return(__wrap_readdir, &entry_9);

    // lstat for nested - it's a directory
    expect_string(__wrap_stat, __file, "/test/dir/subfolder/nested");
    will_return(__wrap_stat, &mock_stat_dir);
    will_return(__wrap_stat, 0);

    // Recurse into nested
    will_return(__wrap_opendir, (DIR *)3);

    // Inside nested: return "file.txt"
    CREATE_MOCK_DIRENT(entry_10, "file.txt");
    will_return(__wrap_readdir, &entry_10);

    // lstat for file.txt
    expect_string(__wrap_stat, __file, "/test/dir/subfolder/nested/file.txt");
    struct stat mock_stat_file = { .st_mode = S_IFREG };
    will_return(__wrap_stat, &mock_stat_file);
    will_return(__wrap_stat, 0);

    // file.txt is in ignore list, should NOT be deleted

    // End of nested directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    // Try to rmdir nested (will fail because file.txt is still there)
    expect_string(__wrap_rmdir, path, "/test/dir/subfolder/nested");
    will_return(__wrap_rmdir, -1);
    errno = ENOTEMPTY;

    // End of subfolder directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    // Try to rmdir subfolder (will fail because nested is still there)
    expect_string(__wrap_rmdir, path, "/test/dir/subfolder");
    will_return(__wrap_rmdir, -1);
    errno = ENOTEMPTY;

    // End of main directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    const char *ignore[] = { "subfolder/nested/file.txt", NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore skips . and .. entries */
void test_cldir_ex_ignore_skip_dot_entries(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Mock readdir to return ".", "..", and a normal file
    CREATE_MOCK_DIRENT(entry_11, ".");
    will_return(__wrap_readdir, &entry_11);
    CREATE_MOCK_DIRENT(entry_12, "..");
    will_return(__wrap_readdir, &entry_12);
    CREATE_MOCK_DIRENT(entry_13, "file.txt");
    will_return(__wrap_readdir, &entry_13);

    // file.txt should be deleted
    expect_string(__wrap_rmdir, path, "/test/dir/file.txt");
    will_return(__wrap_rmdir, 0);

    // End of directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    const char *ignore[] = { NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore with opendir failure */
void test_cldir_ex_ignore_opendir_failure(void **state) {
    (void) state;

    will_return(__wrap_opendir, NULL);

    int ret = cldir_ex_ignore("/test/dir", NULL);
    assert_int_equal(ret, -1);
}

/* Test cldir_ex_ignore with rmdir_ex failure */
void test_cldir_ex_ignore_rmdir_ex_failure(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Mock readdir to return a file
    CREATE_MOCK_DIRENT(entry_15, "file.txt");
    will_return(__wrap_readdir, &entry_15);

    // rmdir_ex fails
    expect_string(__wrap_rmdir, path, "/test/dir/file.txt");
    will_return(__wrap_rmdir, -1);

    will_return(__wrap_closedir, 0);

    errno = 0;

    const char *ignore[] = { NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, -1);
}

/* Test cldir_ex_ignore with multiple files in ignore list */
void test_cldir_ex_ignore_multiple_files_in_ignore(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Return three files
    CREATE_MOCK_DIRENT(entry_16, "keep1.txt");
    will_return(__wrap_readdir, &entry_16);
    expect_string(__wrap_stat, __file, "/test/dir/keep1.txt");
    struct stat mock_stat = { .st_mode = S_IFREG };
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    CREATE_MOCK_DIRENT(entry_17, "delete.txt");
    will_return(__wrap_readdir, &entry_17);
    expect_string(__wrap_rmdir, path, "/test/dir/delete.txt");
    will_return(__wrap_rmdir, 0);

    CREATE_MOCK_DIRENT(entry_18, "keep2.txt");
    will_return(__wrap_readdir, &entry_18);
    expect_string(__wrap_stat, __file, "/test/dir/keep2.txt");
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    // End of directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    const char *ignore[] = { "keep1.txt", "keep2.txt", NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, 0);
}

/* Test cldir_ex_ignore preserves directory with partial ignore match */
void test_cldir_ex_ignore_partial_path_match(void **state) {
    (void) state;

    will_return(__wrap_opendir, (DIR *)1);

    // Return "sub" directory
    CREATE_MOCK_DIRENT(entry_19, "sub");
    will_return(__wrap_readdir, &entry_19);

    // "subfolder/file.txt" is in ignore, but "sub" should NOT match
    // So "sub" should be deleted
    expect_string(__wrap_rmdir, path, "/test/dir/sub");
    will_return(__wrap_rmdir, 0);

    // End of directory
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_closedir, 0);

    const char *ignore[] = { "subfolder/file.txt", NULL };
    int ret = cldir_ex_ignore("/test/dir", ignore);
    assert_int_equal(ret, 0);
}

#endif /* TEST_WINAGENT */

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
        // cldir_ex and cldir_ex_ignore
        cmocka_unit_test(test_cldir_ex_empty_directory),
        cmocka_unit_test(test_cldir_ex_ignore_null_ignore),
        cmocka_unit_test(test_cldir_ex_ignore_delete_single_file),
        cmocka_unit_test(test_cldir_ex_ignore_preserve_file_in_ignore),
        cmocka_unit_test(test_cldir_ex_ignore_preserve_subdirectory_file),
        cmocka_unit_test(test_cldir_ex_ignore_remove_empty_subdirectory),
        cmocka_unit_test(test_cldir_ex_ignore_nested_subdirectory_paths),
        cmocka_unit_test(test_cldir_ex_ignore_skip_dot_entries),
        cmocka_unit_test(test_cldir_ex_ignore_opendir_failure),
        cmocka_unit_test(test_cldir_ex_ignore_rmdir_ex_failure),
        cmocka_unit_test(test_cldir_ex_ignore_multiple_files_in_ignore),
        cmocka_unit_test(test_cldir_ex_ignore_partial_path_match),
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
        cmocka_unit_test(test_is_network_path_extended_length_unc),
        cmocka_unit_test(test_is_network_path_device),
        cmocka_unit_test(test_is_network_path_extended_length_local),
        cmocka_unit_test(test_wfopen_local_path),
        cmocka_unit_test(test_wfopen_network_path),
        cmocka_unit_test(test_waccess_local_path),
        cmocka_unit_test(test_waccess_network_path),
        cmocka_unit_test(test_wCreateFile_local_path),
        cmocka_unit_test(test_wCreateFile_network_path),
        cmocka_unit_test(test_wCreateProcessW_local_path),
        cmocka_unit_test(test_wCreateProcessW_network_path),
        cmocka_unit_test(test_wCreateProcessW_conversion_failure),
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
