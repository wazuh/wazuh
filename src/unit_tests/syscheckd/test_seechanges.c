/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

#ifdef TEST_AGENT
char *_read_file(const char *high_name, const char *low_name, const char *defines_file) __attribute__((nonnull(3)));
#endif

/* redefinitons/wrapping */

#ifdef TEST_AGENT
int __wrap_getDefine_Int(const char *high_name, const char *low_name, int min, int max) {
    int ret;
    char *value;
    char *pt;

    /* Try to read from the local define file */
    value = _read_file(high_name, low_name, "./internal_options.conf");
    if (!value) {
        merror_exit(DEF_NOT_FOUND, high_name, low_name);
    }

    pt = value;
    while (*pt != '\0') {
        if (!isdigit((int)*pt)) {
            merror_exit(INV_DEF, high_name, low_name, value);
        }
        pt++;
    }

    ret = atoi(value);
    if ((ret < min) || (ret > max)) {
        merror_exit(INV_DEF, high_name, low_name, value);
    }

    /* Clear memory */
    free(value);

    return (ret);
}

int __wrap_isChroot() {
    return 1;
}
#endif
char* filter(const char *string);
int symlink_to_dir (const char *filename);
char *gen_diff_alert(const char *filename, time_t alert_diff_time);
int seechanges_dupfile(const char *old, const char *current);
int seechanges_createpath(const char *filename);

int test_mode = 0;

/* redefinitons/wrapping */

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_lstat(const char *filename, struct stat *buf) {
    check_expected(filename);
    buf->st_mode = mock();
    return mock();
}

int __real_stat(const char * __file, struct stat * __buf);
int __wrap_stat(const char * __file, struct stat * __buf) {
    if (test_mode) {
        check_expected(__file);
        __buf->st_mode = mock();
        return mock_type(int);
    }
    return __real_stat(__file, __buf);
}

int __wrap_abspath(const char *path, char *buffer, size_t size) {
    check_expected(path);

    strncpy(buffer, path, size);
    buffer[size - 1] = '\0';

    return mock();
}

FILE *__real_fopen(const char * __filename, const char * __modes);
FILE *__wrap_fopen(const char * __filename, const char * __modes) {
    if (test_mode) {
        check_expected(__filename);
        check_expected(__modes);
        return mock_type(FILE *);
    }
    return __real_fopen(__filename, __modes);
}

size_t __real_fread(void *ptr, size_t size, size_t n, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t n, FILE *stream) {
    if (test_mode) {
        strncpy((char *) ptr, mock_type(char *), n);
        return mock();
    }
    return __real_fread(ptr, size, n, stream);
}

int __real_fclose(FILE *fp);
int __wrap_fclose(FILE *fp) {
    if (test_mode) {
        return mock();
    }
    return __real_fclose(fp);
}

size_t __real_fwrite(const void * ptr, size_t size, size_t count, FILE * stream);
size_t __wrap_fwrite(const void * ptr, size_t size, size_t count, FILE * stream) {
    if (test_mode) {
        return mock();
    }
    return __real_fwrite(ptr, size, count, stream);
}

int __wrap_unlink() {
    return 1;
}

int __wrap_w_compress_gzfile(const char *filesrc, const char *filedst) {
    check_expected(filesrc);
    check_expected(filedst);
    return mock();
}

int __wrap_IsDir(const char *file) {
    check_expected(file);
    return mock();
}

int __wrap_mkdir(const char *__path, __mode_t __mode) {
    check_expected(__path);
    check_expected(__mode);
    return mock();
}

/* Setup/teardown */

static int setup_group(void **state) {
    (void) state;
    Read_Syscheck_Config("test_syscheck.conf");
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    Free_Syscheck(&syscheck);
    test_mode = 0;
    return 0;
}

static int teardown_free_string(void **state) {
    char * string = *state;
    free(string);
    return 0;
}

/* tests */
void test_filter(void **state) {
    (void) state;

    const char * file_name = "$file.test";

    char * out = filter(file_name);

    *state = out;

    assert_non_null(out);
    assert_string_equal(out, "\\$file.test");
}

void test_symlink_to_dir(void **state) {
    (void) state;
    int ret;

    const char * file_name = "/folder";

    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0120000);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_stat, __file, file_name);
    will_return(__wrap_stat, 0040000);
    will_return(__wrap_stat, 0);

    ret = symlink_to_dir(file_name);

    assert_int_equal(ret, 1);
}

void test_symlink_to_dir_no_link(void **state) {
    (void) state;
    int ret;

    const char * file_name = "/folder";

    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, 0);

    ret = symlink_to_dir(file_name);

    assert_int_equal(ret, 0);
}

void test_symlink_to_dir_no_dir(void **state) {
    (void) state;
    int ret;

    const char * file_name = "/folder";

    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0120000);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_stat, __file, file_name);
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, 0);

    ret = symlink_to_dir(file_name);

    assert_int_equal(ret, 0);
}

void test_symlink_to_dir_lstat_error(void **state) {
    (void) state;
    int ret;

    const char * file_name = "/folder";

    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, -1);

    ret = symlink_to_dir(file_name);

    assert_int_equal(ret, 0);
}

void test_symlink_to_dir_stat_error(void **state) {
    (void) state;
    int ret;

    const char * file_name = "/folder";

    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0120000);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_stat, __file, file_name);
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    ret = symlink_to_dir(file_name);

    assert_int_equal(ret, 0);
}

void test_is_nodiff_true(void **state) {
    int ret;

    const char * file_name = "/etc/ssl/private.key";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 1);
}


void test_is_nodiff_false(void **state) {
    int ret;

    const char * file_name = "/dummy_file.key";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


void test_is_nodiff_regex_true(void **state) {
    int ret;

    const char * file_name = "file.test";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 1);
}


void test_is_nodiff_regex_false(void **state) {
    int ret;

    const char * file_name = "test.file";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


void test_is_nodiff_no_nodiff(void **state) {
    int ret;
    int i;

    if (syscheck.nodiff) {
        for (i=0; syscheck.nodiff[i] != NULL; i++) {
            free(syscheck.nodiff[i]);
        }
        free(syscheck.nodiff);
    }
    if (syscheck.nodiff_regex) {
        for (i=0; syscheck.nodiff_regex[i] != NULL; i++) {
            OSMatch_FreePattern(syscheck.nodiff_regex[i]);
            free(syscheck.nodiff_regex[i]);
        }
        free(syscheck.nodiff_regex);
    }
    syscheck.nodiff = NULL;
    syscheck.nodiff_regex = NULL;

    const char * file_name = "test.file";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}

void test_gen_diff_alert(void **state) {
    const char * file_name = "/folder/test.file";
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);

    will_return(__wrap_fclose, 1);

    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, 0);

    char *diff = gen_diff_alert(file_name, time);

    *state = diff;

    assert_string_equal(diff, "test diff");
}

void test_gen_diff_alert_big_size(void **state) {
    const char * file_name = "/folder/test.file";
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "this is a really big diff\n");
    will_return(__wrap_fread, OS_MAXSTR - OS_SK_HEADER - 1);

    will_return(__wrap_fclose, 1);

    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, 0);

    char *diff = gen_diff_alert(file_name, time);

    *state = diff;

    assert_string_equal(diff, "this is a really big diff\nMore changes...");
}

void test_gen_diff_alert_abspath_error(void **state) {
    const char * file_name = "/folder/test.file";
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 0);

    expect_string(__wrap__merror, formatted_msg, "Cannot get absolute path of '/folder/test.file': Success (0)");

    char *diff = gen_diff_alert(file_name, time);

    assert_null(diff);
}

void test_gen_diff_alert_fopen_error(void **state) {
    const char * file_name = "/folder/test.file";
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 0);

    expect_string(__wrap__merror, formatted_msg, "(6665): Unable to generate diff alert (fopen)'/var/ossec/queue/diff/local/folder/test.file/diff.12345'.");

    char *diff = gen_diff_alert(file_name, time);

    assert_null(diff);
}

void test_gen_diff_alert_fread_error(void **state) {
    const char * file_name = "/folder/test.file";
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 0);

    will_return(__wrap_fclose, 1);

    expect_string(__wrap__merror, formatted_msg, "(6666): Unable to generate diff alert (fread).");

    char *diff = gen_diff_alert(file_name, time);

    assert_null(diff);
}

void test_gen_diff_alert_compress_error(void **state) {
    const char * file_name = "/folder/test.file";
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);

    will_return(__wrap_fclose, 1);

    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, -1);

    expect_string(__wrap__mwarn, formatted_msg, "(6914): Cannot create a snapshot of file '/folder/test.file'");

    char *diff = gen_diff_alert(file_name, time);

    *state = diff;

    assert_string_equal(diff, "test diff");
}

void test_seechanges_dupfile(void **state) {
    (void) state;

    const char * old_file = "/folder/test.old";
    const char * new_file = "/folder/test.new";

    expect_string(__wrap_fopen, __filename, old_file);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_fopen, __filename, new_file);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test dup file");
    will_return(__wrap_fread, 13);

    will_return(__wrap_fwrite, 13);

    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);

    will_return(__wrap_fclose, 1);
    will_return(__wrap_fclose, 1);

    int ret = seechanges_dupfile(old_file, new_file);

    assert_int_equal(ret, 1);
}

void test_seechanges_dupfile_fopen_error1(void **state) {
    (void) state;

    const char * old_file = "/folder/test.old";
    const char * new_file = "/folder/test.new";

    expect_string(__wrap_fopen, __filename, old_file);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 0);

    int ret = seechanges_dupfile(old_file, new_file);

    assert_int_equal(ret, 0);
}

void test_seechanges_dupfile_fopen_error2(void **state) {
    (void) state;

    const char * old_file = "/folder/test.old";
    const char * new_file = "/folder/test.new";

    expect_string(__wrap_fopen, __filename, old_file);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_fopen, __filename, new_file);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 0);

    will_return(__wrap_fclose, 1);

    int ret = seechanges_dupfile(old_file, new_file);

    assert_int_equal(ret, 0);
}

void test_seechanges_dupfile_fwrite_error(void **state) {
    (void) state;

    const char * old_file = "/folder/test.old";
    const char * new_file = "/folder/test.new";

    expect_string(__wrap_fopen, __filename, old_file);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_fopen, __filename, new_file);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test dup file");
    will_return(__wrap_fread, 13);

    will_return(__wrap_fwrite, 0);

    expect_string(__wrap__merror, formatted_msg, "(6668): Unable to write data on file '/folder/test.new'");

    will_return(__wrap_fclose, 1);
    will_return(__wrap_fclose, 1);

    int ret = seechanges_dupfile(old_file, new_file);

    assert_int_equal(ret, 1);
}

void test_seechanges_createpath(void **state) {
    (void) state;

    const char * file_name = "/folder/test.file";

    expect_string(__wrap_IsDir, file, "/folder");
    will_return(__wrap_IsDir, 0);

    int ret = seechanges_createpath(file_name);

    assert_int_equal(ret, 1);
}

void test_seechanges_createpath_invalid_path(void **state) {
    (void) state;

    const char * file_name = "\\";

    expect_string(__wrap__merror, formatted_msg, "(6669): Invalid path name: '\\'");

    int ret = seechanges_createpath(file_name);

    assert_int_equal(ret, 0);
}

void test_seechanges_createpath_mkdir(void **state) {
    (void) state;

    const char * file_name = "/folder/test.file";

    expect_string(__wrap_IsDir, file, "/folder");
    will_return(__wrap_IsDir, -1);

    expect_string(__wrap_mkdir, __path, "/folder");
    expect_value(__wrap_mkdir, __mode, 0770);
    will_return(__wrap_mkdir, 0);

    int ret = seechanges_createpath(file_name);

    assert_int_equal(ret, 1);
}

void test_seechanges_createpath_mkdir_error(void **state) {
    (void) state;

    const char * file_name = "/folder/test.file";

    expect_string(__wrap_IsDir, file, "/folder");
    will_return(__wrap_IsDir, -1);

    expect_string(__wrap_mkdir, __path, "/folder");
    expect_value(__wrap_mkdir, __mode, 0770);
    will_return(__wrap_mkdir, -1);

    expect_string(__wrap__merror, formatted_msg, "(1107): Could not create directory '/folder' due to [(0)-(Success)].");

    int ret = seechanges_createpath(file_name);

    assert_int_equal(ret, 0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_filter, teardown_free_string),
        cmocka_unit_test(test_symlink_to_dir),
        cmocka_unit_test(test_symlink_to_dir_no_link),
        cmocka_unit_test(test_symlink_to_dir_no_dir),
        cmocka_unit_test(test_symlink_to_dir_lstat_error),
        cmocka_unit_test(test_symlink_to_dir_stat_error),
        cmocka_unit_test(test_is_nodiff_true),
        cmocka_unit_test(test_is_nodiff_false),
        cmocka_unit_test(test_is_nodiff_regex_true),
        cmocka_unit_test(test_is_nodiff_regex_false),
        cmocka_unit_test(test_is_nodiff_no_nodiff),
        cmocka_unit_test_teardown(test_gen_diff_alert, teardown_free_string),
        cmocka_unit_test_teardown(test_gen_diff_alert_big_size, teardown_free_string),
        cmocka_unit_test(test_gen_diff_alert_abspath_error),
        cmocka_unit_test(test_gen_diff_alert_fopen_error),
        cmocka_unit_test(test_gen_diff_alert_fread_error),
        cmocka_unit_test_teardown(test_gen_diff_alert_compress_error, teardown_free_string),
        cmocka_unit_test(test_seechanges_dupfile),
        cmocka_unit_test(test_seechanges_dupfile_fopen_error1),
        cmocka_unit_test(test_seechanges_dupfile_fopen_error2),
        cmocka_unit_test(test_seechanges_dupfile_fwrite_error),
        cmocka_unit_test(test_seechanges_createpath),
        cmocka_unit_test(test_seechanges_createpath_invalid_path),
        cmocka_unit_test(test_seechanges_createpath_mkdir),
        cmocka_unit_test(test_seechanges_createpath_mkdir_error),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
