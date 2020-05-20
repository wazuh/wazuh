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
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

#ifndef TEST_WINAGENT
#define PATH_OFFSET 1
#else
#define PATH_OFFSET 0
#endif

#ifdef TEST_AGENT
char *_read_file(const char *high_name, const char *low_name, const char *defines_file) __attribute__((nonnull(3)));
#endif

#ifdef TEST_WINAGENT
#define __mode_t int

char *adapt_win_fc_output(char *command_output);
#endif

char* filter(const char *string);
int symlink_to_dir (const char *filename);
char *gen_diff_alert(const char *filename, time_t alert_diff_time, int status);
int seechanges_dupfile(const char *old, const char *current);
int seechanges_createpath(const char *filename);

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

#ifndef TEST_WINAGENT
int __wrap_unlink() {
    return 1;
}
#else
int __wrap__unlink() {
    return 1;
}
#endif

int __wrap_w_compress_gzfile(const char *filesrc, const char *filedst) {
    check_expected(filesrc);
    check_expected(filedst);
    return mock();
}

int __wrap_w_uncompress_gzfile(const char *gzfilesrc, const char *gzfiledst) {
    check_expected(gzfilesrc);
    check_expected(gzfiledst);
    return mock();
}

int __wrap_IsDir(const char *file) {
    check_expected(file);
    return mock();
}

#ifndef TEST_WINAGENT
int __wrap_mkdir(const char *__path, __mode_t __mode) {
    check_expected(__path);
    check_expected(__mode);
    return mock();
}
#else
int __wrap_mkdir(const char *__path) {
    check_expected(__path);
    return mock();
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}
#endif
int __wrap_OS_MD5_File(const char *fname, os_md5 output, int mode) {
    check_expected(fname);
    check_expected(mode);

    char *md5 = mock_type(char *);
    strncpy(output, md5, sizeof(os_md5));

    return mock();
}

int __wrap_File_DateofChange(const char *file) {
    return 1;
}

int __wrap_rename(const char *__old, const char *__new) {
    check_expected(__old);
    check_expected(__new);
    return mock();
}

int __wrap_system(const char *__command) {
    check_expected(__command);
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

#ifdef TEST_WINAGENT
static int teardown_string(void **state) {
    char *s = *state;
    free(s);
    return 0;
}

static int setup_adapt_win_fc_output(void **state) {
    char **strarray = calloc(2, sizeof(char*));

    if(strarray == NULL)
        return -1;

    *state = strarray;

    return 0;
}

static int teardown_adapt_win_fc_output(void **state) {
    char **strarray = *state;

    free(strarray[0]);
    free(strarray[1]);
    free(strarray);

    return 0;
}
#endif

/* tests */
#ifndef TEST_WINAGENT
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
#endif

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

#ifdef TEST_WINAGENT
void test_filter_success(void **state) {
    char *input = "a/unix/style/path/";
    char *output;

    output = filter(input);

    *state = output;

    assert_string_equal(output, "a\\unix\\style\\path\\");
}

void test_filter_unchanged_string(void **state) {
    char *input = "This string wont change";
    char *output;

    output = filter(input);

    *state = output;

    assert_string_equal(output, input);
}

void test_filter_percentage_char(void **state) {
    char *input = "This % is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_adapt_win_fc_output_success(void **state) {
    char **strarray = *state;
    char *output;
    char *input = strdup(
        "Comparing files start.txt and end.txt\r\n"
        "***** start.txt\r\n"
        "    1:  First line\r\n"
        "***** END.TXT\r\n"
        "    1:  First Line 123\r\n"
        "    2:  Last line\r\n"
        "*****\r\n\r\n\r\n");

    if(input == NULL) fail();

    strarray[0] = input;

    output = adapt_win_fc_output(input);

    assert_non_null(output);

    strarray[1] = output;

    assert_string_equal(output, "< First line\n---\n> First Line 123\n> Last line\n");
}

void test_adapt_win_fc_output_invalid_input(void **state) {
    char **strarray = *state;
    char *output;
    char *input = strdup("This is invalid");

    if(input == NULL) fail();

    strarray[0] = input;

    expect_string(__wrap__mdebug2, formatted_msg, "(6667): Unable to find second line of alert string.: This is invalid");

    output = adapt_win_fc_output(input);

    assert_non_null(output);

    strarray[1] = output;

    assert_string_equal(output, input);
}

void test_adapt_win_fc_output_no_differences(void **state) {
    char **strarray = *state;
    char *output;
    char *input = strdup(
        "Comparing files start.txt and end.txt\r\n"
        "FC: no differences encountered\r\n\r\n\r\n");

    if(input == NULL) fail();

    strarray[0] = input;

    output = adapt_win_fc_output(input);

    assert_non_null(output);

    strarray[1] = output;

    assert_string_equal(output, "");
}

#endif
void test_gen_diff_alert(void **state) {
    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test.file";
    #else
    const char * file_name = "c:\\folder\\test.file";
    #endif
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    #else
    expect_string(__wrap_fopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
    #endif
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    #ifndef TEST_WINAGENT
    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);
    #else
    will_return(__wrap_fread, "Comparing files start.txt and end.txt\r\n"
                              "***** start.txt\r\n"
                              "    1:  First line\r\n"
                              "***** END.TXT\r\n"
                              "    1:  First Line 123\r\n"
                              "    2:  Last line\r\n"
                              "*****\r\n\r\n\r\n");
    will_return(__wrap_fread, 146);
    #endif

    will_return(__wrap_fclose, 1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    #else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    #endif
    will_return(__wrap_w_compress_gzfile, 0);

    char *diff = gen_diff_alert(file_name, time, 1);

    *state = diff;

    #ifndef TEST_WINAGENT
    assert_string_equal(diff, "test diff");
    #else
    assert_string_equal(diff, "< First line\n---\n> First Line 123\n> Last line\n");
    #endif
}

void test_gen_diff_alert_big_size(void **state) {
    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test.file";
    #else
    const char * file_name = "c:\\folder\\test.file";
    #endif
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    #else
    expect_string(__wrap_fopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
    #endif
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    #ifndef TEST_WINAGENT
    will_return(__wrap_fread, "this is a really big diff\n");
    will_return(__wrap_fread, OS_MAXSTR - OS_SK_HEADER - 1);
    #else
    will_return(__wrap_fread, "Comparing files start.txt and end.txt\r\n"
                              "Resync failed. Files are too different.\r\n"
                              "***** start.txt\r\n"
                              "    1:  First line\r\n"
                              "***** END.TXT\r\n"
                              "    1:  First Line 123\r\n"
                              "    2:  Last line\r\n"
                              "*****\r\n");
    will_return(__wrap_fread, OS_MAXSTR - OS_SK_HEADER - 1);
    #endif

    will_return(__wrap_fclose, 1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    #else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    #endif
    will_return(__wrap_w_compress_gzfile, 0);

    char *diff = gen_diff_alert(file_name, time, 1);

    *state = diff;

    #ifndef TEST_WINAGENT
    assert_string_equal(diff, "this is a really big diff\nMore changes...");
    #else
    assert_string_equal(diff, "< First line\n---\n> First Line 123\n> Last line\nMore changes...");
    #endif
}

void test_gen_diff_alert_abspath_error(void **state) {
    const char * file_name = "/folder/test.file";
    time_t time = 12345;

    errno = 0;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 0);

    expect_string(__wrap__merror, formatted_msg, "Cannot get absolute path of '/folder/test.file': Success (0)");

    char *diff = gen_diff_alert(file_name, time, 1);

    assert_null(diff);
}

void test_gen_diff_alert_fopen_error(void **state) {
    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test.file";
    #else
    const char * file_name = "c:\\folder\\test.file";
    #endif
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    #else
    expect_string(__wrap_fopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
    #endif
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 0);

    #ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "(6665): Unable to generate diff alert (fopen)'/var/ossec/queue/diff/local/folder/test.file/diff.12345'.");
    #else
    expect_string(__wrap__merror, formatted_msg, "(6665): Unable to generate diff alert (fopen)'queue/diff/local/c\\folder\\test.file/diff.12345'.");
    #endif

    char *diff = gen_diff_alert(file_name, time, 1);

    assert_null(diff);
}

void test_gen_diff_alert_fread_error(void **state) {
    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test.file";
    #else
    const char * file_name = "c:\\folder\\test.file";
    #endif
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    #else
    expect_string(__wrap_fopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
    #endif
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 0);

    will_return(__wrap_fclose, 1);

    expect_string(__wrap__merror, formatted_msg, "(6666): Unable to generate diff alert (fread).");

    char *diff = gen_diff_alert(file_name, time, 1);

    assert_null(diff);
}

void test_gen_diff_alert_compress_error(void **state) {
    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test.file";
    #else
    const char * file_name = "c:\\folder\\test.file";
    #endif
    time_t time = 12345;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap_fopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    #else
    expect_string(__wrap_fopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
    #endif
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);

    #ifndef TEST_WINAGENT
    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);
    #else
    will_return(__wrap_fread, "Comparing files start.txt and end.txt\r\n"
                              "***** start.txt\r\n"
                              "    1:  First line\r\n"
                              "***** END.TXT\r\n"
                              "    1:  First Line 123\r\n"
                              "    2:  Last line\r\n"
                              "*****\r\n\r\n\r\n");
    will_return(__wrap_fread, 146);
    #endif

    will_return(__wrap_fclose, 1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    #else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    #endif
    will_return(__wrap_w_compress_gzfile, -1);

    #ifndef TEST_WINAGENT
    expect_string(__wrap__mwarn, formatted_msg, "(6914): Cannot create a snapshot of file '/folder/test.file'");
    #else
    expect_string(__wrap__mwarn, formatted_msg, "(6914): Cannot create a snapshot of file 'c:\\folder\\test.file'");
    #endif

    char *diff = gen_diff_alert(file_name, time, 1);

    *state = diff;

    #ifndef TEST_WINAGENT
    assert_string_equal(diff, "test diff");
    #else
    assert_string_equal(diff, "< First line\n---\n> First Line 123\n> Last line\n");
    #endif
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
    #ifndef TEST_WINAGENT
    expect_value(__wrap_mkdir, __mode, 0770);
    #endif
    will_return(__wrap_mkdir, 0);

    int ret = seechanges_createpath(file_name);

    assert_int_equal(ret, 1);
}

void test_seechanges_createpath_mkdir_error(void **state) {
    (void) state;

    const char * file_name = "/folder/test.file";

    errno = 0;

    expect_string(__wrap_IsDir, file, "/folder");
    will_return(__wrap_IsDir, -1);

    expect_string(__wrap_mkdir, __path, "/folder");
    #ifndef TEST_WINAGENT
    expect_value(__wrap_mkdir, __mode, 0770);
    #endif
    will_return(__wrap_mkdir, -1);

    expect_string(__wrap__merror, formatted_msg, "(1107): Could not create directory '/folder' due to [(0)-(Success)].");

    int ret = seechanges_createpath(file_name);

    assert_int_equal(ret, 0);
}

void test_seechanges_addfile(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test_";
    const char * file_name_abs = "C\\folder\\test_";
    const char * default_path = "";
    const char * diff_string = "Comparing files start.txt and end.txt\r\n"
                               "***** start.txt\r\n"
                               "    1:  First line\r\n"
                               "***** END.TXT\r\n"
                               "    1:  First Line 123\r\n"
                               "    2:  Last line\r\n"
                               "*****\r\n\r\n\r\n";
    const char * diff_adapted_string = "< First line\n"
                                       "---\n"
                                       "> First Line 123\n"
                                       "> Last line\n";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    // seechanges_dupfile()
    expect_string(__wrap_fopen, __filename, file_name);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);
    expect_string(__wrap_fopen, __filename, last_entry);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    will_return(__wrap_fclose, 1);
    will_return(__wrap_fclose, 1);

    #ifndef TEST_WINAGENT
    // symlink_to_dir()
    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0120000);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_stat, __file, file_name);
    will_return(__wrap_stat, 0040000);
    will_return(__wrap_stat, 0);
    #endif

    expect_string(__wrap_fopen, __filename, diff_file);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fwrite, 1);

    will_return(__wrap_fclose, 1);

    // gen_diff_alert()
    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);
    expect_string(__wrap_fopen, __filename, diff_file);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);
    #ifndef TEST_WINAGENT
    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);
    #else
    will_return(__wrap_fread, diff_string);
    will_return(__wrap_fread, strlen(diff_string));
    #endif
    will_return(__wrap_fclose, 1);
    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz);
    will_return(__wrap_w_compress_gzfile, 0);

    char * diff = seechanges_addfile(file_name);

    *state = diff;

    #ifndef TEST_WINAGENT
    assert_string_equal(diff, "test diff");
    #else
    assert_string_equal(diff, diff_adapted_string);
    #endif
}

void test_seechanges_addfile_run_diff(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";
    const char * diff_string = "Comparing files start.txt and end.txt\r\n"
                               "***** start.txt\r\n"
                               "    1:  First line\r\n"
                               "***** END.TXT\r\n"
                               "    1:  First Line 123\r\n"
                               "    2:  Last line\r\n"
                               "*****\r\n\r\n\r\n";
    const char * diff_adapted_string = "< First line\n"
                                       "---\n"
                                       "> First Line 123\n"
                                       "> Last line\n";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    // seechanges_dupfile()
    expect_string(__wrap_fopen, __filename, file_name);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);
    expect_string(__wrap_fopen, __filename, last_entry);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    will_return(__wrap_fclose, 1);
    will_return(__wrap_fclose, 1);

    #ifndef TEST_WINAGENT
    // symlink_to_dir()
    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_system, __command, "diff \"/var/ossec/queue/diff/local/folder/test/state.1\" "
                                            "\"/var/ossec/queue/diff/local/folder/test/last-entry\" > "
                                            "\"/var/ossec/queue/diff/local/folder/test/diff.1\" 2> "
                                            "/dev/null");
    will_return(__wrap_system, 256);
    #else
    expect_string(__wrap_system, __command, "fc /n \"queue\\diff\\local\\C\\folder\\test\\state.1\" "
                                            "\"queue\\diff\\local\\C\\folder\\test\\last-entry\" > "
                                            "\"queue\\diff\\local\\C\\folder\\test\\diff.1\" 2> "
                                            "nul");
    will_return(__wrap_system, 0);
    #endif

    // gen_diff_alert()
    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);
    expect_string(__wrap_fopen, __filename, diff_file);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);
    #ifndef TEST_WINAGENT
    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);
    #else
    will_return(__wrap_fread, diff_string);
    will_return(__wrap_fread, strlen(diff_string));
    #endif
    will_return(__wrap_fclose, 1);
    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz);
    will_return(__wrap_w_compress_gzfile, 0);

    char * diff = seechanges_addfile(file_name);

    *state = diff;

    #ifndef TEST_WINAGENT
    assert_string_equal(diff, "test diff");
    #else
    assert_string_equal(diff, diff_adapted_string);
    #endif
}

void test_seechanges_addfile_create_gz_file(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    char *dirs[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/local",
        "/var/ossec/queue/diff/local/folder",
        "/var/ossec/queue/diff/local/folder/test",
        NULL
    };
    #else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";
    char *dirs[] = {
        "queue",
        "queue/diff",
        "queue/diff/local",
        "queue/diff/local/C",
        "queue/diff/local/C/folder",
        "queue/diff/local/C/folder/test",
        NULL
    };
    #endif

    int i;
    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];
    char warn_msg[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, -1);

    // seechanges_createpath()

    for(i = 0; dirs[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs[i]);
        will_return(__wrap_IsDir, 0);
    }

    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz);
    will_return(__wrap_w_compress_gzfile, -1);

    snprintf(warn_msg, OS_SIZE_128, FIM_WARN_GENDIFF_SNAPSHOT, file_name);
    expect_string(__wrap__mwarn, formatted_msg, warn_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_same_md5(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_abspath_error(void **state) {
    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    #else
    const char * file_name = "C:\\folder\\test";
    #endif

    char error_msg[OS_SIZE_128];

    errno = 0;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 0);

    snprintf(error_msg, OS_SIZE_128, "Cannot get absolute path of '%s': Success (0)", file_name);
    expect_string(__wrap__merror, formatted_msg, error_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_md5_error1(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, -1);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_md5_error2(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, -1);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_rename_error(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char error_msg[OS_SIZE_256];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, -1);

    snprintf(error_msg, OS_SIZE_256, RENAME_ERROR, last_entry, state_file, errno, strerror(errno));
    expect_string(__wrap__merror, formatted_msg, error_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_dupfile_error(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char error_msg[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    // seechanges_dupfile()
    expect_string(__wrap_fopen, __filename, file_name);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 0);

    snprintf(error_msg, OS_SIZE_128, FIM_ERROR_GENDIFF_CREATE_SNAPSHOT, file_name);
    expect_string(__wrap__merror, formatted_msg, error_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_fopen_error(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test_";
    const char * file_name_abs = "C\\folder\\test_";
    const char * default_path = "";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];
    char error_msg[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    // seechanges_dupfile()
    expect_string(__wrap_fopen, __filename, file_name);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);
    expect_string(__wrap_fopen, __filename, last_entry);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    will_return(__wrap_fclose, 1);
    will_return(__wrap_fclose, 1);

    #ifndef TEST_WINAGENT
    // symlink_to_dir()
    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0120000);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_stat, __file, file_name);
    will_return(__wrap_stat, 0040000);
    will_return(__wrap_stat, 0);
    #endif

    expect_string(__wrap_fopen, __filename, diff_file);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 0);

    snprintf(error_msg, OS_SIZE_128, FIM_ERROR_GENDIFF_OPEN_FILE, diff_file);
    expect_string(__wrap__merror, formatted_msg, error_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_fwrite_error(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    #else
    const char * file_name = "C:\\folder\\test_";
    const char * file_name_abs = "C\\folder\\test_";
    const char * default_path = "";
    const char * diff_string = "Comparing files start.txt and end.txt\r\n"
                               "***** start.txt\r\n"
                               "    1:  First line\r\n"
                               "***** END.TXT\r\n"
                               "    1:  First Line 123\r\n"
                               "    2:  Last line\r\n"
                               "*****\r\n\r\n\r\n";
    const char * diff_adapted_string = "< First line\n"
                                       "---\n"
                                       "> First Line 123\n"
                                       "> Last line\n";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];
    char error_msg[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    // seechanges_dupfile()
    expect_string(__wrap_fopen, __filename, file_name);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);
    expect_string(__wrap_fopen, __filename, last_entry);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    will_return(__wrap_fclose, 1);
    will_return(__wrap_fclose, 1);

    #ifndef TEST_WINAGENT
    // symlink_to_dir()
    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0120000);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_stat, __file, file_name);
    will_return(__wrap_stat, 0040000);
    will_return(__wrap_stat, 0);
    #endif

    expect_string(__wrap_fopen, __filename, diff_file);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);

    will_return(__wrap_fwrite, 0);

    snprintf(error_msg, OS_SIZE_128, FIM_ERROR_GENDIFF_WRITING_DATA, diff_file);
    expect_string(__wrap__merror, formatted_msg, error_msg);

    will_return(__wrap_fclose, 1);

    // gen_diff_alert()
    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);
    expect_string(__wrap_fopen, __filename, diff_file);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);
    #ifndef TEST_WINAGENT
    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);
    #else
    will_return(__wrap_fread, diff_string);
    will_return(__wrap_fread, strlen(diff_string));
    #endif
    will_return(__wrap_fclose, 1);
    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz);
    will_return(__wrap_w_compress_gzfile, 0);

    char * diff = seechanges_addfile(file_name);

    *state = diff;

    #ifndef TEST_WINAGENT
    assert_string_equal(diff, "test diff");
    #else
    assert_string_equal(diff, diff_adapted_string);
    #endif
}

void test_seechanges_addfile_run_diff_system_error(void **state) {
    const char * diff_folder = "queue/diff/local";

    #ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    const char * diff_command = "diff \"/var/ossec/queue/diff/local/folder/test/state.1\" "
                                     "\"/var/ossec/queue/diff/local/folder/test/last-entry\" > "
                                     "\"/var/ossec/queue/diff/local/folder/test/diff.1\" 2> "
                                     "/dev/null";
    #else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";
    const char * diff_command = "fc /n \"queue\\diff\\local\\C\\folder\\test\\state.1\" "
                                      "\"queue\\diff\\local\\C\\folder\\test\\last-entry\" > "
                                      "\"queue\\diff\\local\\C\\folder\\test\\diff.1\" 2> "
                                      "nul";
    #endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char error_msg[OS_SIZE_256];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    // seechanges_dupfile()
    expect_string(__wrap_fopen, __filename, file_name);
    expect_string(__wrap_fopen, __modes, "rb");
    will_return(__wrap_fopen, 1);
    expect_string(__wrap_fopen, __filename, last_entry);
    expect_string(__wrap_fopen, __modes, "wb");
    will_return(__wrap_fopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    will_return(__wrap_fclose, 1);
    will_return(__wrap_fclose, 1);

    #ifndef TEST_WINAGENT
    // symlink_to_dir()
    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, 0);
    #endif

    expect_string(__wrap_system, __command, diff_command);
    will_return(__wrap_system, -1);

    snprintf(error_msg, OS_SIZE_256, FIM_ERROR_GENDIFF_COMMAND, diff_command);
    expect_string(__wrap__merror, formatted_msg, error_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        #ifndef TEST_WINAGENT
        cmocka_unit_test_teardown(test_filter, teardown_free_string),
        cmocka_unit_test(test_symlink_to_dir),
        cmocka_unit_test(test_symlink_to_dir_no_link),
        cmocka_unit_test(test_symlink_to_dir_no_dir),
        cmocka_unit_test(test_symlink_to_dir_lstat_error),
        cmocka_unit_test(test_symlink_to_dir_stat_error),
        #endif
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

        cmocka_unit_test_teardown(test_seechanges_addfile, teardown_free_string),
        cmocka_unit_test_teardown(test_seechanges_addfile_run_diff, teardown_free_string),
        cmocka_unit_test(test_seechanges_addfile_create_gz_file),
        cmocka_unit_test(test_seechanges_addfile_same_md5),
        cmocka_unit_test(test_seechanges_addfile_abspath_error),
        cmocka_unit_test(test_seechanges_addfile_md5_error1),
        cmocka_unit_test(test_seechanges_addfile_md5_error2),
        cmocka_unit_test(test_seechanges_addfile_rename_error),
        cmocka_unit_test(test_seechanges_addfile_dupfile_error),
        cmocka_unit_test(test_seechanges_addfile_fopen_error),
        cmocka_unit_test_teardown(test_seechanges_addfile_fwrite_error, teardown_free_string),
        cmocka_unit_test(test_seechanges_addfile_run_diff_system_error),

        /* Windows specific tests */
        #ifdef TEST_WINAGENT
        /* filter */
        cmocka_unit_test_teardown(test_filter_success, teardown_string),
        cmocka_unit_test_teardown(test_filter_unchanged_string, teardown_string),
        cmocka_unit_test(test_filter_percentage_char),

        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_success, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_invalid_input, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_no_differences, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        #endif

        cmocka_unit_test(test_is_nodiff_true),
        cmocka_unit_test(test_is_nodiff_false),
        cmocka_unit_test(test_is_nodiff_regex_true),
        cmocka_unit_test(test_is_nodiff_regex_false),
        cmocka_unit_test(test_is_nodiff_no_nodiff), // This test needs to be last, it messes with global variables
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
