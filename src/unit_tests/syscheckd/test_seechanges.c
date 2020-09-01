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

#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/libc/stdlib_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/fs_op_wrappers.h"
#include "../wrappers/wazuh/os_crypto/md5_op_wrappers.h"

#ifndef TEST_WINAGENT
#define PATH_OFFSET 1
#else
#define PATH_OFFSET 0
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

/* Setup/teardown */

static int setup_group(void **state) {
    (void) state;

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif
    test_mode = 0;
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

static int setup_disk_quota_exceeded(void **state) {
    syscheck.disk_quota_full_msg = true;
    return 0;
}

static int teardown_disk_quota_exceeded(void **state) {
    syscheck.disk_quota_full_msg = false;
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

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/folder",
        "/var/ossec/queue/diff/localtmp/folder/test.file",
        NULL
    };
#else
    const char * file_name = "c:\\folder\\test.file";

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/folder",
        "queue/diff/localtmp/c/folder/test.file",
        NULL
    };
#endif

    time_t time = 12345;
    int i = 0;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);
    expect_string(__wrap_FileSize, path, "/folder/test.file");
    will_return(__wrap_FileSize, 10);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, "c\\folder\\test.file");
    will_return(__wrap_FileSizeWin, 10);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

#ifndef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
#else
    expect_string(__wrap_wfopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
#endif
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);

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

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
#else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
#endif
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);

    expect_string(__wrap_rename_ex, source, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    expect_string(__wrap_rename_ex, destination, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_rename_ex, 0);

    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);

    expect_string(__wrap_rename_ex, source, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    expect_string(__wrap_rename_ex, destination, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_rename_ex, 0);

    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#endif

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

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/folder",
        "/var/ossec/queue/diff/localtmp/folder/test.file",
        NULL
    };
#else
    const char * file_name = "c:\\folder\\test.file";

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/folder",
        "queue/diff/localtmp/c/folder/test.file",
        NULL
    };
#endif
    time_t time = 12345;
    int i = 0;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);
    expect_string(__wrap_FileSize, path, "/folder/test.file");
    will_return(__wrap_FileSize, 10);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, "c\\folder\\test.file");
    will_return(__wrap_FileSizeWin, 10);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

#ifndef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
#else
    expect_string(__wrap_wfopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
#endif
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);

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

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
#else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
#endif
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);

    expect_string(__wrap_rename_ex, source, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    expect_string(__wrap_rename_ex, destination, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_rename_ex, 0);

    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);

    expect_string(__wrap_rename_ex, source, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    expect_string(__wrap_rename_ex, destination, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_rename_ex, 0);

    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#endif

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

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/folder",
        "/var/ossec/queue/diff/localtmp/folder/test.file",
        NULL
    };
#else
    const char * file_name = "c:\\folder\\test.file";

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/folder",
        "queue/diff/localtmp/c/folder/test.file",
        NULL
    };
#endif
    time_t time = 12345;
    int i = 0;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);
	expect_string(__wrap_FileSize, path, "/folder/test.file");
    will_return(__wrap_FileSize, 10);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, "c\\folder\\test.file");
    will_return(__wrap_FileSizeWin, 10);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

#ifndef TEST_WINAGENT
    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, 0);

    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);

    expect_string(__wrap_wfopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
#else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, 0);

    expect_string(__wrap_FileSizeWin, file, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);

    expect_string(__wrap_wfopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
#endif
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 0);

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

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/folder",
        "/var/ossec/queue/diff/localtmp/folder/test.file",
        NULL
    };
#else
    const char * file_name = "c:\\folder\\test.file";

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/folder",
        "queue/diff/localtmp/c/folder/test.file",
        NULL
    };
#endif
    time_t time = 12345;
    int i = 0;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);
	expect_string(__wrap_FileSize, path, "/folder/test.file");
    will_return(__wrap_FileSize, 10);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, "c\\folder\\test.file");
    will_return(__wrap_FileSizeWin, 10);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

#ifndef TEST_WINAGENT
    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, 0);

    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);

    expect_string(__wrap_wfopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
#else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, 0);

    expect_string(__wrap_FileSizeWin, file, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);

    expect_string(__wrap_wfopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
#endif
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap__merror, formatted_msg, "(6666): Unable to generate diff alert (fread).");

    char *diff = gen_diff_alert(file_name, time, 1);

    assert_null(diff);
}

void test_gen_diff_alert_compress_error(void **state) {
#ifndef TEST_WINAGENT
    const char * file_name = "/folder/test.file";

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/folder",
        "/var/ossec/queue/diff/localtmp/folder/test.file",
        NULL
    };
#else
    const char * file_name = "c:\\folder\\test.file";

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/folder",
        "queue/diff/localtmp/c/folder/test.file",
        NULL
    };
#endif
    time_t time = 12345;
    int i = 0;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);
	expect_string(__wrap_FileSize, path, "/folder/test.file");
    will_return(__wrap_FileSize, 10);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, "c\\folder\\test.file");
    will_return(__wrap_FileSizeWin, 10);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

#ifndef TEST_WINAGENT
    expect_string(__wrap_wfopen, __filename, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
#else
    expect_string(__wrap_wfopen, __filename, "queue/diff/local/c\\folder\\test.file/diff.12345");
#endif
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);

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

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/folder/test.file/diff.12345");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
#else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
#endif
    will_return(__wrap_w_compress_gzfile, -1);

#ifndef TEST_WINAGENT
    expect_string(__wrap__mwarn, formatted_msg, "(6914): Cannot create a snapshot of file '/folder/test.file'");
#else
    expect_string(__wrap__mwarn, formatted_msg, "(6914): Cannot create a snapshot of file 'c:\\folder\\test.file'");
#endif

#ifndef TEST_WINAGENT
    expect_string(__wrap_rename_ex, source, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    expect_string(__wrap_rename_ex, destination, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_rename_ex, 0);

    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#else
    expect_string(__wrap_rename_ex, source, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    expect_string(__wrap_rename_ex, destination, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_rename_ex, 0);

    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#endif

    char *diff = gen_diff_alert(file_name, time, 1);

    *state = diff;

#ifndef TEST_WINAGENT
    assert_string_equal(diff, "test diff");
#else
    assert_string_equal(diff, "< First line\n---\n> First Line 123\n> Last line\n");
#endif
}

void test_gen_diff_alert_exceed_disk_quota_limit(void **state) {
#ifndef TEST_WINAGENT
    const char * file_name = "/folder/test.file";

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/folder",
        "/var/ossec/queue/diff/localtmp/folder/test.file",
        NULL
    };
#else
    const char * file_name = "c:\\folder\\test.file";

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/folder",
        "queue/diff/localtmp/c/folder/test.file",
        NULL
    };
#endif
    time_t time = 12345;
    int i = 0;
    syscheck.diff_folder_size = 2048;

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/local/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);
	expect_string(__wrap_FileSize, path, "/folder/test.file");
    will_return(__wrap_FileSize, 10);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/local/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, "c\\folder\\test.file");
    will_return(__wrap_FileSizeWin, 10);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

#ifndef TEST_WINAGENT
    expect_string(__wrap_w_compress_gzfile, filesrc, "/folder/test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, 0);

    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, syscheck.disk_quota_limit * 1024 + 1024 * 2);

    expect_string(__wrap__mdebug2, formatted_msg, "(6350): The maximum configured size for the '/var/ossec/queue/diff' folder has been reached, the diff operation cannot be performed.");

	expect_string(__wrap_FileSize, path, "/folder/test.file");
    will_return(__wrap_FileSize, syscheck.disk_quota_limit * 1024 + 1024 * 2);
	expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/localtmp/folder/test.file/last-entry.gz");
    will_return(__wrap_FileSize, syscheck.disk_quota_limit * 1024 + 1024 * 2);
#else
    expect_string(__wrap_w_compress_gzfile, filesrc, "c:\\folder\\test.file");
    expect_string(__wrap_w_compress_gzfile, filedst, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_w_compress_gzfile, 0);

    expect_string(__wrap_FileSizeWin, file, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, syscheck.disk_quota_limit * 1024 + 1024 * 2);

    expect_string(__wrap__mdebug2, formatted_msg, "(6350): The maximum configured size for the 'queue/diff' folder has been reached, the diff operation cannot be performed.");
	expect_string(__wrap_FileSizeWin, file, "c:\\folder\\test.file");
    will_return(__wrap_FileSizeWin, syscheck.disk_quota_limit * 1024 + 1024 * 2);
	expect_string(__wrap_FileSizeWin, file, "queue/diff/localtmp/c\\folder\\test.file/last-entry.gz");
    will_return(__wrap_FileSizeWin, syscheck.disk_quota_limit * 1024 + 1024 * 2);
#endif

    // seechanges_delete_compressed_file
    const char * diff_folder = "queue/diff";
    char containing_folder[PATH_MAX + 1];
    char last_entry_file[PATH_MAX + 1];
    float file_size = 0.0;

#ifndef TEST_WINAGENT
    const char * file_name_delete = "/folder/test.file";
    const char * file_name_delete_abs = file_name_delete;
    const char * default_path = "/var/ossec/";

    snprintf(containing_folder, OS_SIZE_128, "%s%s/local%s", default_path, diff_folder, file_name_delete_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local%s/last-entry.gz", default_path, diff_folder, file_name_delete_abs);
#else
    const char * file_name_delete = "c:\\folder\\test.file";
    const char * file_name_delete_abs = "c\\folder\\test.file";
    const char * default_path = "";

    snprintf(containing_folder, OS_SIZE_128, "%s%s/local/%s", default_path, diff_folder, file_name_delete_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local/%s/last-entry.gz", default_path, diff_folder, file_name_delete_abs);

    expect_string(__wrap_abspath, path, containing_folder);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_abspath, path, last_entry_file);
    will_return(__wrap_abspath, 1);
#endif

    expect_string(__wrap_IsDir, file, containing_folder);
    will_return(__wrap_IsDir, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, last_entry_file);
    will_return(__wrap_FileSize, 1024);
#else
    expect_string(__wrap_FileSizeWin, file, last_entry_file);
    will_return(__wrap_FileSizeWin, 1024);
#endif

    expect_string(__wrap_rmdir_ex, name, containing_folder);
    will_return(__wrap_rmdir_ex, 0);

    // gen_diff_alert
#ifndef TEST_WINAGENT
    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
#else
    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
#endif
    will_return(__wrap_rmdir_ex, 0);

    char *diff = gen_diff_alert(file_name, time, 1);

    assert_null(diff);
}

void test_seechanges_dupfile(void **state) {
    (void) state;

    const char * old_file = "/folder/test.old";
    const char * new_file = "/folder/test.new";

    expect_string(__wrap_wfopen, __filename, old_file);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);

    expect_string(__wrap_wfopen, __filename, new_file);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fread, "test dup file");
    will_return(__wrap_fread, 13);

    will_return(__wrap_fwrite, 13);

    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = seechanges_dupfile(old_file, new_file);

    assert_int_equal(ret, 1);
}

void test_seechanges_dupfile_fopen_error1(void **state) {
    (void) state;

    const char * old_file = "/folder/test.old";
    const char * new_file = "/folder/test.new";

    expect_string(__wrap_wfopen, __filename, old_file);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 0);

    int ret = seechanges_dupfile(old_file, new_file);

    assert_int_equal(ret, 0);
}

void test_seechanges_dupfile_fopen_error2(void **state) {
    (void) state;

    const char * old_file = "/folder/test.old";
    const char * new_file = "/folder/test.new";

    expect_string(__wrap_wfopen, __filename, old_file);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);

    expect_string(__wrap_wfopen, __filename, new_file);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = seechanges_dupfile(old_file, new_file);

    assert_int_equal(ret, 0);
}

void test_seechanges_dupfile_fwrite_error(void **state) {
    (void) state;

    const char * old_file = "/folder/test.old";
    const char * new_file = "/folder/test.new";

    expect_string(__wrap_wfopen, __filename, old_file);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);

    expect_string(__wrap_wfopen, __filename, new_file);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fread, "test dup file");
    will_return(__wrap_fread, 13);

    will_return(__wrap_fwrite, 0);

    expect_string(__wrap__merror, formatted_msg, "(6668): Unable to write data on file '/folder/test.new'");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 1);
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
    const char * diff_tmp_folder = "queue/diff/localtmp";
    int i = 0;

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
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

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test_",
        NULL
    };
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 20);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 20);
#endif

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

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    // seechanges_dupfile()
    expect_string(__wrap_wfopen, __filename, file_name);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);
    expect_string(__wrap_wfopen, __filename, last_entry);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/state.1");
    will_return(__wrap_unlink, 0);
    // symlink_to_dir()
    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0120000);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_stat, __file, file_name);
    will_return(__wrap_stat, 0040000);
    will_return(__wrap_stat, 0);
#endif

    expect_string(__wrap_wfopen, __filename, diff_file);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/last-entry");
    will_return(__wrap_unlink, 0);
#endif

    // gen_diff_alert()
    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/local/home/test/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

    expect_string(__wrap_wfopen, __filename, diff_file);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);
#ifndef TEST_WINAGENT
    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);
#else
    will_return(__wrap_fread, diff_string);
    will_return(__wrap_fread, strlen(diff_string));
#endif
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/diff.1");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz_tmp);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name);
    will_return(__wrap_FileSize, 10);
    expect_string(__wrap_FileSize, path, last_entry_gz_tmp);
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, file_name_abs);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, last_entry_gz_tmp);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    expect_string(__wrap_rename_ex, source, last_entry_gz_tmp);
    expect_string(__wrap_rename_ex, destination, last_entry_gz);
    will_return(__wrap_rename_ex, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#else
    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#endif

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
    const char * diff_tmp_folder = "queue/diff/localtmp";
    int i = 0;

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test";
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

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test",
        NULL
    };
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/state.1");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/last-entry");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    // seechanges_dupfile()
    expect_string(__wrap_wfopen, __filename, file_name);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);
    expect_string(__wrap_wfopen, __filename, last_entry);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/diff.1");
    will_return(__wrap_unlink, 0);

    // symlink_to_dir()
    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_system, __command, "diff \"/var/ossec/queue/diff/local/home/test/state.1\" "
                                            "\"/var/ossec/queue/diff/local/home/test/last-entry\" > "
                                            "\"/var/ossec/queue/diff/local/home/test/diff.1\" 2> "
                                            "/dev/null");
    will_return(__wrap_system, 256);
#else
    expect_string(__wrap_system, __command, "fc /n \"queue\\diff\\local\\c\\windows\\system32\\drivers\\etc\\test\\state.1\" "
                                            "\"queue\\diff\\local\\c\\windows\\system32\\drivers\\etc\\test\\last-entry\" > "
                                            "\"queue\\diff\\local\\c\\windows\\system32\\drivers\\etc\\test\\diff.1\" 2> "
                                            "nul");
    will_return(__wrap_system, 0);
#endif

    // gen_diff_alert()
    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, last_entry_gz);
    will_return(__wrap_FileSize, 1024 * 1024);
    expect_string(__wrap_FileSize, path, file_name);
    will_return(__wrap_FileSize, 10);
#else
    expect_string(__wrap_FileSizeWin, file, last_entry_gz);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, file_name_abs);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

    expect_string(__wrap_wfopen, __filename, diff_file);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);
#ifndef TEST_WINAGENT
    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);
#else
    will_return(__wrap_fread, diff_string);
    will_return(__wrap_fread, strlen(diff_string));
#endif
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz_tmp);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, last_entry_gz_tmp);
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, last_entry_gz_tmp);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    expect_string(__wrap_rename_ex, source, last_entry_gz_tmp);
    expect_string(__wrap_rename_ex, destination, last_entry_gz);
    will_return(__wrap_rename_ex, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#else
    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#endif

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
    const char * diff_tmp_folder = "queue/diff/localtmp";

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    char *dirs[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/local",
        "/var/ossec/queue/diff/local/home",
        "/var/ossec/queue/diff/local/home/test",
        NULL
    };

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
    const char * default_path = "";
    char *dirs[] = {
        "queue",
        "queue/diff",
        "queue/diff/local",
        "queue/diff/local/c",
        "queue/diff/local/c/windows",
        "queue/diff/local/c/windows/system32",
        "queue/diff/local/c/windows/system32/drivers",
        "queue/diff/local/c/windows/system32/drivers/etc",
        "queue/diff/local/c/windows/system32/drivers/etc/test_",
        NULL
    };

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test_",
        NULL
    };
#endif

    int i;
    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];
    char warn_msg[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, -1);

    // seechanges_createpath

    for (i = 0; dirs[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs[i]);
        will_return(__wrap_IsDir, 0);
    }

    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, -1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz_tmp);
    will_return(__wrap_w_compress_gzfile, -1);

    snprintf(warn_msg, OS_SIZE_128, FIM_WARN_GENDIFF_SNAPSHOT, file_name);
    expect_string(__wrap__mwarn, formatted_msg, warn_msg);

#ifdef TEST_WINAGENT
    expect_string(__wrap_abspath, path, "queue/diff/localtmp");
    will_return(__wrap_abspath, 1);
#endif

#ifndef TEST_WINAGENT
    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#else
    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#endif

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_same_md5(void **state) {
    const char * diff_folder = "queue/diff/local";
    const char * diff_tmp_folder = "queue/diff/localtmp";
    int i = 0;

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
    const char * default_path = "";

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test_",
        NULL
    };
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

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

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/last-entry");
    will_return(__wrap_unlink, 0);
#endif

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_abspath_error(void **state) {
#ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
#else
    const char * file_name = "c:\\folder\\test";
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
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
    const char * default_path = "";
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif


    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, -1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/last-entry");
    will_return(__wrap_unlink, 0);
#endif

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_md5_error2(void **state) {
    const char * diff_folder = "queue/diff/local";

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
    const char * default_path = "";
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

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

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/last-entry");
    will_return(__wrap_unlink, 0);
#endif

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_rename_error(void **state) {
    const char * diff_folder = "queue/diff/local";

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
    const char * default_path = "";
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char error_msg[OS_SIZE_512];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

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

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, -1);

    snprintf(error_msg, OS_SIZE_512, RENAME_ERROR, last_entry, state_file, errno, strerror(errno));
    expect_string(__wrap__merror, formatted_msg, error_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_dupfile_error(void **state) {
    const char * diff_folder = "queue/diff/local";

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
    const char * default_path = "";
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char error_msg[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

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

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    // seechanges_dupfile()
    expect_string(__wrap_wfopen, __filename, file_name);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 0);

    snprintf(error_msg, OS_SIZE_128, FIM_ERROR_GENDIFF_CREATE_SNAPSHOT, file_name);
    expect_string(__wrap__merror, formatted_msg, error_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_fopen_error(void **state) {
    const char * diff_folder = "queue/diff/local";

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
    const char * default_path = "";
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];
    char error_msg[OS_SIZE_256];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/state.1");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/last-entry");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    // seechanges_dupfile()
    expect_string(__wrap_wfopen, __filename, file_name);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);
    expect_string(__wrap_wfopen, __filename, last_entry);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/diff.1");
    will_return(__wrap_unlink, 0);
#endif

#ifndef TEST_WINAGENT
    // symlink_to_dir()
    expect_string(__wrap_lstat, filename, file_name);
    will_return(__wrap_lstat, 0120000);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_stat, __file, file_name);
    will_return(__wrap_stat, 0040000);
    will_return(__wrap_stat, 0);
#endif

    expect_string(__wrap_wfopen, __filename, diff_file);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 0);

    snprintf(error_msg, OS_SIZE_256, FIM_ERROR_GENDIFF_OPEN_FILE, diff_file);
    expect_string(__wrap__merror, formatted_msg, error_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_fwrite_error(void **state) {
    const char * diff_folder = "queue/diff/local";
    const char * diff_tmp_folder = "queue/diff/localtmp";
    int i = 0;

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
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

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test_",
        NULL
    };
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];
    char error_msg[OS_SIZE_256];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/state.1");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/last-entry");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    // seechanges_dupfile()
    expect_string(__wrap_wfopen, __filename, file_name);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);
    expect_string(__wrap_wfopen, __filename, last_entry);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 1);
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

    expect_string(__wrap_wfopen, __filename, diff_file);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fwrite, 0);

    snprintf(error_msg, OS_SIZE_256, FIM_ERROR_GENDIFF_WRITING_DATA, diff_file);
    expect_string(__wrap__merror, formatted_msg, error_msg);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/diff.1");
    will_return(__wrap_unlink, 0);
#endif

    // gen_diff_alert()
    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, "/var/ossec/queue/diff/local/home/test/last-entry.gz");
    will_return(__wrap_FileSize, 1024 * 1024);
    expect_string(__wrap_FileSize, path, "/home/test");
    will_return(__wrap_FileSize, 10);
#else
    expect_string(__wrap_FileSizeWin, file, "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_/last-entry.gz");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
    expect_string(__wrap_FileSizeWin, file, "c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    // seechanges_createpath
    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, 1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

    expect_string(__wrap_wfopen, __filename, diff_file);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);
#ifndef TEST_WINAGENT
    will_return(__wrap_fread, "test diff");
    will_return(__wrap_fread, 9);
#else
    will_return(__wrap_fread, diff_string);
    will_return(__wrap_fread, strlen(diff_string));
#endif
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz_tmp);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, last_entry_gz_tmp);
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, last_entry_gz_tmp);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    expect_string(__wrap_rename_ex, source, last_entry_gz_tmp);
    expect_string(__wrap_rename_ex, destination, last_entry_gz);
    will_return(__wrap_rename_ex, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#else
    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
    will_return(__wrap_rmdir_ex, 0);
#endif

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
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
    const char * diff_command = "diff \"/var/ossec/queue/diff/local/home/test/state.1\" "
                                     "\"/var/ossec/queue/diff/local/home/test/last-entry\" > "
                                     "\"/var/ossec/queue/diff/local/home/test/diff.1\" 2> "
                                     "/dev/null";
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test";
    const char * default_path = "";
    const char * diff_command = "fc /n \"queue\\diff\\local\\c\\windows\\system32\\drivers\\etc\\test\\state.1\" "
                                      "\"queue\\diff\\local\\c\\windows\\system32\\drivers\\etc\\test\\last-entry\" > "
                                      "\"queue\\diff\\local\\c\\windows\\system32\\drivers\\etc\\test\\diff.1\" 2> "
                                      "nul";
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char error_msg[OS_SIZE_256];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, 0);

    expect_string(__wrap_OS_MD5_File, fname, last_entry);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "3c183a30cffcda1408daf1c61d47b274");
    will_return(__wrap_OS_MD5_File, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/state.1");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_OS_MD5_File, fname, file_name);
    expect_value(__wrap_OS_MD5_File, mode, OS_BINARY);
    will_return(__wrap_OS_MD5_File, "636fd4d56b21e95c6bde60277ed355ea");
    will_return(__wrap_OS_MD5_File, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/last-entry");
    will_return(__wrap_unlink, 0);
#endif

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap_rename, __old, last_entry);
    expect_string(__wrap_rename, __new, state_file);
    will_return(__wrap_rename, 1);

    expect_string(__wrap_File_DateofChange, file, last_entry);
    will_return(__wrap_File_DateofChange, 1);

    // seechanges_dupfile()
    expect_string(__wrap_wfopen, __filename, file_name);
    expect_string(__wrap_wfopen, __modes, "rb");
    will_return(__wrap_wfopen, 1);
    expect_string(__wrap_wfopen, __filename, last_entry);
    expect_string(__wrap_wfopen, __modes, "wb");
    will_return(__wrap_wfopen, 1);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 13);
    will_return(__wrap_fwrite, 13);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_unlink, file, "/var/ossec/queue/diff/local/home/test/diff.1");
    will_return(__wrap_unlink, 0);
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

void test_seechanges_addfile_file_size_exceeded(void **state) {
#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
    const char * default_path = "";
#endif

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, syscheck.diff_size_limit[2] * 2 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, syscheck.diff_size_limit[2] * 2 * 1024);
#endif

    char info_msg[OS_SIZE_128];
    snprintf(info_msg,
             OS_SIZE_128,
             "(6349): File \'%s\' is too big for configured maximum size to perform diff operation.",
             file_name_abs);

    expect_string(__wrap__mdebug2, formatted_msg, info_msg);

    // seechanges_delete_compressed_file
    const char * diff_folder = "queue/diff";
    char containing_folder[PATH_MAX + 1];
    char last_entry_file[PATH_MAX + 1];
    float file_size = 0.0;

#ifndef TEST_WINAGENT
    snprintf(containing_folder, OS_SIZE_128, "%s%s/local%s", default_path, diff_folder, file_name_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local%s/last-entry.gz", default_path, diff_folder, file_name_abs);
#else
    snprintf(containing_folder, OS_SIZE_128, "%s%s/local/%s", default_path, diff_folder, file_name_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local/%s/last-entry.gz", default_path, diff_folder, file_name_abs);

    expect_string(__wrap_abspath, path, containing_folder);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_abspath, path, last_entry_file);
    will_return(__wrap_abspath, 1);
#endif

    expect_string(__wrap_IsDir, file, containing_folder);
    will_return(__wrap_IsDir, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, last_entry_file);
    will_return(__wrap_FileSize, 1024);
#else
    expect_string(__wrap_FileSizeWin, file, last_entry_file);
    will_return(__wrap_FileSizeWin, 1024);
#endif

    expect_string(__wrap_rmdir_ex, name, containing_folder);
    will_return(__wrap_rmdir_ex, 0);

    seechanges_addfile(file_name);
}

void test_seechanges_addfile_disk_quota_exceeded(void **state) {
    const char * diff_folder = "queue/diff/local";
    const char * diff_tmp_folder = "queue/diff/localtmp";
    int i = 0;

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    char *dirs[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/local",
        "/var/ossec/queue/diff/local/home",
        "/var/ossec/queue/diff/local/home/test",
        NULL
    };

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
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

    char *dirs[] = {
        "queue",
        "queue/diff",
        "queue/diff/local",
        "queue/diff/local/c",
        "queue/diff/local/c/windows",
        "queue/diff/local/c/windows/system32",
        "queue/diff/local/c/windows/system32/drivers",
        "queue/diff/local/c/windows/system32/drivers/etc",
        "queue/diff/local/c/windows/system32/drivers/etc/test_",
        NULL
    };

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test_",
        NULL
    };
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, -1);

    // seechanges_createpath

    for (i = 0; dirs[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs[i]);
        will_return(__wrap_IsDir, 0);
    }

    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, -1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

    // seechanges_addfile
    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz_tmp);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/localtmp/home/test");
#else
    expect_string(__wrap_abspath, path, "queue/diff/localtmp/c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_DirSize, path, "queue/diff/localtmp/c\\windows\\system32\\drivers\\etc\\test_");
#endif

    will_return(__wrap_DirSize, syscheck.disk_quota_limit * 2 * 1024);

    char info_msg[OS_SIZE_512];
    snprintf(info_msg, OS_SIZE_512, FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);

    expect_string(__wrap__mdebug2, formatted_msg, info_msg);

#ifndef TEST_WINAGENT
    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/local/home/test");
#else
    expect_string(__wrap_abspath, path, "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_rmdir_ex, name, "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_");
#endif
    will_return(__wrap_rmdir_ex, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/localtmp");
#else
    expect_string(__wrap_abspath, path, "queue/diff/localtmp");
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_rmdir_ex, name, "queue/diff/localtmp");
#endif
    will_return(__wrap_rmdir_ex, 0);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_disk_quota_exceeded_rmdir_ex_error1(void **state) {
    const char * diff_folder = "queue/diff/local";
    const char * diff_tmp_folder = "queue/diff/localtmp";
    int i = 0;

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    char *dirs[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/local",
        "/var/ossec/queue/diff/local/home",
        "/var/ossec/queue/diff/local/home/test",
        NULL
    };

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
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

    char *dirs[] = {
        "queue",
        "queue/diff",
        "queue/diff/local",
        "queue/diff/local/c",
        "queue/diff/local/c/windows",
        "queue/diff/local/c/windows/system32",
        "queue/diff/local/c/windows/system32/drivers",
        "queue/diff/local/c/windows/system32/drivers/etc",
        "queue/diff/local/c/windows/system32/drivers/etc/test_",
        NULL
    };

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test_",
        NULL
    };
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, -1);

    // seechanges_createpath

    for (i = 0; dirs[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs[i]);
        will_return(__wrap_IsDir, 0);
    }

    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, -1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

    // seechanges_addfile
    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz_tmp);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/localtmp/home/test");
#else
    expect_string(__wrap_abspath, path, "queue/diff/localtmp/c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_DirSize, path, "queue/diff/localtmp/c\\windows\\system32\\drivers\\etc\\test_");
#endif

    will_return(__wrap_DirSize, syscheck.disk_quota_limit * 2 * 1024);

    char info_msg[OS_SIZE_512];
    snprintf(info_msg, OS_SIZE_512, FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);

    expect_string(__wrap__mdebug2, formatted_msg, info_msg);

    char containing_folder[OS_SIZE_128];
    char containing_folder_tmp[OS_SIZE_128];

#ifndef TEST_WINAGENT
    snprintf(containing_folder, OS_SIZE_128, "%s", "/var/ossec/queue/diff/local/home/test");
#else
    expect_string(__wrap_abspath, path, "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_abspath, 1);

    snprintf(containing_folder, OS_SIZE_128, "%s", "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_");
#endif
    expect_string(__wrap_rmdir_ex, name, containing_folder);
    will_return(__wrap_rmdir_ex, -1);

    char debug_msg[OS_SIZE_512];

#ifndef TEST_WINAGENT
    snprintf(debug_msg, OS_SIZE_512, RMDIR_ERROR, containing_folder, 39, "Directory not empty");
#else
    snprintf(debug_msg, OS_SIZE_512, RMDIR_ERROR, containing_folder, 41, "Directory not empty");
#endif

    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

#ifndef TEST_WINAGENT
    snprintf(containing_folder_tmp, OS_SIZE_128, "%s", "/var/ossec/queue/diff/localtmp");
#else
    expect_string(__wrap_abspath, path, "queue/diff/localtmp");
    will_return(__wrap_abspath, 1);

    snprintf(containing_folder_tmp, OS_SIZE_128, "%s", "queue/diff/localtmp");
#endif
    expect_string(__wrap_rmdir_ex, name, containing_folder_tmp);
    will_return(__wrap_rmdir_ex, 0);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_disk_quota_exceeded_rmdir_ex_error2(void **state) {
    const char * diff_folder = "queue/diff/local";
    const char * diff_tmp_folder = "queue/diff/localtmp";
    int i = 0;

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    char *dirs[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/local",
        "/var/ossec/queue/diff/local/home",
        "/var/ossec/queue/diff/local/home/test",
        NULL
    };

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
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

    char *dirs[] = {
        "queue",
        "queue/diff",
        "queue/diff/local",
        "queue/diff/local/c",
        "queue/diff/local/c/windows",
        "queue/diff/local/c/windows/system32",
        "queue/diff/local/c/windows/system32/drivers",
        "queue/diff/local/c/windows/system32/drivers/etc",
        "queue/diff/local/c/windows/system32/drivers/etc/test_",
        NULL
    };

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test_",
        NULL
    };
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, -1);

    // seechanges_createpath

    for (i = 0; dirs[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs[i]);
        will_return(__wrap_IsDir, 0);
    }

    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, -1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

    // seechanges_addfile
    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz_tmp);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/localtmp/home/test");
#else
    expect_string(__wrap_abspath, path, "queue/diff/localtmp/c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_DirSize, path, "queue/diff/localtmp/c\\windows\\system32\\drivers\\etc\\test_");
#endif

    will_return(__wrap_DirSize, syscheck.disk_quota_limit * 2 * 1024);

    char info_msg[OS_SIZE_512];
    snprintf(info_msg, OS_SIZE_512, FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);

    expect_string(__wrap__mdebug2, formatted_msg, info_msg);

    char containing_folder[OS_SIZE_128];
    char containing_folder_tmp[OS_SIZE_128];

#ifndef TEST_WINAGENT
    snprintf(containing_folder, OS_SIZE_128, "%s", "/var/ossec/queue/diff/local/home/test");
#else
    expect_string(__wrap_abspath, path, "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_abspath, 1);

    snprintf(containing_folder, OS_SIZE_128, "%s", "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_");
#endif
    expect_string(__wrap_rmdir_ex, name, containing_folder);
    will_return(__wrap_rmdir_ex, 0);

#ifndef TEST_WINAGENT
    snprintf(containing_folder_tmp, OS_SIZE_128, "%s", "/var/ossec/queue/diff/localtmp");
#else
    expect_string(__wrap_abspath, path, "queue/diff/localtmp");
    will_return(__wrap_abspath, 1);

    snprintf(containing_folder_tmp, OS_SIZE_128, "%s", "queue/diff/localtmp");
#endif
    expect_string(__wrap_rmdir_ex, name, containing_folder_tmp);
    will_return(__wrap_rmdir_ex, -1);

    char debug_msg[OS_SIZE_512];

#ifndef TEST_WINAGENT
    snprintf(debug_msg, OS_SIZE_512, RMDIR_ERROR, containing_folder_tmp, 39, "Directory not empty");
#else
    snprintf(debug_msg, OS_SIZE_512, RMDIR_ERROR, containing_folder_tmp, 41, "Directory not empty");
#endif

    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_addfile_disk_quota_exceeded_rmdir_ex_error3(void **state) {
    const char * diff_folder = "queue/diff/local";
    const char * diff_tmp_folder = "queue/diff/localtmp";
    int i = 0;

#ifndef TEST_WINAGENT
    const char * file_name = "/home/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    char *dirs[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/local",
        "/var/ossec/queue/diff/local/home",
        "/var/ossec/queue/diff/local/home/test",
        NULL
    };

    char *dirs_tmp[] = {
        "/var",
        "/var/ossec",
        "/var/ossec/queue",
        "/var/ossec/queue/diff",
        "/var/ossec/queue/diff/localtmp",
        "/var/ossec/queue/diff/localtmp/home",
        "/var/ossec/queue/diff/localtmp/home/test",
        NULL
    };
#else
    const char * file_name = "c:\\windows\\system32\\drivers\\etc\\test_";
    const char * file_name_abs = "c\\windows\\system32\\drivers\\etc\\test_";
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

    char *dirs[] = {
        "queue",
        "queue/diff",
        "queue/diff/local",
        "queue/diff/local/c",
        "queue/diff/local/c/windows",
        "queue/diff/local/c/windows/system32",
        "queue/diff/local/c/windows/system32/drivers",
        "queue/diff/local/c/windows/system32/drivers/etc",
        "queue/diff/local/c/windows/system32/drivers/etc/test_",
        NULL
    };

    char *dirs_tmp[] = {
        "queue",
        "queue/diff",
        "queue/diff/localtmp",
        "queue/diff/localtmp/c",
        "queue/diff/localtmp/c/windows",
        "queue/diff/localtmp/c/windows/system32",
        "queue/diff/localtmp/c/windows/system32/drivers",
        "queue/diff/localtmp/c/windows/system32/drivers/etc",
        "queue/diff/localtmp/c/windows/system32/drivers/etc/test_",
        NULL
    };
#endif

    char last_entry[OS_SIZE_128];
    char last_entry_gz[OS_SIZE_128];
    char last_entry_tmp[OS_SIZE_128];
    char last_entry_gz_tmp[OS_SIZE_128];
    char state_file[OS_SIZE_128];
    char diff_file[OS_SIZE_128];

    snprintf(last_entry, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz, OS_SIZE_128, "%.124s.gz", last_entry);
    snprintf(last_entry_tmp, OS_SIZE_128, "%s%s/%s/last-entry", default_path, diff_tmp_folder, file_name_abs + PATH_OFFSET);
    snprintf(last_entry_gz_tmp, OS_SIZE_128, "%.124s.gz", last_entry_tmp);
    snprintf(state_file, OS_SIZE_128, "%s%s/%s/state.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);
    snprintf(diff_file, OS_SIZE_128, "%s%s/%s/diff.1", default_path, diff_folder, file_name_abs + PATH_OFFSET);

    expect_string(__wrap_abspath, path, file_name);
    will_return(__wrap_abspath, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_name_abs);
    will_return(__wrap_FileSize, 2048);
#else
    expect_string(__wrap_FileSizeWin, file, file_name);
    will_return(__wrap_FileSizeWin, 2048);
#endif

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, last_entry_gz);
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, last_entry);
    will_return(__wrap_w_uncompress_gzfile, -1);

    // seechanges_createpath

    for (i = 0; dirs[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs[i]);
        will_return(__wrap_IsDir, 0);
    }

    for (i = 0; dirs_tmp[i]; i++) {
        expect_string(__wrap_IsDir, file, dirs_tmp[i]);
        will_return(__wrap_IsDir, -1);
        expect_string(__wrap_mkdir, __path, dirs_tmp[i]);
#ifndef TEST_WINAGENT
        expect_value(__wrap_mkdir, __mode, 0770);
#endif
        will_return(__wrap_mkdir, 0);
    }

    // seechanges_addfile
    expect_string(__wrap_w_compress_gzfile, filesrc, file_name);
    expect_string(__wrap_w_compress_gzfile, filedst, last_entry_gz_tmp);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/localtmp/home/test");
#else
    expect_string(__wrap_abspath, path, "queue/diff/localtmp/c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_DirSize, path, "queue/diff/localtmp/c\\windows\\system32\\drivers\\etc\\test_");
#endif

    will_return(__wrap_DirSize, syscheck.disk_quota_limit * 2 * 1024);

    char info_msg[OS_SIZE_512];
    snprintf(info_msg, OS_SIZE_512, FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);

    expect_string(__wrap__mdebug2, formatted_msg, info_msg);

    char containing_folder[OS_SIZE_128];
    char containing_folder_tmp[OS_SIZE_128];

#ifndef TEST_WINAGENT
    snprintf(containing_folder, OS_SIZE_128, "%s", "/var/ossec/queue/diff/local/home/test");
#else
    expect_string(__wrap_abspath, path, "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_");
    will_return(__wrap_abspath, 1);

    snprintf(containing_folder, OS_SIZE_128, "%s", "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test_");
#endif
    expect_string(__wrap_rmdir_ex, name, containing_folder);
    will_return(__wrap_rmdir_ex, -1);

    char debug_msg1[OS_SIZE_512];
    snprintf(debug_msg1, OS_SIZE_512, RMDIR_ERROR, containing_folder, errno, strerror(errno));
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg1);

#ifndef TEST_WINAGENT
    snprintf(containing_folder_tmp, OS_SIZE_128, "%s", "/var/ossec/queue/diff/localtmp");
#else
    expect_string(__wrap_abspath, path, "queue/diff/localtmp");
    will_return(__wrap_abspath, 1);

    snprintf(containing_folder_tmp, OS_SIZE_128, "%s", "queue/diff/localtmp");
#endif
    expect_string(__wrap_rmdir_ex, name, containing_folder_tmp);
    will_return(__wrap_rmdir_ex, -1);

    char debug_msg2[OS_SIZE_512];
    snprintf(debug_msg2, OS_SIZE_512, RMDIR_ERROR, containing_folder_tmp, errno, strerror(errno));
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg2);

    char * diff = seechanges_addfile(file_name);

    assert_null(diff);
}

void test_seechanges_delete_compressed_file_not_dir(void **state) {
    const char * diff_folder = "queue/diff";
    char containing_folder[PATH_MAX + 1];
    char last_entry_file[PATH_MAX + 1];
    float file_size = 0.0;

#ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    snprintf(containing_folder, OS_SIZE_128, "%s%s/local%s", default_path, diff_folder, file_name_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local%s/last-entry.gz", default_path, diff_folder, file_name_abs);
#else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";

    snprintf(containing_folder, OS_SIZE_128, "%s%s/local/%s", default_path, diff_folder, file_name_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local/%s/last-entry.gz", default_path, diff_folder, file_name_abs);

    expect_string(__wrap_abspath, path, containing_folder);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_abspath, path, last_entry_file);
    will_return(__wrap_abspath, 1);
#endif

    expect_string(__wrap_IsDir, file, containing_folder);
    will_return(__wrap_IsDir, -1);

    seechanges_delete_compressed_file(file_name_abs);
}

void test_seechanges_delete_compressed_file_rm_error(void **state) {
    const char * diff_folder = "queue/diff";
    char containing_folder[PATH_MAX + 1];
    char last_entry_file[PATH_MAX + 1];
    float file_size = 0.0;

#ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    snprintf(containing_folder, OS_SIZE_128, "%s%s/local%s", default_path, diff_folder, file_name_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local%s/last-entry.gz", default_path, diff_folder, file_name_abs);
#else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";

    snprintf(containing_folder, OS_SIZE_128, "%s%s/local/%s", default_path, diff_folder, file_name_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local/%s/last-entry.gz", default_path, diff_folder, file_name_abs);

    expect_string(__wrap_abspath, path, containing_folder);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_abspath, path, last_entry_file);
    will_return(__wrap_abspath, 1);
#endif

    expect_string(__wrap_IsDir, file, containing_folder);
    will_return(__wrap_IsDir, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, last_entry_file);
    will_return(__wrap_FileSize, 1024);
#else
    expect_string(__wrap_FileSizeWin, file, last_entry_file);
    will_return(__wrap_FileSizeWin, 1024);
#endif

    expect_string(__wrap_rmdir_ex, name, containing_folder);
    will_return(__wrap_rmdir_ex, -1);

    errno = 2;

    char debug_msg[OS_SIZE_512];

#ifndef TEST_WINAGENT
    snprintf(debug_msg,
             OS_SIZE_512,
             RMDIR_ERROR,
             "/var/ossec/queue/diff/local/folder/test",
             39,
             "Directory not empty");
#else
    snprintf(debug_msg,
             OS_SIZE_512,
             RMDIR_ERROR,
             "queue/diff/local/C\\folder\\test",
             41,
             "Directory not empty");
#endif

    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    seechanges_delete_compressed_file(file_name_abs);
}

void test_seechanges_delete_compressed_file_successful(void **state) {
    const char * diff_folder = "queue/diff";
    char containing_folder[PATH_MAX + 1];
    char last_entry_file[PATH_MAX + 1];
    float file_size = 0.0;

#ifndef TEST_WINAGENT
    const char * file_name = "/folder/test";
    const char * file_name_abs = file_name;
    const char * default_path = "/var/ossec/";

    snprintf(containing_folder, OS_SIZE_128, "%s%s/local%s", default_path, diff_folder, file_name_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local%s/last-entry.gz", default_path, diff_folder, file_name_abs);
#else
    const char * file_name = "C:\\folder\\test";
    const char * file_name_abs = "C\\folder\\test";
    const char * default_path = "";

    snprintf(containing_folder, OS_SIZE_128, "%s%s/local/%s", default_path, diff_folder, file_name_abs);
    snprintf(last_entry_file, OS_SIZE_128, "%s%s/local/%s/last-entry.gz", default_path, diff_folder, file_name_abs);

    expect_string(__wrap_abspath, path, containing_folder);
    will_return(__wrap_abspath, 1);

    expect_string(__wrap_abspath, path, last_entry_file);
    will_return(__wrap_abspath, 1);
#endif

    expect_string(__wrap_IsDir, file, containing_folder);
    will_return(__wrap_IsDir, 1);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, last_entry_file);
    will_return(__wrap_FileSize, 1024);
#else
    expect_string(__wrap_FileSizeWin, file, last_entry_file);
    will_return(__wrap_FileSizeWin, 1024);
#endif

    expect_string(__wrap_rmdir_ex, name, containing_folder);
    will_return(__wrap_rmdir_ex, 0);

    seechanges_delete_compressed_file(file_name_abs);
}

void test_seechanges_get_diff_path(void **state) {
    char *path;
    path = (char*)malloc(sizeof(char) * 15);

#ifndef TEST_WINAGENT
    snprintf(path, 11, "%s", "/home/test");
#else
    snprintf(path, 13, "%s", "c:\\home\\test");
#endif

    char *result = seechanges_get_diff_path(path);

#ifndef TEST_WINAGENT
    assert_string_equal(result, "/var/ossec/queue/diff/local/home/test");
#else
    assert_string_equal(result, "queue/diff\\local\\c\\home\\test");
#endif

    if (path) {
        free(path);
    }

    if (result) {
        free(result);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        #ifndef TEST_WINAGENT
        // filter
        cmocka_unit_test_teardown(test_filter, teardown_free_string),

        // symlink_to_dir
        cmocka_unit_test(test_symlink_to_dir),
        cmocka_unit_test(test_symlink_to_dir_no_link),
        cmocka_unit_test(test_symlink_to_dir_no_dir),
        cmocka_unit_test(test_symlink_to_dir_lstat_error),
        cmocka_unit_test(test_symlink_to_dir_stat_error),
        #endif

        // gen_diff_alert
        cmocka_unit_test_teardown(test_gen_diff_alert, teardown_free_string),
        cmocka_unit_test_teardown(test_gen_diff_alert_big_size, teardown_free_string),
        cmocka_unit_test(test_gen_diff_alert_abspath_error),
        cmocka_unit_test(test_gen_diff_alert_fopen_error),
        cmocka_unit_test(test_gen_diff_alert_fread_error),
        cmocka_unit_test_teardown(test_gen_diff_alert_compress_error, teardown_free_string),
        cmocka_unit_test(test_gen_diff_alert_exceed_disk_quota_limit),

        // seechanges_dupfile
        cmocka_unit_test(test_seechanges_dupfile),
        cmocka_unit_test(test_seechanges_dupfile_fopen_error1),
        cmocka_unit_test(test_seechanges_dupfile_fopen_error2),
        cmocka_unit_test(test_seechanges_dupfile_fwrite_error),
        cmocka_unit_test(test_seechanges_createpath),
        cmocka_unit_test(test_seechanges_createpath_invalid_path),
        cmocka_unit_test(test_seechanges_createpath_mkdir),
        cmocka_unit_test(test_seechanges_createpath_mkdir_error),

        // seechanges_addfile
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
        cmocka_unit_test(test_seechanges_addfile_file_size_exceeded),
        cmocka_unit_test_setup_teardown(test_seechanges_addfile_disk_quota_exceeded, setup_disk_quota_exceeded, teardown_disk_quota_exceeded),
        cmocka_unit_test_setup_teardown(test_seechanges_addfile_disk_quota_exceeded_rmdir_ex_error1, setup_disk_quota_exceeded, teardown_disk_quota_exceeded),
        cmocka_unit_test_setup_teardown(test_seechanges_addfile_disk_quota_exceeded_rmdir_ex_error2, setup_disk_quota_exceeded, teardown_disk_quota_exceeded),
        cmocka_unit_test_setup_teardown(test_seechanges_addfile_disk_quota_exceeded_rmdir_ex_error3, setup_disk_quota_exceeded, teardown_disk_quota_exceeded),
        cmocka_unit_test_teardown(test_seechanges_addfile_fwrite_error, teardown_free_string),
        cmocka_unit_test(test_seechanges_addfile_run_diff_system_error),

        // seechanges_delete_compressed_file
        cmocka_unit_test(test_seechanges_delete_compressed_file_not_dir),
        cmocka_unit_test(test_seechanges_delete_compressed_file_rm_error),
        cmocka_unit_test(test_seechanges_delete_compressed_file_successful),

        // seechanges_get_diff_path
        cmocka_unit_test(test_seechanges_get_diff_path),

        /* Windows specific tests */
#ifdef TEST_WINAGENT
        /* filter */
        cmocka_unit_test_teardown(test_filter_success, teardown_string),
        cmocka_unit_test_teardown(test_filter_unchanged_string, teardown_string),
        cmocka_unit_test(test_filter_percentage_char),

        // adapt_win_fc_output
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_success, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_invalid_input, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_no_differences, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
#endif

        // is_nodiff
        cmocka_unit_test(test_is_nodiff_true),
        cmocka_unit_test(test_is_nodiff_false),
        cmocka_unit_test(test_is_nodiff_regex_true),
        cmocka_unit_test(test_is_nodiff_regex_false),
        cmocka_unit_test(test_is_nodiff_no_nodiff), // This test needs to be last, it messes with global variables
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
