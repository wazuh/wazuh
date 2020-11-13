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
#include <sys/stat.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"
#include "../wrappers/wazuh/os_crypto/md5_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/libc/stdlib_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"

#ifdef TEST_WINAGENT
#define CHECK_REGISTRY_ALL                                                                             \
    CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_MD5SUM | CHECK_SHA1SUM | \
    CHECK_SHA256SUM | CHECK_SEECHANGES | CHECK_TYPE

static registry default_reg_config[] = {
    { "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { "HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0", ARCH_64BIT, CHECK_REGISTRY_ALL, 0, 0, NULL, NULL, NULL },
    { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { "HKEY_LOCAL_MACHINE_Invalid_key\\Software\\Ignore", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { NULL, 0, 0, 320, 0, NULL, NULL, NULL }
};

static registry_ignore default_reg_ignore[] = { { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_32BIT},
                                            { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_64BIT},
                                            { NULL, 0} };

static registry default_reg_nodiff[] = { { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_32BIT},
                                            { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_64BIT},
                                            { NULL, 0} };

static char *default_reg_ignore_regex_patterns[] = { "IgnoreRegex", "batfile", NULL };
static registry_ignore_regex default_reg_ignore_regex[] = { { NULL, ARCH_32BIT }, { NULL, ARCH_64BIT }, { NULL, 0 } };

#endif

static char *syscheck_nodiff[] = {"/file/nodiff/", NULL};

static char *syscheck_nodiff_regex_patterns[] = {"regex", NULL};
static OSMatch *syscheck_nodiff_regex[] = { NULL, NULL };

static char *dir_config[] = {
    "/path/to/file",
    "C:\\path\\to\\file",
    NULL,
};

static int diff_size_limit_config[] = {
    50000,
    50000,
    50000,
    50000,
    50000,
};

typedef struct diff_data {
    int file_size;
    int size_limit;

    char *compress_folder;
    char *compress_file;

    char *tmp_folder;
    char *file_origin;
    char *uncompress_file;
    char *compress_tmp_file;
    char *diff_file;
} diff_data;

typedef struct gen_diff_struct {
    diff_data *diff;
    char **strarray;
} gen_diff_struct;


#ifdef TEST_WINAGENT
char *adapt_win_fc_output(char *command_output);
diff_data *initialize_registry_diff_data(const char *key_name, const char *value_name, const registry *configuration);
#endif

diff_data *initialize_file_diff_data(const char *filename);
char* filter(const char *string);
void free_diff_data(diff_data *diff);
int fim_diff_check_limits(diff_data *diff);
int fim_diff_delete_compress_folder(const char *folder);
int fim_diff_estimate_compression(float file_size);
int fim_diff_create_compress_file(const diff_data *diff);
void fim_diff_modify_compress_estimation(float compressed_size, float uncompressed_size);
int fim_diff_compare(const diff_data *diff);
void save_compress_file(const diff_data *diff);
int is_file_nodiff(const char *filename);
int is_registry_nodiff(const char *key_name, const char *value_name, int arch);
char *gen_diff_str(const diff_data *diff);
char *fim_diff_generate(const diff_data *diff);
int fim_diff_registry_tmp(const char *value_data, DWORD data_type, const diff_data *diff);

void expect_gen_diff_generate(gen_diff_struct *gen_diff_data_container) {
    gen_diff_data_container->diff->diff_file = "/path/to/diff/file";

    FILE *fp = (FILE*)2345;
    size_t n = 145;

    expect_wfopen(gen_diff_data_container->diff->diff_file, "rb", fp);

    expect_fread(gen_diff_data_container->strarray[0], n);

    expect_fclose(fp, 0);
}

void expect_initialize_file_diff_data(const char *path, int ret_abspath){
    expect_abspath(path, ret_abspath);
}

void expect_fim_diff_registry_tmp(const char *folder, const char *file, FILE *fp, const char *value_data) {
    expect_mkdir_ex(folder, 0);
    expect_fopen(file, "w", fp);
    if (fp){
        expect_fprintf(fp, value_data, 0);
        expect_fclose(fp, 0);
    } else {
        expect_any(__wrap__merror, formatted_msg);
    }

}

void expect_fim_diff_check_limits(const char *file_origin, const char *compress_folder, int ret) {
    int file_size;
    file_size = 512 * 1024;
    syscheck.file_size_enabled = 1;
    syscheck.disk_quota_enabled = 0;
    syscheck.disk_quota_limit = 1024;

    if (ret) {
        file_size = 2048 * 1024;
        if (ret == 2) {
            syscheck.file_size_enabled = 0;
            syscheck.disk_quota_enabled = 1;
        }
    }

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_origin);
    will_return(__wrap_FileSize, file_size);
#else
    expect_string(__wrap_FileSizeWin, file, file_origin);
    will_return(__wrap_FileSizeWin, file_size);
#endif
    if (ret == 1){
        expect_string(__wrap_IsDir, file, compress_folder);
        will_return(__wrap_IsDir, -1);
    }
}

void expect_fim_diff_create_compress_file(const char *file_origin, const char *compress_folder, int ret) {
    int file_size;
    file_size = 512 * 1024;
    syscheck.file_size_enabled = 1;
    syscheck.disk_quota_enabled = 0;
    syscheck.disk_quota_limit = 1024;

    if (ret) {
        file_size = 2048 * 1024;
        if (ret == 2) {
            syscheck.file_size_enabled = 0;
            syscheck.disk_quota_enabled = 1;
        }
    }

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, file_origin);
    will_return(__wrap_FileSize, file_size);
#else
    expect_string(__wrap_FileSizeWin, file, file_origin);
    will_return(__wrap_FileSizeWin, file_size);
#endif
    if (ret == 1){
        expect_string(__wrap_IsDir, file, compress_folder);
        will_return(__wrap_IsDir, -1);
    }
}

/* Setup/teardown */

static int setup_group(void **state) {

    // No diff
    for (int i = 0; syscheck_nodiff_regex_patterns[i]; i++) {
        syscheck_nodiff_regex[i] = calloc(1, sizeof(OSMatch));

        if (syscheck_nodiff_regex[i] == NULL) {
            return -1;
        }

        if (!OSMatch_Compile(syscheck_nodiff_regex_patterns[i], syscheck_nodiff_regex[i], 0)) {
            return -1;
        }
    }
    syscheck.nodiff = syscheck_nodiff;
    syscheck.nodiff_regex = syscheck_nodiff_regex;

    syscheck.dir = dir_config;
    syscheck.diff_size_limit = diff_size_limit_config;

#ifdef TEST_WINAGENT
    syscheck.registry = default_reg_config;

    // Ignore registries
    for (int i = 0; default_reg_ignore_regex_patterns[i]; i++) {
        default_reg_ignore_regex[i].regex = calloc(1, sizeof(OSMatch));

        if (default_reg_ignore_regex[i].regex == NULL) {
            return -1;
        }

        if (!OSMatch_Compile(default_reg_ignore_regex_patterns[i], default_reg_ignore_regex[i].regex, 0)) {
            return -1;
        }
    }
    syscheck.key_ignore = default_reg_ignore;
    syscheck.key_ignore_regex = default_reg_ignore_regex;

    // No diff registries
    syscheck.registry_nodiff = default_reg_nodiff;
    syscheck.registry_nodiff_regex = default_reg_ignore_regex;
#endif

    test_mode = 1;

    return 0;
}

static int teardown_group(void **state) {

    test_mode = 0;

    return 0;
}

static int teardown_free_string(void **state) {
    char * string = *state;
    free(string);
    return 0;
}

static int setup_diff_data(void **state) {
    diff_data *diff = NULL;
    os_calloc(1, sizeof(diff_data), diff);
    if (!diff)
        return 1;

    *state = diff;

    return 0;
}

static int teardown_free_diff_data(void **state) {
    diff_data *diff = *state;

    free_diff_data(diff);

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

static int setup_gen_diff_str(void **state) {
    gen_diff_struct *gen_diff_data_container = calloc(1, sizeof(gen_diff_struct));

    if(gen_diff_data_container == NULL)
        return -1;

    setup_adapt_win_fc_output((void **)&gen_diff_data_container->strarray);
    setup_diff_data((void **)&gen_diff_data_container->diff);

    char *input = strdup(
        "Comparing files start.txt and end.txt\r\n"
        "***** start.txt\r\n"
        "    1:  First line\r\n"
        "***** END.TXT\r\n"
        "    1:  First Line 123\r\n"
        "    2:  Last line\r\n"
        "*****\r\n\r\n\r\n");
    if(input == NULL) fail();
    gen_diff_data_container->strarray[0] = input;

    char *output = strdup(
        "< First line\n"
        "---\n"
        "> First Line 123\n"
        "> Last line\n");
    if(output == NULL) fail();
    gen_diff_data_container->strarray[1] = output;

    *state = gen_diff_data_container;

    return 0;
}

static int teardown_free_gen_diff_str(void **state) {
    gen_diff_struct *gen_diff_data_container = *state;

    teardown_adapt_win_fc_output((void **)&gen_diff_data_container->strarray);
    teardown_free_diff_data((void **)&gen_diff_data_container->diff);
    os_free(gen_diff_data_container);

    return 0;
}





/**********************************************************************************************************************\
 * Tests
\**********************************************************************************************************************/

void test_filter(void **state) {
    (void) state;

#ifdef TEST_WINAGENT
    const char * file_name = "a/unix/style/path/";
#else
    const char * file_name = "$file/$test";
#endif

    char * out = filter(file_name);
    *state = out;
    assert_non_null(out);

#ifdef TEST_WINAGENT
    assert_string_equal(out, "a\\unix\\style\\path\\");
#else
    assert_string_equal(out, "\\$file/\\$test");
#endif
}

// Windows test

#ifdef TEST_WINAGENT
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

void test_initialize_registry_diff_data(void **state) {
    diff_data *diff = NULL;
    registry *configuration = &syscheck.registry[0];

    diff = initialize_registry_diff_data("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", "valuename", configuration);

    assert_non_null(diff);
    assert_string_equal(diff->compress_folder, "queue/diff/registry/[x64] b9b175e8810d3475f15976dd3b5f9210f3af6604/3f17670fd80d6563a3d4283adfe14140907b75b0");
    assert_string_equal(diff->compress_file, "queue/diff/registry/[x64] b9b175e8810d3475f15976dd3b5f9210f3af6604/3f17670fd80d6563a3d4283adfe14140907b75b0/last-entry.gz");
    assert_string_equal(diff->tmp_folder, "queue/diff/tmp");
    assert_string_equal(diff->file_origin, "queue/diff/tmp/[x64] b9b175e8810d3475f15976dd3b5f9210f3af66043f17670fd80d6563a3d4283adfe14140907b75b0");
    assert_string_equal(diff->uncompress_file, "queue/diff/tmp/tmp-entry");
    assert_string_equal(diff->compress_tmp_file, "queue/diff/tmp/tmp-entry.gz");
    assert_string_equal(diff->diff_file, "queue/diff/tmp/diff-file");

    *state = diff;
}

void test_initialize_file_diff_data(void **state) {
    diff_data *diff = NULL;

    expect_abspath("C:\\path\\to\\file", 1);
    expect_abspath("queue/diff", 1);

    diff = initialize_file_diff_data("C:\\path\\to\\file");

    assert_non_null(diff);
    assert_string_equal(diff->compress_folder, "queue/diff/local/C\\path\\to\\file");
    assert_string_equal(diff->compress_file, "queue/diff/local/C\\path\\to\\file/last-entry.gz");
    assert_string_equal(diff->tmp_folder, "queue/diff/tmp");
    assert_string_equal(diff->file_origin, "C:\\path\\to\\file");
    assert_string_equal(diff->uncompress_file, "queue/diff/tmp/tmp-entry");
    assert_string_equal(diff->compress_tmp_file, "queue/diff/tmp/tmp-entry.gz");
    assert_string_equal(diff->diff_file, "queue/diff/tmp/diff-file");

    *state = diff;
}

#else // END TEST_WINAGENT

void test_initialize_file_diff_data(void **state) {
    diff_data *diff = NULL;

    expect_abspath("/path/to/file", 1);

    diff = initialize_file_diff_data("/path/to/file");

    assert_non_null(diff);
    assert_string_equal(diff->compress_folder, "/var/ossec/queue/diff/local/path/to/file");
    assert_string_equal(diff->compress_file, "/var/ossec/queue/diff/local/path/to/file/last-entry.gz");
    assert_string_equal(diff->tmp_folder, "/var/ossec/queue/diff/tmp");
    assert_string_equal(diff->file_origin, "/path/to/file");
    assert_string_equal(diff->uncompress_file, "/var/ossec/queue/diff/tmp/tmp-entry");
    assert_string_equal(diff->compress_tmp_file, "/var/ossec/queue/diff/tmp/tmp-entry.gz");
    assert_string_equal(diff->diff_file, "/var/ossec/queue/diff/tmp/diff-file");

    *state = diff;
}

#endif // END TEST_AGENT and TEST_SERVER

void test_initialize_file_diff_data_too_long_path(void **state) {
    diff_data *diff = NULL;
    char error_msg[PATH_MAX + 100];

    // Long path
#ifdef TEST_WINAGENT
    char path[PATH_MAX] = "c:\\";
    for (int i = 0; i < PATH_MAX - 26; i++) {
        strcat (path, "a");
    }
    expect_abspath(path, 1);
    expect_abspath("queue/diff", 1);
#else
    char path[PATH_MAX] = "/aa";
    for (int i = 0; i < PATH_MAX - 37; i++) {
        strcat (path, "a");
    }

    expect_abspath(path, 1);
#endif

    expect_any(__wrap__merror, formatted_msg);

    diff = initialize_file_diff_data(path);

    assert_null(diff);

    *state = diff;
}

void test_initialize_file_diff_data_abspath_fail(void **state) {
    diff_data *diff = NULL;

    expect_abspath("/path/to/file", 0);

    expect_string(__wrap__merror, formatted_msg, "(6711): Cannot get absolute path of '/path/to/file': Success (0)");

    diff = initialize_file_diff_data("/path/to/file");

    assert_null(diff);

    *state = diff;
}

void test_fim_diff_check_limits(void **state) {
    diff_data *diff = *state;

    diff->size_limit = 2048;
    diff->file_origin = "/path/to/file";
    syscheck.file_size_enabled = 1;

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, diff->file_origin);
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, diff->file_origin);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    int ret = fim_diff_check_limits(diff);

    assert_int_equal(ret, 0);

    *state = diff;
}

void test_fim_diff_check_limits_size_limit_reached(void **state) {
    diff_data *diff = *state;

    diff->size_limit = 1024;
    diff->file_origin = "/path/to/file";
    diff->compress_folder = "/compress_folder";
    syscheck.file_size_enabled = 1;

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, diff->file_origin);
    will_return(__wrap_FileSize, 2048 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, diff->file_origin);
    will_return(__wrap_FileSizeWin, 2048 * 1024);
#endif

    expect_string(__wrap_IsDir, file, diff->compress_folder);
    will_return(__wrap_IsDir, -1);

    int ret = fim_diff_check_limits(diff);

    assert_int_equal(ret, 1);

    *state = diff;
}

void test_fim_diff_check_limits_estimate_compression(void **state) {
    diff_data *diff = *state;

    diff->size_limit = 2048;
    diff->file_origin = "/path/to/file";
    syscheck.file_size_enabled = 0;
    syscheck.disk_quota_enabled = 1;

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, diff->file_origin);
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, diff->file_origin);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    int ret = fim_diff_check_limits(diff);

    assert_int_equal(ret, 2);

    *state = diff;
}

void test_fim_diff_delete_compress_folder(void **state) {
    char *folder = "/path/to/folder";

    syscheck.diff_folder_size = -1;

    expect_string(__wrap_IsDir, file, folder);
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, folder);
    will_return(__wrap_DirSize, 1024 * 1024);

    expect_string(__wrap_rmdir_ex, name, folder);
    will_return(__wrap_rmdir_ex, 0);

    expect_string(__wrap_remove_empty_folders, folder, folder);
    will_return(__wrap_remove_empty_folders, 0);

    int ret = fim_diff_delete_compress_folder(folder);

    assert_int_equal(ret, 0);
}

void test_fim_diff_delete_compress_folder_no_dir(void **state) {
    char *folder = "/path/to/folder";

    syscheck.diff_folder_size = -1;

    expect_string(__wrap_IsDir, file, folder);
    will_return(__wrap_IsDir, -1);

    int ret = fim_diff_delete_compress_folder(folder);

    assert_int_equal(ret, -2);
}

void test_fim_diff_delete_compress_folder_rmdir_ex_fail(void **state) {
    char *folder = "/path/to/folder";

    syscheck.diff_folder_size = -1;

    expect_string(__wrap_IsDir, file, folder);
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, folder);
    will_return(__wrap_DirSize, 1024 * 1024);

    expect_string(__wrap_rmdir_ex, name, folder);
    will_return(__wrap_rmdir_ex, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "(1143): Unable to delete folder '/path/to/folder' due to [(41)-(Directory not empty)].");

    int ret = fim_diff_delete_compress_folder(folder);

    assert_int_equal(ret, -1);
}

void test_fim_diff_delete_compress_folder_remove_folder_fail(void **state) {
    char *folder = "/path/to/folder";

    syscheck.diff_folder_size = -1;

    expect_string(__wrap_IsDir, file, folder);
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, folder);
    will_return(__wrap_DirSize, 1024 * 1024);

    expect_string(__wrap_rmdir_ex, name, folder);
    will_return(__wrap_rmdir_ex, 0);

    expect_string(__wrap_remove_empty_folders, folder, folder);
    will_return(__wrap_remove_empty_folders, -1);

    int ret = fim_diff_delete_compress_folder(folder);

    assert_int_equal(ret, -1);
}

void test_fim_diff_estimate_compression_file_not_fit(void **state) {
    syscheck.diff_folder_size = 10240;
    syscheck.disk_quota_limit = 10240;

    int ret = fim_diff_estimate_compression(1024);

    assert_int_equal(ret, 0);
}

void test_fim_diff_estimate_compression_ok(void **state) {
    syscheck.diff_folder_size = 5120;
    syscheck.disk_quota_limit = 10240;

    int ret = fim_diff_estimate_compression(1024);

    assert_int_equal(ret, 1);
}

void test_fim_diff_create_compress_file_fail_compress(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/file/origin";
    diff->compress_tmp_file = "/path/compress/tmp/file";

    expect_string(__wrap_w_compress_gzfile, filesrc, diff->file_origin);
    expect_string(__wrap_w_compress_gzfile, filedst, diff->compress_tmp_file);
    will_return(__wrap_w_compress_gzfile, -1);

    expect_string(__wrap__mwarn, formatted_msg, "(6914): Cannot create a snapshot of file '/path/file/origin'");

    int ret = fim_diff_create_compress_file(diff);

    assert_int_equal(ret, -1);

    *state = diff;
}

void test_fim_diff_create_compress_file_ok(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/file/origin";
    diff->compress_tmp_file = "/path/compress/tmp/file";
    syscheck.disk_quota_enabled = 1;
    syscheck.diff_folder_size = 5120;
    syscheck.disk_quota_limit = 10240;

    expect_string(__wrap_w_compress_gzfile, filesrc, diff->file_origin);
    expect_string(__wrap_w_compress_gzfile, filedst, diff->compress_tmp_file);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, diff->compress_tmp_file);
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, diff->compress_tmp_file);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    int ret = fim_diff_create_compress_file(diff);

    assert_int_equal(ret, 0);

    *state = diff;
}

void test_fim_diff_create_compress_file_quota_reached(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/file/origin";
    diff->compress_tmp_file = "/path/compress/tmp/file";
    syscheck.disk_quota_enabled = 1;
    syscheck.diff_folder_size = 10240;
    syscheck.disk_quota_limit = 10240;
    syscheck.disk_quota_full_msg = true;

    expect_string(__wrap_w_compress_gzfile, filesrc, diff->file_origin);
    expect_string(__wrap_w_compress_gzfile, filedst, diff->compress_tmp_file);
    will_return(__wrap_w_compress_gzfile, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, diff->compress_tmp_file);
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, diff->compress_tmp_file);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6350): The calculate of the file size '/path/file/origin' exceeds the disk_quota. Operation discarded.");

    int ret = fim_diff_create_compress_file(diff);

    assert_int_equal(ret, -1);

    *state = diff;
}

void test_fim_diff_modify_compress_estimation_small_compresion_rate(void **state) {
    syscheck.comp_estimation_perc = 0.9;

    fim_diff_modify_compress_estimation(10240, 10240);

    // Rate unmodified
    assert_float_equal(syscheck.comp_estimation_perc, 0.9, 0.001);
}

void test_fim_diff_modify_compress_estimation_MIN_COMP_ESTIM(void **state) {
    syscheck.comp_estimation_perc = 0.6;

    fim_diff_modify_compress_estimation(9216, 10240);

    // Rate set at minimun
    assert_float_equal(syscheck.comp_estimation_perc, 0.4, 0.001);
}

void test_fim_diff_modify_compress_estimation_ok(void **state) {
    syscheck.comp_estimation_perc = 0.9;

    fim_diff_modify_compress_estimation(5120, 10240);

    // Rate modified
    assert_float_equal(syscheck.comp_estimation_perc, 0.7, 0.001);
}

void test_fim_diff_compare_fail_uncompress_MD5(void **state) {
    diff_data *diff = *state;
    diff->uncompress_file = "/path/to/uncompress/file";
    os_md5 md5sum_old = "3c183a30cffcda1408daf1c61d47b274";

    expect_OS_MD5_File_call(diff->uncompress_file, md5sum_old, OS_BINARY, -1);

    int ret = fim_diff_compare(diff);

    assert_int_equal(ret, -1);

    *state = diff;
}

void test_fim_diff_compare_fail_origin_MD5(void **state) {
    diff_data *diff = *state;
    diff->uncompress_file = "/path/to/uncompress/file";
    diff->file_origin = "/path/to/uncompress/file";
    os_md5 md5sum_old = "3c183a30cffcda1408daf1c61d47b274";
    os_md5 md5sum_new = "3c183a30cffcda1408daf1c61d47b274";

    expect_OS_MD5_File_call(diff->uncompress_file, md5sum_old, OS_BINARY, 0);
    expect_OS_MD5_File_call(diff->file_origin, md5sum_new, OS_BINARY, 0);

    int ret = fim_diff_compare(diff);

    assert_int_equal(ret, -1);
}

void test_fim_diff_compare_fail_not_match(void **state) {
    diff_data *diff = *state;
    diff->uncompress_file = "/path/to/uncompress/file";
    diff->file_origin = "/path/to/uncompress/file";
    os_md5 md5sum_old = "3c183a30cffcda1408daf1c61d47b274";
    os_md5 md5sum_new = "abc44bfb4ab4cf4af49a4fa9b04fa44a";

    expect_OS_MD5_File_call(diff->uncompress_file, md5sum_old, OS_BINARY, 0);
    expect_OS_MD5_File_call(diff->file_origin, md5sum_new, OS_BINARY, 0);

    int ret = fim_diff_compare(diff);

    assert_int_equal(ret, 0);

    *state = diff;
}

void test_fim_diff_compare_fail_match(void **state) {
    diff_data *diff = *state;
    diff->uncompress_file = "/path/to/uncompress/file";
    diff->file_origin = "/path/to/uncompress/file";
    os_md5 md5sum_old = "3c183a30cffcda1408daf1c61d47b274";
    os_md5 md5sum_new = "3c183a30cffcda1408daf1c61d47b274";

    expect_OS_MD5_File_call(diff->uncompress_file, md5sum_old, OS_BINARY, 0);
    expect_OS_MD5_File_call(diff->file_origin, md5sum_new, OS_BINARY, 0);

    int ret = fim_diff_compare(diff);

    assert_int_equal(ret, -1);

    *state = diff;
}

void test_save_compress_file_ok(void **state) {
    diff_data *diff = *state;
    diff->compress_tmp_file = "/path/to/compress/tmp/file";
    diff->compress_file = "/path/to/compress/file";
    syscheck.disk_quota_enabled = 1;
    syscheck.diff_folder_size = 0;

    expect_rename_ex(diff->compress_tmp_file, diff->compress_file, 0);

#ifndef TEST_WINAGENT
    expect_string(__wrap_FileSize, path, diff->compress_file);
    will_return(__wrap_FileSize, 1024 * 1024);
#else
    expect_string(__wrap_FileSizeWin, file, diff->compress_file);
    will_return(__wrap_FileSizeWin, 1024 * 1024);
#endif

    save_compress_file(diff);
    assert_int_equal(syscheck.diff_folder_size, 1024);

    *state = diff;
}

void test_save_compress_file_rename_fail(void **state) {
    diff_data *diff = *state;
    diff->compress_tmp_file = "/path/to/compress/tmp/file";
    diff->compress_file = "/path/to/compress/file";
    syscheck.disk_quota_enabled = 1;
    syscheck.diff_folder_size = 0;

    expect_rename_ex(diff->compress_tmp_file, diff->compress_file, -1);

    expect_string(__wrap__merror, formatted_msg, "(1124): Could not rename file '/path/to/compress/tmp/file' to '/path/to/compress/file' due to [(0)-(Success)].");

    save_compress_file(diff);
    assert_int_equal(syscheck.diff_folder_size, 0);

    *state = diff;
}

void test_is_file_nodiff_normal_check(void **state) {

    int ret = is_file_nodiff("/file/nodiff/");
    assert_int_equal(ret, 1);
}

void test_is_file_nodiff_regex_check(void **state) {

    int ret = is_file_nodiff("/file/nodiff/regex/");
    assert_int_equal(ret, 1);
}

void test_is_file_nodiff_not_match(void **state) {

    int ret = is_file_nodiff("/file/nodiff/no_config");
    assert_int_equal(ret, 0);
}

#ifdef TEST_WINAGENT
void test_is_registry_nodiff_normal_check(void **state) {

    int ret = is_registry_nodiff("HKEY_LOCAL_MACHINE\\Software", "Ignore", 1);
    assert_int_equal(ret, 1);
}

void test_is_registry_nodiff_regex_check(void **state) {

    int ret = is_registry_nodiff("HKEY_LOCAL_MACHINE\\Software", "batfile", 1);
    assert_int_equal(ret, 1);
}

void test_is_registry_nodiff_not_match(void **state) {

    int ret = is_registry_nodiff("HKEY_LOCAL_MACHINE\\Software", "RecursionLevel0", 1);
    assert_int_equal(ret, 0);
}
#endif

// gen_diff_str function tests

void test_gen_diff_str_wfropen_fail(void **state) {
    diff_data *diff = *state;
    diff->diff_file = "/path/to/diff/file";

    expect_wfopen(diff->diff_file, "rb", NULL);

    expect_string(__wrap__merror, formatted_msg, "(6665): Unable to generate diff alert (fopen)'/path/to/diff/file'.");

    char *diff_str = gen_diff_str(diff);
    assert_ptr_equal(diff_str, NULL);

    *state = diff;
}

void test_gen_diff_str_fread_fail(void **state) {
    diff_data *diff = *state;
    diff->diff_file = "/path/to/diff/file";
    FILE *fp = (FILE*)2345;
    char *diff_contain = "diff_contain";

    expect_wfopen(diff->diff_file, "rb", fp);

    expect_fread(diff_contain, 0);

    expect_fclose(fp, 0);

    expect_string(__wrap__merror, formatted_msg, "(6666): Unable to generate diff alert (fread).");

    char *diff_str = gen_diff_str(diff);
    assert_ptr_equal(diff_str, NULL);

    *state = diff;
}

void test_gen_diff_str_ok(void **state) {
    gen_diff_struct *gen_diff_data_container = *state;
    gen_diff_data_container->diff->diff_file = "/path/to/diff/file";

    FILE *fp = (FILE*)2345;
    size_t n = 145;

    expect_wfopen(gen_diff_data_container->diff->diff_file, "rb", fp);

    expect_fread(gen_diff_data_container->strarray[0], n);

    expect_fclose(fp, 0);

    char *diff_str = gen_diff_str(gen_diff_data_container->diff);
    assert_string_equal(diff_str, gen_diff_data_container->strarray[1]);

    *state = gen_diff_data_container;
}

#ifdef TEST_WINAGENT
void test_fim_diff_generate_filters_fail(void **state) {
    diff_data *diff = *state;
    diff->uncompress_file = "\%wrong path";
    diff->file_origin = "\%wrong path";
    diff->diff_file = "\%wrong path";

    expect_string(__wrap__mdebug1, formatted_msg, "(6200): Diff execution skipped for containing insecure characters.");

    char *diff_str = fim_diff_generate(diff);
    assert_ptr_equal(diff_str, NULL);

    *state = diff;
}

void test_fim_diff_generate_status_equal(void **state) {
    diff_data *diff = *state;
    diff->uncompress_file = "/path/to/uncompress/file";
    diff->file_origin = "/path/to/file/origin";
    diff->diff_file = "/path/to/diff/file";

    expect_system("fc /n \"\\path\\to\\uncompress\\file\" \"\\path\\to\\file\\origin\" > \"\\path\\to\\diff\\file\" 2> nul", 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6352): Command diff/fc output 0, files are the same");

    char *diff_str = fim_diff_generate(diff);
    assert_ptr_equal(diff_str, NULL);

    *state = diff;
}
#endif

void test_fim_diff_generate_status_error(void **state) {
    diff_data *diff = *state;
    diff->uncompress_file = "/path/to/uncompress/file";
    diff->file_origin = "/path/to/file/origin";
    diff->diff_file = "/path/to/diff/file";

#ifndef WIN32
    expect_system("diff \"%s\" \"%s\" > \"%s\" 2> /dev/null", -1);
#else
    expect_system("fc /n \"\\path\\to\\uncompress\\file\" \"\\path\\to\\file\\origin\" > \"\\path\\to\\diff\\file\" 2> nul", -1);
#endif

    expect_string(__wrap__merror, formatted_msg, "(6714): Command fc output an error");

    char *diff_str = fim_diff_generate(diff);
    assert_ptr_equal(diff_str, NULL);

    *state = diff;
}

void test_fim_diff_generate_status_ok(void **state) {
    gen_diff_struct *gen_diff_data_container = *state;
    gen_diff_data_container->diff->uncompress_file = "/path/to/uncompress/file";
    gen_diff_data_container->diff->file_origin = "/path/to/file/origin";
    gen_diff_data_container->diff->diff_file = "/path/to/diff/file";

#ifndef WIN32
    expect_system("diff \"%s\" \"%s\" > \"%s\" 2> /dev/null", 256);
#else
    expect_system("fc /n \"\\path\\to\\uncompress\\file\" \"\\path\\to\\file\\origin\" > \"\\path\\to\\diff\\file\" 2> nul", 1);
#endif

    expect_gen_diff_generate(gen_diff_data_container);

    char *diff_str = fim_diff_generate(gen_diff_data_container->diff);
    assert_string_equal(diff_str, gen_diff_data_container->strarray[1]);

    *state = gen_diff_data_container;
}

#ifdef TEST_WINAGENT
void test_fim_diff_registry_tmp_fopen_fail(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/to/file/origin";
    diff->tmp_folder = "/path/to/tmp/folder";
    FILE *fp = NULL;
    const char *value_data = "value_data";
    DWORD data_type = 0;

    expect_mkdir_ex(diff->tmp_folder, 0);

    expect_fopen(diff->file_origin, "w", fp);

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/path/to/file/origin' due to [(2)-(No such file or directory)].");

    int ret = fim_diff_registry_tmp(value_data, data_type, diff);
    assert_int_equal(ret, -1);

    *state = diff;
}

void test_fim_diff_registry_tmp_REG_SZ(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/to/file/origin";
    diff->tmp_folder = "/path/to/tmp/folder";
    FILE *fp = (FILE*)2345;
    const char *value_data = "value_data";
    DWORD data_type = REG_EXPAND_SZ;

    expect_mkdir_ex(diff->tmp_folder, 0);

    expect_fopen(diff->file_origin, "w", fp);

    expect_fprintf(fp, value_data, 0);

    expect_fclose(fp, 0);

    int ret = fim_diff_registry_tmp(value_data, data_type, diff);
    assert_int_equal(ret, 0);

    *state = diff;
}

void test_fim_diff_registry_tmp_REG_MULTI_SZ(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/to/file/origin";
    diff->tmp_folder = "/path/to/tmp/folder";
    FILE *fp = (FILE*)2345;
    const char *value_data = "value_data\0value_data2\0";
    const char *value_data_formatted = "value_data\n";
    const char *value_data_formatted2 = "value_data2\n";
    DWORD data_type = REG_MULTI_SZ;

    expect_mkdir_ex(diff->tmp_folder, 0);

    expect_fopen(diff->file_origin, "w", fp);

    expect_fprintf(fp, value_data_formatted, 0);
    expect_fprintf(fp, value_data_formatted2, 0);

    expect_fclose(fp, 0);

    int ret = fim_diff_registry_tmp((char *)value_data, data_type, diff);
    assert_int_equal(ret, 0);

    *state = diff;
}

void test_fim_diff_registry_tmp_REG_DWORD(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/to/file/origin";
    diff->tmp_folder = "/path/to/tmp/folder";
    FILE *fp = (FILE*)2345;
    unsigned int *value_data = (unsigned int *)12345;
    DWORD data_type = REG_DWORD;

    expect_mkdir_ex(diff->tmp_folder, 0);

    expect_fopen(diff->file_origin, "w", fp);

    expect_fprintf(fp, "3039", 0);

    expect_fclose(fp, 0);

    int ret = fim_diff_registry_tmp((char *)&value_data, data_type, diff);
    assert_int_equal(ret, 0);

    *state = diff;
}

void test_fim_diff_registry_tmp_REG_DWORD_BIG_ENDIAN(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/to/file/origin";
    diff->tmp_folder = "/path/to/tmp/folder";
    FILE *fp = (FILE*)2345;
    unsigned int *value_data = (unsigned int *)12345;
    DWORD data_type = REG_DWORD_BIG_ENDIAN;

    expect_mkdir_ex(diff->tmp_folder, 0);

    expect_fopen(diff->file_origin, "w", fp);

    expect_fprintf(fp, "39300000", 0);

    expect_fclose(fp, 0);

    int ret = fim_diff_registry_tmp((char *)&value_data, data_type, diff);
    assert_int_equal(ret, 0);

    *state = diff;
}

void test_fim_diff_registry_tmp_REG_QWORD(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/to/file/origin";
    diff->tmp_folder = "/path/to/tmp/folder";
    FILE *fp = (FILE*)2345;
    unsigned long long *value_data = (unsigned long long *)12345;
    DWORD data_type = REG_QWORD;

    expect_mkdir_ex(diff->tmp_folder, 0);

    expect_fopen(diff->file_origin, "w", fp);

    expect_fprintf(fp, "2311f400003039", 0);

    expect_fclose(fp, 0);

    int ret = fim_diff_registry_tmp((char *)&value_data, data_type, diff);
    assert_int_equal(ret, 0);

    *state = diff;
}

void test_fim_diff_registry_tmp_default_type(void **state) {
    diff_data *diff = *state;
    diff->file_origin = "/path/to/file/origin";
    diff->tmp_folder = "/path/to/tmp/folder";
    FILE *fp = (FILE*)2345;
    const char *value_data = "value_data";
    DWORD data_type = -1;

    expect_mkdir_ex(diff->tmp_folder, 0);

    expect_fopen(diff->file_origin, "w", fp);

    expect_string(__wrap__mwarn, formatted_msg, "(6935): Wrong registry value type processed for report_changes.");

    expect_fclose(fp, 0);

    int ret = fim_diff_registry_tmp((char *)&value_data, data_type, diff);
    assert_int_equal(ret, -1);

    *state = diff;
}

void test_fim_registry_value_diff_wrong_data_type(void **state) {
    const char *key_name = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    const char *value_name = "valuename";
    const char *value_data = "value_data";
    DWORD data_type = REG_NONE;
    registry *configuration = &syscheck.registry[0];

    char *diff_str = fim_registry_value_diff(key_name, value_name, value_data, data_type, configuration);

    assert_ptr_equal(diff_str, NULL);
}

void test_fim_registry_value_diff_wrong_registry_tmp(void **state) {
    const char *key_name = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    const char *value_name = "valuename";
    const char *value_data = "value_data";
    DWORD data_type = REG_EXPAND_SZ;
    registry *configuration = &syscheck.registry[0];

    expect_fim_diff_registry_tmp("queue/diff/tmp", "queue/diff/tmp/[x64] b9b175e8810d3475f15976dd3b5f9210f3af66043f17670fd80d6563a3d4283adfe14140907b75b0", NULL, value_data);

    expect_string(__wrap_rmdir_ex, name, "queue/diff/tmp");
    will_return(__wrap_rmdir_ex, 0);

    char *diff_str = fim_registry_value_diff(key_name, value_name, value_data, data_type, configuration);

    assert_ptr_equal(diff_str, NULL);
}

void test_fim_registry_value_diff_wrong_too_big_file(void **state) {
    const char *key_name = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    const char *value_name = "valuename";
    const char *value_data = "value_data";
    DWORD data_type = REG_EXPAND_SZ;
    registry *configuration = &syscheck.registry[0];
    configuration->diff_size_limit = 1024;

    expect_fim_diff_registry_tmp("queue/diff/tmp", "queue/diff/tmp/[x64] b9b175e8810d3475f15976dd3b5f9210f3af66043f17670fd80d6563a3d4283adfe14140907b75b0", (FILE *)1234, value_data);

    expect_fim_diff_check_limits("queue/diff/tmp/[x64] b9b175e8810d3475f15976dd3b5f9210f3af66043f17670fd80d6563a3d4283adfe14140907b75b0", "queue/diff/registry/[x64] b9b175e8810d3475f15976dd3b5f9210f3af6604/3f17670fd80d6563a3d4283adfe14140907b75b0", 1);

    expect_string(__wrap__mdebug2, formatted_msg, "(6349): File 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\valuename' is too big for configured maximum size to perform diff operation.");

    expect_string(__wrap_rmdir_ex, name, "queue/diff/tmp");
    will_return(__wrap_rmdir_ex, 0);

    char *diff_str = fim_registry_value_diff(key_name, value_name, value_data, data_type, configuration);

    assert_ptr_equal(diff_str, NULL);
}

void test_fim_registry_value_diff_wrong_quota_reached(void **state) {
    const char *key_name = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    const char *value_name = "valuename";
    const char *value_data = "value_data";
    DWORD data_type = REG_EXPAND_SZ;
    registry *configuration = &syscheck.registry[0];
    configuration->diff_size_limit = 1024;
    syscheck.comp_estimation_perc = 0.4;

    expect_fim_diff_registry_tmp("queue/diff/tmp", "queue/diff/tmp/[x64] b9b175e8810d3475f15976dd3b5f9210f3af66043f17670fd80d6563a3d4283adfe14140907b75b0", (FILE *)1234, value_data);

    expect_fim_diff_check_limits("queue/diff/tmp/[x64] b9b175e8810d3475f15976dd3b5f9210f3af66043f17670fd80d6563a3d4283adfe14140907b75b0", "queue/diff/registry/[x64] b9b175e8810d3475f15976dd3b5f9210f3af6604/3f17670fd80d6563a3d4283adfe14140907b75b0", 2);

    expect_string(__wrap__mdebug2, formatted_msg, "(6350): The estimation of the file size 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\valuename' exceeds the disk_quota. Operation discarded.");

    expect_string(__wrap_rmdir_ex, name, "queue/diff/tmp");
    will_return(__wrap_rmdir_ex, 0);

    char *diff_str = fim_registry_value_diff(key_name, value_name, value_data, data_type, configuration);

    assert_ptr_equal(diff_str, NULL);
}

void test_fim_registry_value_diff_wrong_quota_reached(void **state) {
    const char *key_name = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    const char *value_name = "valuename";
    const char *value_data = "value_data";
    DWORD data_type = REG_EXPAND_SZ;
    registry *configuration = &syscheck.registry[0];
    configuration->diff_size_limit = 1024;
    syscheck.comp_estimation_perc = 0.4;

    expect_fim_diff_registry_tmp("queue/diff/tmp", "queue/diff/tmp/[x64] b9b175e8810d3475f15976dd3b5f9210f3af66043f17670fd80d6563a3d4283adfe14140907b75b0", (FILE *)1234, value_data);

    expect_fim_diff_check_limits("queue/diff/tmp/[x64] b9b175e8810d3475f15976dd3b5f9210f3af66043f17670fd80d6563a3d4283adfe14140907b75b0", "queue/diff/registry/[x64] b9b175e8810d3475f15976dd3b5f9210f3af6604/3f17670fd80d6563a3d4283adfe14140907b75b0", 0);

    expect_w_uncompress_gzfile("aaa", "bbb", 1);

    char *diff_str = fim_registry_value_diff(key_name, value_name, value_data, data_type, configuration);

    assert_ptr_equal(diff_str, NULL);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {

#ifdef TEST_WINAGENT
        // filter
        cmocka_unit_test_teardown(test_filter_unchanged_string, teardown_free_string),
        cmocka_unit_test(test_filter_percentage_char),

        // adapt_win_fc_output
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_success, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_invalid_input, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_no_differences, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),

        // initialize_registry_diff_data
        cmocka_unit_test_teardown(test_initialize_registry_diff_data, teardown_free_diff_data),
#endif
        // initialize_file_diff_data
        cmocka_unit_test_teardown(test_initialize_file_diff_data, teardown_free_diff_data),
        cmocka_unit_test_teardown(test_initialize_file_diff_data_too_long_path, teardown_free_diff_data),
        cmocka_unit_test_teardown(test_initialize_file_diff_data_abspath_fail, teardown_free_diff_data),

        // filter
        cmocka_unit_test_teardown(test_filter, teardown_free_string),

        // fim_diff_check_limits
        cmocka_unit_test_setup_teardown(test_fim_diff_check_limits, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_check_limits_size_limit_reached, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_check_limits_estimate_compression, setup_diff_data, teardown_free_diff_data),

        // fim_diff_delete_compress_folder
        cmocka_unit_test_teardown(test_fim_diff_delete_compress_folder, teardown_disk_quota_exceeded),
        cmocka_unit_test(test_fim_diff_delete_compress_folder_no_dir),
        cmocka_unit_test(test_fim_diff_delete_compress_folder_rmdir_ex_fail),
        cmocka_unit_test_setup_teardown(test_fim_diff_delete_compress_folder_remove_folder_fail, setup_diff_data, teardown_free_diff_data),

        // fim_diff_estimate_compression
        cmocka_unit_test(test_fim_diff_estimate_compression_file_not_fit),
        cmocka_unit_test(test_fim_diff_estimate_compression_ok),

        // fim_diff_create_compress_file
        cmocka_unit_test_setup_teardown(test_fim_diff_create_compress_file_fail_compress, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_create_compress_file_ok, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_create_compress_file_quota_reached, setup_diff_data, teardown_free_diff_data),

        // fim_diff_modify_compress_estimation
        cmocka_unit_test(test_fim_diff_modify_compress_estimation_small_compresion_rate),
        cmocka_unit_test(test_fim_diff_modify_compress_estimation_MIN_COMP_ESTIM),
        cmocka_unit_test(test_fim_diff_modify_compress_estimation_ok),

        // fim_diff_compare
        cmocka_unit_test_setup_teardown(test_fim_diff_compare_fail_uncompress_MD5, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_compare_fail_origin_MD5, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_compare_fail_not_match, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_compare_fail_match, setup_diff_data, teardown_free_diff_data),

        // save_compress_file
        cmocka_unit_test_setup_teardown(test_save_compress_file_ok, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_save_compress_file_rename_fail, setup_diff_data, teardown_free_diff_data),

        // is_file_nodiff
        cmocka_unit_test(test_is_file_nodiff_normal_check),
        cmocka_unit_test(test_is_file_nodiff_regex_check),
        cmocka_unit_test(test_is_file_nodiff_not_match),

        // is_registry_nodiff
        cmocka_unit_test(test_is_registry_nodiff_normal_check),
        cmocka_unit_test(test_is_registry_nodiff_regex_check),
        cmocka_unit_test(test_is_registry_nodiff_not_match),

        // gen_diff_str
        cmocka_unit_test_setup_teardown(test_gen_diff_str_wfropen_fail, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_gen_diff_str_fread_fail, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_gen_diff_str_ok, setup_gen_diff_str, teardown_free_gen_diff_str),

        // fim_diff_generate
        cmocka_unit_test_setup_teardown(test_fim_diff_generate_status_error, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_generate_status_ok, setup_gen_diff_str, teardown_free_gen_diff_str),
#ifdef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_fim_diff_generate_filters_fail, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_generate_status_equal, setup_diff_data, teardown_free_diff_data),

        // fim_diff_registry_tmp
        cmocka_unit_test_setup_teardown(test_fim_diff_registry_tmp_fopen_fail, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_registry_tmp_REG_SZ, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_registry_tmp_REG_MULTI_SZ, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_registry_tmp_REG_DWORD, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_registry_tmp_REG_DWORD_BIG_ENDIAN, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_registry_tmp_REG_QWORD, setup_diff_data, teardown_free_diff_data),
        cmocka_unit_test_setup_teardown(test_fim_diff_registry_tmp_default_type, setup_diff_data, teardown_free_diff_data),

        // fim_registry_value_diff
        cmocka_unit_test(test_fim_registry_value_diff_wrong_data_type),
        cmocka_unit_test(test_fim_registry_value_diff_wrong_registry_tmp),
        cmocka_unit_test(test_fim_registry_value_diff_wrong_too_big_file),
        cmocka_unit_test(test_fim_registry_value_diff_wrong_quota_reached),
        cmocka_unit_test(test_fim_registry_value_diff_wrong_quota_reached),


#endif
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
