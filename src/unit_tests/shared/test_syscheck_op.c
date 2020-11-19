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

#include "../headers/syscheck_op.h"
#include "../analysisd/eventinfo.h"

#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/posix/grp_wrappers.h"
#include "../wrappers/posix/pwd_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/string_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

#ifdef TEST_WINAGENT
#include "../wrappers/wazuh/syscheckd/syscom_wrappers.h"
#else
#include "../wrappers/posix/unistd_wrappers.h"
#endif

/* Auxiliar structs */

typedef struct __sk_decode_data_s {
    sk_sum_t sum;
    char *c_sum;
    char *w_sum;
}sk_decode_data_t;

typedef struct __sk_fill_event_s {
    sk_sum_t *sum;
    Eventinfo *lf;
    char *f_name;
}sk_fill_event_t;

typedef struct __sk_build_sum_s {
    sk_sum_t sum;
    char *output;
}sk_build_sum_t;

typedef struct __unescape_syscheck_field_data_s {
    char *input;
    char *output;
}unescape_syscheck_field_data_t;

/* setup/teardown */
static int teardown_string(void **state) {
    free(*state);
    return 0;
}

#ifdef TEST_WINAGENT
static int setup_string_array(void **state) {
    char **array = calloc(10, sizeof(char*));

    if(array == NULL)
        return -1;

    *state = array;

    return 0;
}

static int teardown_string_array(void **state) {
    char **array = *state;

    free_strarray(array);

    return 0;
}
#endif

#if defined(TEST_SERVER)
static int setup_sk_decode(void **state) {
    sk_decode_data_t *data = calloc(1, sizeof(sk_decode_data_t));

    if(!data) {
        return -1;
    }

    *state = data;
    return 0;
}

static int teardown_sk_decode(void **state) {
    sk_decode_data_t *data = *state;

    if(data) {
        sk_sum_clean(&data->sum);

        if(data->c_sum)
            free(data->c_sum);

        if(data->w_sum)
            free(data->w_sum);

        free(data);
    }
    return 0;
}


static int setup_sk_fill_event(void **state) {
    sk_fill_event_t* data = calloc(1, sizeof(sk_fill_event_t));

    if(!data) {
        return -1;
    }

    if(data->lf = calloc(1, sizeof(Eventinfo)), data->lf == NULL) {
        return -1;
    }

    if(data->lf->fields = calloc(FIM_NFIELDS, sizeof(DynamicField)), !data->lf->fields)
        return -1;

    data->lf->nfields = FIM_NFIELDS;

    if(data->sum = calloc(1, sizeof(sk_sum_t)), data->sum == NULL) {
        return -1;
    }

    *state = data;
    return 0;
}

static int teardown_sk_fill_event(void **state) {
    sk_fill_event_t* data = *state;

    if(data){
        free(data->f_name);

        free(data->sum);
        // sk_sum_clean(&data->sum);
        Free_Eventinfo(data->lf);
        free(data);
    }
    return 0;
}

static int setup_sk_build_sum(void **state) {
    sk_build_sum_t* data = calloc(1, sizeof(sk_build_sum_t));

    if(!data) {
        return -1;
    }

    if(data->output = calloc(OS_MAXSTR, sizeof(char)), !data->output)
        return -1;

    *state = data;
    return 0;
}

static int teardown_sk_build_sum(void **state) {
    sk_build_sum_t* data = *state;

    if(data){
        free(data->output);
        // sk_sum_clean(&data->sum);

        free(data);
    }
    return 0;
}
#endif
#ifndef TEST_WINAGENT
static int setup_unescape_syscheck_field(void **state) {
    *state = calloc(1, sizeof(unescape_syscheck_field_data_t));

    if(!*state) {
        return -1;
    }
    return 0;
}

static int teardown_unescape_syscheck_field(void **state) {
    unescape_syscheck_field_data_t *data = *state;

    if(data) {
        free(data->input);
        free(data->output);
        free(data);
    }
    return 0;
}
#endif

static int teardown_cjson(void **state) {
    cJSON *array = *state;

    cJSON_Delete(array);

    return 0;
}

/* Tests */

/* delete_target_file tests */
#ifndef TEST_WINAGENT
static void test_delete_target_file_success(void **state) {
    int ret = -1;
    char *path = "/test_file.tmp";

    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/local/test_file.tmp");
    will_return(__wrap_rmdir_ex, 0);

    ret = delete_target_file(path);

    assert_int_equal(ret, 0);
}

static void test_delete_target_file_rmdir_ex_error(void **state) {
    int ret = -1;
    char *path = "/test_file.tmp";

    expect_string(__wrap_rmdir_ex, name, "/var/ossec/queue/diff/local/test_file.tmp");
    will_return(__wrap_rmdir_ex, -1);

    ret = delete_target_file(path);

    assert_int_equal(ret, 1);
}
#else
static void test_delete_target_file_success(void **state) {
    int ret = -1;
    char *path = "c:\\test_file.tmp";

    expect_string(__wrap_rmdir_ex, name, "queue/diff\\local\\c\\test_file.tmp");
    will_return(__wrap_rmdir_ex, 0);

    expect_string(__wrap_wreaddir, name, "queue/diff\\local\\c");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Removing empty directory 'queue/diff\\local\\c'.");

    expect_string(__wrap_rmdir_ex, name, "queue/diff\\local\\c");
    will_return(__wrap_rmdir_ex, 0);

    ret = delete_target_file(path);

    assert_int_equal(ret, 0);
}

static void test_delete_target_file_rmdir_ex_error(void **state) {
    int ret = -1;
    char *path = "c:\\test_file.tmp";

    expect_string(__wrap_rmdir_ex, name, "queue/diff\\local\\c\\test_file.tmp");
    will_return(__wrap_rmdir_ex, -1);

    ret = delete_target_file(path);

    assert_int_equal(ret, 1);
}

static void test_delete_target_file_invalid_path(void **state) {
    int ret = -1;
    char *path = "an\\invalid\\path";

    expect_string(__wrap__mdebug1, formatted_msg, "Incorrect path. This does not contain ':' ");

    ret = delete_target_file(path);

    assert_int_equal(ret, 0);
}
#endif

/* escape_syscheck_field tests */
static void test_escape_syscheck_field_escape_all(void **state) {
    char *input = "This is: a test string!!";
    char *output = NULL;

    output = escape_syscheck_field(input);

    *state = output;

    assert_string_equal(output, "This\\ is\\:\\ a\\ test\\ string\\!\\!");
}

static void test_escape_syscheck_field_null_input(void **state) {
    char *output;

    output = (char*)0xFFFF;
    output = escape_syscheck_field(NULL);

    assert_null(output);
}

/* normalize_path tests */
static void test_normalize_path_success(void **state) {
    char *test_string = strdup("C:\\Regular/windows/path\\");
    *state = test_string;

    normalize_path(test_string);

    assert_string_equal(test_string, "C:\\Regular\\windows\\path\\");
}

static void test_normalize_path_linux_dir(void **state) {
    char *test_string = strdup("/var/ossec/unchanged/path");

    if(test_string != NULL) {
        *state = test_string;
    } else {
        fail();
    }

    normalize_path(test_string);

    assert_string_equal(test_string, "/var/ossec/unchanged/path");
}

static void test_normalize_path_null_input(void **state) {
    char *test_string = NULL;

    expect_assert_failure(normalize_path(test_string));
}

/* remove_empty_folders tests */
static void test_remove_empty_folders_success(void **state) {
#ifndef TEST_WINAGENT
    char *input = "/var/ossec/queue/diff/local/test-dir/";
    char *first_subdir = "/var/ossec/queue/diff/local/test-dir";
#else
    char *input = "queue/diff\\local\\test-dir\\";
    char *first_subdir = "queue/diff\\local\\test-dir";
#endif
    int ret = -1;
    char message[OS_SIZE_1024];

    expect_string(__wrap_wreaddir, name, first_subdir);
    will_return(__wrap_wreaddir, NULL);

    snprintf(message, OS_SIZE_1024, "Removing empty directory '%s'.", first_subdir);
    expect_string(__wrap__mdebug1, formatted_msg, message);

    expect_string(__wrap_rmdir_ex, name, first_subdir);
    will_return(__wrap_rmdir_ex, 0);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_recursive_success(void **state) {
#ifndef TEST_WINAGENT
    char *input = "/var/ossec/queue/diff/local/dir1/dir2/";
    static const char *parent_dirs[] = {
        "/var/ossec/queue/diff/local/dir1/dir2",
        "/var/ossec/queue/diff/local/dir1"
    };
#else
    char *input = "queue/diff\\local\\dir1\\dir2\\";
    static const char *parent_dirs[] = {
        "queue/diff\\local\\dir1\\dir2",
        "queue/diff\\local\\dir1"
    };
#endif
    char messages[2][OS_SIZE_1024];
    int ret = -1;

    snprintf(messages[0], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[0]);
    snprintf(messages[1], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[1]);

    // Remove dir2
    expect_string(__wrap_wreaddir, name, parent_dirs[0]);
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);

    expect_string(__wrap_rmdir_ex, name, parent_dirs[0]);
    will_return(__wrap_rmdir_ex, 0);

    // Remove dir1
    expect_string(__wrap_wreaddir, name, parent_dirs[1]);
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);

    expect_string(__wrap_rmdir_ex, name, parent_dirs[1]);
    will_return(__wrap_rmdir_ex, 0);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_null_input(void **state) {
    expect_assert_failure(remove_empty_folders(NULL));
}

// TODO: Validate this condition is required to be tested
static void test_remove_empty_folders_relative_path(void **state) {
#ifndef TEST_WINAGENT
    char *input = "./local/test-dir/";
    const static char *parent_dirs[] = {"./local/test-dir", "./local", "."};
#else
    char *input = ".\\local\\test-dir\\";
    const static char *parent_dirs[] = {".\\local\\test-dir", ".\\local", "."};
#endif
    char messages[3][OS_SIZE_1024];
    int ret = -1;

    snprintf(messages[0], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[0]);
    snprintf(messages[1], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[1]);
    snprintf(messages[2], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[2]);

    expect_string(__wrap_wreaddir, name, parent_dirs[0]);
    expect_string(__wrap_wreaddir, name, parent_dirs[1]);
    expect_string(__wrap_wreaddir, name, parent_dirs[2]);
    will_return_always(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[2]);

    expect_string(__wrap_rmdir_ex, name, parent_dirs[0]);
    expect_string(__wrap_rmdir_ex, name, parent_dirs[1]);
    expect_string(__wrap_rmdir_ex, name, parent_dirs[2]);
    will_return_always(__wrap_rmdir_ex, 0);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

// TODO: Validate this condition is required to be tested
static void test_remove_empty_folders_absolute_path(void **state) {
    int ret = -1;
#ifndef TEST_WINAGENT
    char *input = "/home/user1/";
    static const char *parent_dirs[] = {
        "/home/user1",
        "/home",
        ""
    };
#else
    char *input = "c:\\home\\user1\\";
    static const char *parent_dirs[] = {
        "c:\\home\\user1",
        "c:\\home",
        "c:"
    };
#endif
    char messages[3][OS_SIZE_1024];

    snprintf(messages[0], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[0]);
    snprintf(messages[1], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[1]);
    snprintf(messages[2], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[2]);

    expect_string(__wrap_wreaddir, name, parent_dirs[0]);
    expect_string(__wrap_wreaddir, name, parent_dirs[1]);
    expect_string(__wrap_wreaddir, name, parent_dirs[2]);
    will_return_always(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[2]);

    expect_string(__wrap_rmdir_ex, name, parent_dirs[0]);
    expect_string(__wrap_rmdir_ex, name, parent_dirs[1]);
    expect_string(__wrap_rmdir_ex, name, parent_dirs[2]);
    will_return_always(__wrap_rmdir_ex, 0);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_non_empty_dir(void **state) {
#ifndef TEST_WINAGENT
    char *input = "/var/ossec/queue/diff/local/test-dir/";
    static const char *parent_dir = "/var/ossec/queue/diff/local/test-dir";
#else
    char *input = "queue/diff\\local\\c\\test-dir\\";
    static const char *parent_dir = "queue/diff\\local\\c\\test-dir";
#endif
    int ret = -1;
    char **subdir;

    if(subdir = calloc(2, sizeof(char*)), !subdir)
        fail();

    subdir[0] = strdup("some-file.tmp");
    subdir[1] = NULL;

    expect_string(__wrap_wreaddir, name, parent_dir);
    will_return(__wrap_wreaddir, subdir);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_error_removing_dir(void **state) {
#ifndef TEST_WINAGENT
    char *input = "/var/ossec/queue/diff/local/test-dir/";
    static const char *parent_dir = "/var/ossec/queue/diff/local/test-dir";
#else
    char *input = "queue/diff\\local\\test-dir\\";
    static const char *parent_dir = "queue/diff\\local\\test-dir";
#endif
    int ret = -1;
    char remove_dir_message[OS_SIZE_1024];
    char dir_not_deleted_message[OS_SIZE_1024];

    expect_string(__wrap_wreaddir, name, parent_dir);
    will_return(__wrap_wreaddir, NULL);

    snprintf(remove_dir_message, OS_SIZE_1024, "Removing empty directory '%s'.", parent_dir);
    expect_string(__wrap__mdebug1, formatted_msg, remove_dir_message);

    expect_string(__wrap_rmdir_ex, name, parent_dir);
    will_return(__wrap_rmdir_ex, -1);

    snprintf(dir_not_deleted_message, OS_SIZE_1024,
        "Empty directory '%s' couldn't be deleted. ('Directory not empty')", parent_dir);
    expect_string(__wrap__mwarn, formatted_msg, dir_not_deleted_message);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 1);
}

#if defined(TEST_SERVER)
/* sk_decode_sum tests */
static void test_sk_decode_sum_no_decode(void **state) {
    sk_decode_data_t *data = *state;

    int ret = sk_decode_sum(&data->sum, "-1", NULL);

    assert_int_equal(ret, 1);
}

static void test_sk_decode_sum_deleted_file(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("-1");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 1);
}

static void test_sk_decode_sum_no_perm(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_ptr_equal(data->sum.size, data->c_sum);
}

static void test_sk_decode_sum_missing_separator(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, data->c_sum);
}

static void test_sk_decode_sum_no_uid(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size::");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
}

static void test_sk_decode_sum_no_gid(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
}

static void test_sk_decode_sum_no_md5(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
}

static void test_sk_decode_sum_no_sha1(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
}

static void test_sk_decode_sum_no_new_fields(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}

static void test_sk_decode_sum_win_perm_string(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:win_perm:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_string_equal(data->sum.win_perm, "win_perm");
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

}

static void test_sk_decode_sum_win_perm_encoded(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:|account,0,4:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_string_equal(data->sum.win_perm, "account (allowed): append_data");
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}

static void test_sk_decode_sum_no_gname(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}

static void test_sk_decode_sum_no_uname(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        ":gname");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.gname, "gname");
}

static void test_sk_decode_sum_no_mtime(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.gname, "gname");
    assert_string_equal(data->sum.uname, "uname");
}

static void test_sk_decode_sum_no_inode(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname:2345");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.gname, "gname");
    assert_string_equal(data->sum.uname, "uname");
}

static void test_sk_decode_sum_no_sha256(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname:2345:3456");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.gname, "gname");
    assert_string_equal(data->sum.uname, "uname");
    assert_null(data->sum.sha256);
}

static void test_sk_decode_sum_empty_sha256(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname:2345:3456::");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.gname, "gname");
    assert_string_equal(data->sum.uname, "uname");
    assert_string_equal(data->sum.sha256, "");
    assert_int_equal(data->sum.mtime, 2345);
    assert_int_equal(data->sum.inode, 3456);
}

static void test_sk_decode_sum_no_attributes(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname:2345:3456:"
                        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.gname, "gname");
    assert_string_equal(data->sum.uname, "uname");
    assert_string_equal(data->sum.sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    assert_int_equal(data->sum.mtime, 2345);
    assert_int_equal(data->sum.inode, 3456);
}

static void test_sk_decode_sum_non_numeric_attributes(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname:2345:3456:"
                        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40:"
                        "attributes");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.gname, "gname");
    assert_string_equal(data->sum.uname, "uname");
    assert_string_equal(data->sum.sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    assert_int_equal(data->sum.mtime, 2345);
    assert_int_equal(data->sum.inode, 3456);
    assert_string_equal(data->sum.attributes, "attributes");
}

static void test_sk_decode_sum_win_encoded_attributes(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname:2345:3456:"
                        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40:"
                        "1");

    ret = sk_decode_sum(&data->sum, data->c_sum, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.gname, "gname");
    assert_string_equal(data->sum.uname, "uname");
    assert_string_equal(data->sum.sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    assert_int_equal(data->sum.mtime, 2345);
    assert_int_equal(data->sum.inode, 3456);
    assert_string_equal(data->sum.attributes, "READONLY");
}

static void test_sk_decode_sum_extra_data_empty(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}

static void test_sk_decode_sum_extra_data_no_user_name(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
}

static void test_sk_decode_sum_extra_data_no_group_id(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
}

static void test_sk_decode_sum_extra_data_no_group_name(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
    assert_string_equal(data->sum.wdata.group_id, "group_id");
}

static void test_sk_decode_sum_extra_data_no_process_name(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
}

static void test_sk_decode_sum_extra_data_no_audit_uid(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_null(data->sum.wdata.process_name);
}

static void test_sk_decode_sum_extra_data_no_audit_name(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_null(data->sum.wdata.process_name);
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
}

static void test_sk_decode_sum_extra_data_no_effective_uid(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_null(data->sum.wdata.process_name);
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
}

static void test_sk_decode_sum_extra_data_no_effective_name(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_null(data->sum.wdata.process_name);
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
}

static void test_sk_decode_sum_extra_data_no_ppid(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_null(data->sum.wdata.process_name);
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
    assert_string_equal(data->sum.wdata.effective_name, "effective_name");
}

static void test_sk_decode_sum_extra_data_no_process_id(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name:ppid");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, -1);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_null(data->sum.wdata.user_name);
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_null(data->sum.wdata.process_name);
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
    assert_string_equal(data->sum.wdata.effective_name, "effective_name");
    assert_string_equal(data->sum.wdata.ppid, "ppid");
}

static void test_sk_decode_sum_extra_data_no_tag(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name:ppid:process_id");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_string_equal(data->sum.wdata.user_name, "user_name");
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_string_equal(data->sum.wdata.process_name, "process_name");
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
    assert_string_equal(data->sum.wdata.effective_name, "effective_name");
    assert_string_equal(data->sum.wdata.ppid, "ppid");
    assert_string_equal(data->sum.wdata.process_id, "process_id");
    assert_null(data->sum.tag);
    assert_null(data->sum.symbolic_path);
}

static void test_sk_decode_sum_extra_data_no_symbolic_path(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name:"
                        "ppid:process_id:tag");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_string_equal(data->sum.wdata.user_name, "user_name");
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_string_equal(data->sum.wdata.process_name, "process_name");
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
    assert_string_equal(data->sum.wdata.effective_name, "effective_name");
    assert_string_equal(data->sum.wdata.ppid, "ppid");
    assert_string_equal(data->sum.wdata.process_id, "process_id");
    assert_string_equal(data->sum.tag, "tag");
    assert_null(data->sum.symbolic_path);
}

static void test_sk_decode_sum_extra_data_no_inode(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name:"
                        "ppid:process_id:tag:symbolic_path");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_string_equal(data->sum.wdata.user_name, "user_name");
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_string_equal(data->sum.wdata.process_name, "process_name");
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
    assert_string_equal(data->sum.wdata.effective_name, "effective_name");
    assert_string_equal(data->sum.wdata.ppid, "ppid");
    assert_string_equal(data->sum.wdata.process_id, "process_id");
    assert_string_equal(data->sum.tag, "tag");
    assert_string_equal(data->sum.symbolic_path, "symbolic_path");
}

static void test_sk_decode_sum_extra_data_all_fields(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name:"
                        "ppid:process_id:tag:symbolic_path:-");

    data->sum.silent = 0;

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_string_equal(data->sum.wdata.user_name, "user_name");
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_string_equal(data->sum.wdata.process_name, "process_name");
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
    assert_string_equal(data->sum.wdata.effective_name, "effective_name");
    assert_string_equal(data->sum.wdata.ppid, "ppid");
    assert_string_equal(data->sum.wdata.process_id, "process_id");
    assert_string_equal(data->sum.tag, "tag");
    assert_string_equal(data->sum.symbolic_path, "symbolic_path");
    assert_int_equal(data->sum.silent, 0);
}

static void test_sk_decode_sum_extra_data_all_fields_silent(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name:"
                        "ppid:process_id:tag:symbolic_path:+");

    data->sum.silent = 0;

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_string_equal(data->sum.wdata.user_name, "user_name");
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_string_equal(data->sum.wdata.process_name, "process_name");
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
    assert_string_equal(data->sum.wdata.effective_name, "effective_name");
    assert_string_equal(data->sum.wdata.ppid, "ppid");
    assert_string_equal(data->sum.wdata.process_id, "process_id");
    assert_string_equal(data->sum.tag, "tag");
    assert_string_equal(data->sum.symbolic_path, "symbolic_path");
    assert_int_equal(data->sum.silent, 1);
}

static void test_sk_decode_sum_extra_data_null_ppid(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 123456789;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name:"
                        "-:process_id:tag:symbolic_path:+");

    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);

    assert_int_equal(ret, 0);
    assert_string_equal(data->sum.size, "size");
    assert_int_equal(data->sum.perm, 1234);
    assert_string_equal(data->sum.uid, "uid");
    assert_string_equal(data->sum.gid, "gid");
    assert_string_equal(data->sum.md5, "3691689a513ace7e508297b583d7050d");
    assert_string_equal(data->sum.sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    assert_string_equal(data->sum.wdata.user_id, "user_id");
    assert_string_equal(data->sum.wdata.user_name, "user_name");
    assert_string_equal(data->sum.wdata.group_id, "group_id");
    assert_string_equal(data->sum.wdata.group_name, "group_name");
    assert_string_equal(data->sum.wdata.process_name, "process_name");
    assert_string_equal(data->sum.wdata.audit_uid, "audit_uid");
    assert_string_equal(data->sum.wdata.audit_name, "audit_name");
    assert_string_equal(data->sum.wdata.effective_uid, "effective_uid");
    assert_string_equal(data->sum.wdata.effective_name, "effective_name");
    assert_null(data->sum.wdata.ppid);
    assert_string_equal(data->sum.wdata.process_id, "process_id");
    assert_string_equal(data->sum.tag, "tag");
    assert_string_equal(data->sum.symbolic_path, "symbolic_path");
    assert_int_equal(data->sum.silent, 1);
}

// TODO: Validate this condition is required to be tested
static void test_sk_decode_sum_extra_data_null_sum(void **state) {
    sk_decode_data_t *data = *state;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    expect_assert_failure(sk_decode_sum(NULL, data->c_sum, NULL));
}

// TODO: Validate this condition is required to be tested
static void test_sk_decode_sum_extra_data_null_c_sum(void **state) {
    sk_decode_data_t *data = *state;

    expect_assert_failure(sk_decode_sum(&data->sum, NULL, NULL));
}

/* sk_decode_extradata tests */
static void test_sk_decode_extradata_null_sum(void **state) {
    sk_decode_data_t *data = *state;
    data->c_sum = strdup("some string");

    expect_assert_failure(sk_decode_extradata(NULL, data->c_sum));
}

static void test_sk_decode_extradata_null_c_sum(void **state) {
    sk_decode_data_t *data = *state;

    expect_assert_failure(sk_decode_extradata(&data->sum, NULL));
}

static void test_sk_decode_extradata_no_changes(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 12345;

    data->c_sum = strdup("some string");

    ret = sk_decode_extradata(&data->sum, data->c_sum);

    assert_int_equal(ret, 0);
    assert_string_equal(data->c_sum, "some string");
}

static void test_sk_decode_extradata_no_date_alert(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 12345;

    data->c_sum = strdup("some string!15");

    ret = sk_decode_extradata(&data->sum, data->c_sum);

    assert_int_equal(ret, 0);
    assert_string_equal(data->c_sum, "some string");
    assert_string_equal(data->c_sum + 12, "15");
}

static void test_sk_decode_extradata_no_sym_path(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 12345;

    data->c_sum = strdup("some string!15:20");

    data->sum.symbolic_path = NULL;

    ret = sk_decode_extradata(&data->sum, data->c_sum);

    assert_int_equal(ret, 1);
    assert_string_equal(data->c_sum, "some string");
    assert_string_equal(data->c_sum + 12, "15");
    assert_string_equal(data->c_sum + 15, "20");
    assert_int_equal(data->sum.changes, 15);
    assert_int_equal(data->sum.date_alert, 20);
    assert_null(data->sum.symbolic_path);
}

static void test_sk_decode_extradata_all_fields(void **state) {
    sk_decode_data_t *data = *state;
    int ret = 12345;

    data->c_sum = strdup("some string!15:20:a symbolic path");

    data->sum.symbolic_path = NULL;

    ret = sk_decode_extradata(&data->sum, data->c_sum);

    assert_int_equal(ret, 1);
    assert_string_equal(data->c_sum, "some string");
    assert_string_equal(data->c_sum + 12, "15");
    assert_string_equal(data->c_sum + 15, "20");
    assert_int_equal(data->sum.changes, 15);
    assert_int_equal(data->sum.date_alert, 20);
    assert_string_equal(data->sum.symbolic_path, "a symbolic path");
}

/* sk_fill_event tests */
static void test_sk_fill_event_full_event(void **state) {
    sk_fill_event_t *data = *state;

    data->f_name = strdup("f_name");

    data->sum->size = "size";
    data->sum->perm = 123456; // 361100 in octal
    data->sum->uid = "uid";
    data->sum->gid = "gid";
    data->sum->md5 = "md5";
    data->sum->sha1 = "sha1";
    data->sum->uname = "uname";
    data->sum->gname = "gname";
    data->sum->mtime = 2345678;
    data->sum->inode = 3456789;
    data->sum->sha256 = "sha256";
    data->sum->attributes = "attributes";
    data->sum->wdata.user_id = "user_id";
    data->sum->wdata.user_name = "user_name";
    data->sum->wdata.group_id = "group_id";
    data->sum->wdata.group_name = "group_name";
    data->sum->wdata.process_name = "process_name";
    data->sum->wdata.audit_uid = "audit_uid";
    data->sum->wdata.audit_name = "audit_name";
    data->sum->wdata.effective_uid = "effective_uid";
    data->sum->wdata.effective_name = "effective_name";
    data->sum->wdata.ppid = "ppid";
    data->sum->wdata.process_id = "process_id";
    data->sum->tag = "tag";
    data->sum->symbolic_path = "symbolic_path";

    sk_fill_event(data->lf, data->f_name, data->sum);

    assert_string_equal(data->lf->filename, "f_name");
    assert_string_equal(data->lf->fields[FIM_FILE].value, "f_name");
    assert_string_equal(data->lf->fields[FIM_SIZE].value, "size");
    assert_string_equal(data->lf->fields[FIM_PERM].value, "361100");
    assert_string_equal(data->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(data->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(data->lf->fields[FIM_MD5].value, "md5");
    assert_string_equal(data->lf->fields[FIM_SHA1].value, "sha1");
    assert_string_equal(data->lf->fields[FIM_UNAME].value, "uname");
    assert_string_equal(data->lf->fields[FIM_GNAME].value, "gname");
    assert_int_equal(data->lf->mtime_after, data->sum->mtime);
    assert_string_equal(data->lf->fields[FIM_MTIME].value, "2345678");
    assert_int_equal(data->lf->inode_after, data->sum->inode);
    assert_string_equal(data->lf->fields[FIM_INODE].value, "3456789");
    assert_string_equal(data->lf->fields[FIM_SHA256].value, "sha256");
    assert_string_equal(data->lf->fields[FIM_ATTRS].value, "attributes");

    assert_string_equal(data->lf->user_id, "user_id");
    assert_string_equal(data->lf->fields[FIM_USER_ID].value, "user_id");

    assert_string_equal(data->lf->user_name, "user_name");
    assert_string_equal(data->lf->fields[FIM_USER_NAME].value, "user_name");

    assert_string_equal(data->lf->group_id, "group_id");
    assert_string_equal(data->lf->fields[FIM_GROUP_ID].value, "group_id");

    assert_string_equal(data->lf->group_name, "group_name");
    assert_string_equal(data->lf->fields[FIM_GROUP_NAME].value, "group_name");

    assert_string_equal(data->lf->process_name, "process_name");
    assert_string_equal(data->lf->fields[FIM_PROC_NAME].value, "process_name");

    assert_string_equal(data->lf->audit_uid, "audit_uid");
    assert_string_equal(data->lf->fields[FIM_AUDIT_ID].value, "audit_uid");

    assert_string_equal(data->lf->audit_name, "audit_name");
    assert_string_equal(data->lf->fields[FIM_AUDIT_NAME].value, "audit_name");

    assert_string_equal(data->lf->effective_uid, "effective_uid");
    assert_string_equal(data->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");

    assert_string_equal(data->lf->effective_name, "effective_name");
    assert_string_equal(data->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(data->lf->ppid, "ppid");
    assert_string_equal(data->lf->fields[FIM_PPID].value, "ppid");

    assert_string_equal(data->lf->process_id, "process_id");
    assert_string_equal(data->lf->fields[FIM_PROC_ID].value, "process_id");

    assert_string_equal(data->lf->sk_tag, "tag");
    assert_string_equal(data->lf->fields[FIM_TAG].value, "tag");

    assert_string_equal(data->lf->sym_path, "symbolic_path");
    assert_string_equal(data->lf->fields[FIM_SYM_PATH].value, "symbolic_path");
}

static void test_sk_fill_event_empty_event(void **state) {
    sk_fill_event_t *data = *state;

    data->f_name = strdup("f_name");

    sk_fill_event(data->lf, data->f_name, data->sum);

    assert_string_equal(data->lf->filename, "f_name");
    assert_string_equal(data->lf->fields[FIM_FILE].value, "f_name");
    assert_null(data->lf->fields[FIM_SIZE].value);
    assert_null(data->lf->fields[FIM_PERM].value);
    assert_null(data->lf->fields[FIM_UID].value);
    assert_null(data->lf->fields[FIM_GID].value);
    assert_null(data->lf->fields[FIM_MD5].value);
    assert_null(data->lf->fields[FIM_SHA1].value);
    assert_null(data->lf->fields[FIM_UNAME].value);
    assert_null(data->lf->fields[FIM_GNAME].value);
    assert_int_equal(data->lf->mtime_after, data->sum->mtime);
    assert_null(data->lf->fields[FIM_MTIME].value);
    assert_int_equal(data->lf->inode_after, data->sum->inode);
    assert_null(data->lf->fields[FIM_INODE].value);
    assert_null(data->lf->fields[FIM_SHA256].value);
    assert_null(data->lf->fields[FIM_ATTRS].value);

    assert_null(data->lf->user_id);
    assert_null(data->lf->fields[FIM_USER_ID].value);

    assert_null(data->lf->user_name);
    assert_null(data->lf->fields[FIM_USER_NAME].value);

    assert_null(data->lf->group_id);
    assert_null(data->lf->fields[FIM_GROUP_ID].value);

    assert_null(data->lf->group_name);
    assert_null(data->lf->fields[FIM_GROUP_NAME].value);

    assert_null(data->lf->process_name);
    assert_null(data->lf->fields[FIM_PROC_NAME].value);

    assert_null(data->lf->audit_uid);
    assert_null(data->lf->fields[FIM_AUDIT_ID].value);

    assert_null(data->lf->audit_name);
    assert_null(data->lf->fields[FIM_AUDIT_NAME].value);

    assert_null(data->lf->effective_uid);
    assert_null(data->lf->fields[FIM_EFFECTIVE_UID].value);

    assert_null(data->lf->effective_name);
    assert_null(data->lf->fields[FIM_EFFECTIVE_NAME].value);

    assert_null(data->lf->ppid);
    assert_null(data->lf->fields[FIM_PPID].value);

    assert_null(data->lf->process_id);
    assert_null(data->lf->fields[FIM_PROC_ID].value);

    assert_null(data->lf->sk_tag);
    assert_null(data->lf->fields[FIM_TAG].value);

    assert_null(data->lf->sym_path);
    assert_null(data->lf->fields[FIM_SYM_PATH].value);
}

static void test_sk_fill_event_win_perm(void **state) {
    sk_fill_event_t *data = *state;

    data->f_name = strdup("f_name");

    data->sum->win_perm = "win_perm";

    sk_fill_event(data->lf, data->f_name, data->sum);

    assert_string_equal(data->lf->filename, "f_name");
    assert_string_equal(data->lf->fields[FIM_FILE].value, "f_name");
    assert_null(data->lf->fields[FIM_SIZE].value);
    assert_string_equal(data->lf->fields[FIM_PERM].value, "win_perm");
    assert_null(data->lf->fields[FIM_UID].value);
    assert_null(data->lf->fields[FIM_GID].value);
    assert_null(data->lf->fields[FIM_MD5].value);
    assert_null(data->lf->fields[FIM_SHA1].value);
    assert_null(data->lf->fields[FIM_UNAME].value);
    assert_null(data->lf->fields[FIM_GNAME].value);
    assert_int_equal(data->lf->mtime_after, data->sum->mtime);
    assert_null(data->lf->fields[FIM_MTIME].value);
    assert_int_equal(data->lf->inode_after, data->sum->inode);
    assert_null(data->lf->fields[FIM_INODE].value);
    assert_null(data->lf->fields[FIM_SHA256].value);
    assert_null(data->lf->fields[FIM_ATTRS].value);

    assert_null(data->lf->user_id);
    assert_null(data->lf->fields[FIM_USER_ID].value);

    assert_null(data->lf->user_name);
    assert_null(data->lf->fields[FIM_USER_NAME].value);

    assert_null(data->lf->group_id);
    assert_null(data->lf->fields[FIM_GROUP_ID].value);

    assert_null(data->lf->group_name);
    assert_null(data->lf->fields[FIM_GROUP_NAME].value);

    assert_null(data->lf->process_name);
    assert_null(data->lf->fields[FIM_PROC_NAME].value);

    assert_null(data->lf->audit_uid);
    assert_null(data->lf->fields[FIM_AUDIT_ID].value);

    assert_null(data->lf->audit_name);
    assert_null(data->lf->fields[FIM_AUDIT_NAME].value);

    assert_null(data->lf->effective_uid);
    assert_null(data->lf->fields[FIM_EFFECTIVE_UID].value);

    assert_null(data->lf->effective_name);
    assert_null(data->lf->fields[FIM_EFFECTIVE_NAME].value);

    assert_null(data->lf->ppid);
    assert_null(data->lf->fields[FIM_PPID].value);

    assert_null(data->lf->process_id);
    assert_null(data->lf->fields[FIM_PROC_ID].value);

    assert_null(data->lf->sk_tag);
    assert_null(data->lf->fields[FIM_TAG].value);

    assert_null(data->lf->sym_path);
    assert_null(data->lf->fields[FIM_SYM_PATH].value);
}

static void test_sk_fill_event_null_eventinfo(void **state) {
    sk_fill_event_t *data = *state;

    data->f_name = strdup("f_name");

    data->sum->win_perm = "win_perm";

    expect_assert_failure(sk_fill_event(NULL, data->f_name, data->sum));
}

static void test_sk_fill_event_null_f_name(void **state) {
    sk_fill_event_t *data = *state;

    data->sum->win_perm = "win_perm";

    expect_assert_failure(sk_fill_event(data->lf, NULL, data->sum));
}

// TODO: Validate this condition is required to be tested
static void test_sk_fill_event_null_sum(void **state) {
    sk_fill_event_t *data = *state;

    data->f_name = strdup("f_name");

    expect_assert_failure(sk_fill_event(data->lf, data->f_name, NULL));
}

/* sk_build_sum tests */
static void test_sk_build_sum_full_message(void **state) {
    sk_build_sum_t *data = *state;
    int ret;

    data->sum.size = "size";
    data->sum.perm = 123456;
    data->sum.win_perm = NULL;
    data->sum.uid = "uid";
    data->sum.gid = "gid";
    data->sum.md5 = "md5";
    data->sum.sha1 = "sha1";
    data->sum.uname = "username";
    data->sum.gname = "gname";
    data->sum.mtime = 234567;
    data->sum.inode = 345678;
    data->sum.sha256 = "sha256";
    data->sum.attributes = "attributes";
    data->sum.changes = 456789;
    data->sum.date_alert = 567890;

    ret = sk_build_sum(&data->sum, data->output, OS_MAXSTR);

    assert_int_equal(ret, 0);
    assert_string_equal(data->output,
                        "size:123456:uid:gid:md5:sha1:username:gname:234567:345678:sha256:attributes!456789:567890");
}

static void test_sk_build_sum_skip_fields_message(void **state) {
    sk_build_sum_t *data = *state;
    int ret;

    data->sum.size = "size";
    data->sum.perm = 0;
    data->sum.win_perm = NULL;
    data->sum.uid = "uid";
    data->sum.gid = "gid";
    data->sum.md5 = "md5";
    data->sum.sha1 = "sha1";
    data->sum.uname = NULL;
    data->sum.gname = NULL;
    data->sum.mtime = 0;
    data->sum.inode = 0;
    data->sum.sha256 = NULL;
    data->sum.attributes = NULL;
    data->sum.changes = 0;
    data->sum.date_alert = 0;

    ret = sk_build_sum(&data->sum, data->output, OS_MAXSTR);

    assert_int_equal(ret, 0);
    assert_string_equal(data->output, "size::uid:gid:md5:sha1::::::!0:0");
}

static void test_sk_build_sum_win_perm(void **state) {
    sk_build_sum_t *data = *state;
    int ret;

    data->sum.size = "size";
    data->sum.perm = 0;
    data->sum.win_perm = "win_perm";
    data->sum.uid = "uid";
    data->sum.gid = "gid";
    data->sum.md5 = "md5";
    data->sum.sha1 = "sha1";
    data->sum.uname = NULL;
    data->sum.gname = NULL;
    data->sum.mtime = 0;
    data->sum.inode = 0;
    data->sum.sha256 = NULL;
    data->sum.attributes = NULL;
    data->sum.changes = 0;
    data->sum.date_alert = 0;

    ret = sk_build_sum(&data->sum, data->output, OS_MAXSTR);

    assert_int_equal(ret, 0);
    assert_string_equal(data->output, "size:win_perm:uid:gid:md5:sha1::::::!0:0");
}

static void test_sk_build_sum_insufficient_buffer_size(void **state) {
    sk_build_sum_t *data = *state;
    int ret;

    data->sum.size = "size";
    data->sum.perm = 0;
    data->sum.win_perm = "win_perm";
    data->sum.uid = "uid";
    data->sum.gid = "gid";
    data->sum.md5 = "md5";
    data->sum.sha1 = "sha1";
    data->sum.uname = NULL;
    data->sum.gname = NULL;
    data->sum.mtime = 0;
    data->sum.inode = 0;
    data->sum.sha256 = NULL;
    data->sum.attributes = NULL;
    data->sum.changes = 0;
    data->sum.date_alert = 0;

    ret = sk_build_sum(&data->sum, data->output, 10);

    assert_int_equal(ret, -1);
    assert_string_equal(data->output, "size:win_");
}

static void test_sk_build_sum_null_sum(void **state) {
    sk_build_sum_t *data = *state;

    expect_assert_failure(sk_build_sum(NULL, data->output, OS_MAXSTR));
}

static void test_sk_build_sum_null_output(void **state) {
    sk_build_sum_t *data = *state;

    expect_assert_failure(sk_build_sum(&data->sum, NULL, OS_MAXSTR));
}

/* sk_sum_clean tests */
static void test_sk_sum_clean_full_message(void **state) {
    sk_decode_data_t *data = *state;
    int ret;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname:2345:3456:"
                        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40:"
                        "1");
    data->w_sum = strdup("user_id:user_name:group_id:group_name:process_name:"
                        "audit_uid:audit_name:effective_uid:effective_name:"
                        "ppid:process_id:tag:symbolic_path:-");

    // Fill sum with as many info as possible
    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);
    assert_int_equal(ret, 0);

    // And free it
    sk_sum_clean(&data->sum);

    assert_null(data->sum.symbolic_path);
    assert_null(data->sum.attributes);
    assert_null(data->sum.wdata.user_name);
    assert_null(data->sum.wdata.process_name);
    assert_null(data->sum.uname);
    assert_null(data->sum.win_perm);
}

static void test_sk_sum_clean_shortest_valid_message(void **state) {
    sk_decode_data_t *data = *state;
    int ret;

    data->c_sum = strdup("size:1234:uid:gid:"
                        "3691689a513ace7e508297b583d7050d:"
                        "07f05add1049244e7e71ad0f54f24d8094cd8f8b:"
                        "uname:gname:2345:3456");

    // Fill sum with as many info as possible
    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);
    assert_int_equal(ret, 0);

    // And free it
    sk_sum_clean(&data->sum);

    assert_null(data->sum.symbolic_path);
    assert_null(data->sum.attributes);
    assert_null(data->sum.wdata.user_name);
    assert_null(data->sum.wdata.process_name);
    assert_null(data->sum.uname);
    assert_null(data->sum.win_perm);
}

static void test_sk_sum_clean_invalid_message(void **state) {
    sk_decode_data_t *data = *state;
    int ret;

    data->c_sum = strdup("This is not a valid syscheck message");

    // Fill sum with as many info as possible
    ret = sk_decode_sum(&data->sum, data->c_sum, data->w_sum);
    assert_int_equal(ret, -1);

    // And free it
    sk_sum_clean(&data->sum);

    assert_null(data->sum.symbolic_path);
    assert_null(data->sum.attributes);
    assert_null(data->sum.wdata.user_name);
    assert_null(data->sum.wdata.process_name);
    assert_null(data->sum.uname);
    assert_null(data->sum.win_perm);
}

// TODO: Validate this condition is required to be tested
static void test_sk_sum_clean_null_sum(void **state) {
    expect_assert_failure(sk_sum_clean(NULL));
}
#endif
#ifndef TEST_WINAGENT
/* unescape_syscheck_field tests */
static void test_unescape_syscheck_field_escaped_chars(void **state) {
    unescape_syscheck_field_data_t *data = *state;

    data->input = strdup("Hi\\!! This\\ is\\ a string with\\: escaped chars:");

    data->output = unescape_syscheck_field(data->input);

    assert_string_equal(data->output, "Hi!! This is a string with: escaped chars:");
}

static void test_unescape_syscheck_field_no_escaped_chars(void **state) {
    unescape_syscheck_field_data_t *data = *state;

    data->input = strdup("Hi!! This is a string without: escaped chars:");

    data->output = unescape_syscheck_field(data->input);

    assert_string_equal(data->output, "Hi!! This is a string without: escaped chars:");
}

static void test_unescape_syscheck_null_input(void **state) {
    unescape_syscheck_field_data_t *data = *state;

    data->input = NULL;

    data->output = unescape_syscheck_field(data->input);

    assert_null(data->output);
}

static void test_unescape_syscheck_empty_string(void **state) {
    unescape_syscheck_field_data_t *data = *state;

    data->input = strdup("");

    data->output = unescape_syscheck_field(data->input);

    assert_null(data->output);
}

/* get_user tests */
static void test_get_user_success(void **state) {
    char *user;

    will_return(__wrap_sysconf, 16384);

    will_return(__wrap_getpwuid_r, "user_name");
    will_return(__wrap_getpwuid_r, 1);
#ifndef SOLARIS
    will_return(__wrap_getpwuid_r, 0);
#endif

    user = get_user(1);

    *state = user;

    assert_string_equal(user, "user_name");
}

static void test_get_user_uid_not_found(void **state) {
    char *user;

    will_return(__wrap_sysconf, -1);

    will_return(__wrap_getpwuid_r, "user_name");
    will_return(__wrap_getpwuid_r, NULL);
#ifndef SOLARIS
    will_return(__wrap_getpwuid_r, 0);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "User with uid '1' not found.\n");

    user = get_user(1);

    *state = user;

    assert_null(user);
}

static void test_get_user_error(void **state) {
    char *user;

    will_return(__wrap_sysconf, 16384);

    will_return(__wrap_getpwuid_r, "user_name");
    will_return(__wrap_getpwuid_r, NULL);
#ifndef SOLARIS
    will_return(__wrap_getpwuid_r, ENOENT);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "Failed getting user_name (2): 'No such file or directory'\n");

    user = get_user(1);

    *state = user;

    assert_null(user);
}
#endif

#if defined(TEST_WINAGENT)
struct group {
    const char *gr_name;
};
#endif

/* get_group tests */
#ifndef TEST_WINAGENT
static void test_get_group_success(void **state) {
    struct group group = { .gr_name = "group" };
    const char *output;

    will_return(__wrap_getgrgid, &group);

    output = get_group(0);

    assert_ptr_equal(output, group.gr_name);
}

static void test_get_group_failure(void **state) {
    const char *output;

    will_return(__wrap_getgrgid, NULL);

    output = get_group(0);

    assert_string_equal(output, "");
}
#else
static void test_get_group(void **state) {
    assert_string_equal(get_group(0), "");
}
#endif

/* ag_send_syscheck tests */
/* ag_send_syscheck does not modify inputs or return anything, so there are no asserts */
/* validation of this function is done through the wrapped functions. */
#ifndef TEST_WINAGENT
static void test_ag_send_syscheck_success(void **state) {
    char *input = "This is a mock message, it wont be sent anywhere";

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);

    will_return(__wrap_OS_ConnectUnixDomain, 1234);

    expect_value(__wrap_OS_SendSecureTCP, sock, 1234);
    expect_value(__wrap_OS_SendSecureTCP, size, 48);
    expect_string(__wrap_OS_SendSecureTCP, msg, input);

    will_return(__wrap_OS_SendSecureTCP, 48);

    ag_send_syscheck(input);
}

static void test_ag_send_syscheck_unable_to_connect(void **state) {
    char *input = "This is a mock message, it wont be sent anywhere";

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);

    will_return(__wrap_OS_ConnectUnixDomain, OS_SOCKTERR);

    errno = EADDRNOTAVAIL;

    expect_string(__wrap__merror, formatted_msg, "dbsync: cannot connect to syscheck: Cannot assign requested address (99)");

    ag_send_syscheck(input);

    errno = 0;
}
static void test_ag_send_syscheck_error_sending_message(void **state) {
    char *input = "This is a mock message, it wont be sent anywhere";

    expect_string(__wrap_OS_ConnectUnixDomain, path, DEFAULTDIR SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);

    will_return(__wrap_OS_ConnectUnixDomain, 1234);

    expect_value(__wrap_OS_SendSecureTCP, sock, 1234);
    expect_value(__wrap_OS_SendSecureTCP, size, 48);
    expect_string(__wrap_OS_SendSecureTCP, msg, input);

    will_return(__wrap_OS_SendSecureTCP, OS_SOCKTERR);

    errno = EWOULDBLOCK;

    expect_string(__wrap__merror, formatted_msg, "Cannot send message to syscheck: Resource temporarily unavailable (11)");

    ag_send_syscheck(input);

    errno = 0;
}
#else
static void test_ag_send_syscheck(void **state) {
    char *response = strdup("A mock reponse message");

    expect_string(__wrap_syscom_dispatch, command, "command");
    will_return(__wrap_syscom_dispatch, response);
    will_return(__wrap_syscom_dispatch, 23);

    ag_send_syscheck("command");
}
#endif

/* decode_win_attributes tests */
static void test_decode_win_attributes_all_attributes(void **state) {
    char str[OS_SIZE_256];
    unsigned int attrs = 0;

    attrs |= FILE_ATTRIBUTE_ARCHIVE     |
             FILE_ATTRIBUTE_COMPRESSED  |
             FILE_ATTRIBUTE_DEVICE      |
             FILE_ATTRIBUTE_DIRECTORY   |
             FILE_ATTRIBUTE_ENCRYPTED   |
             FILE_ATTRIBUTE_HIDDEN      |
             FILE_ATTRIBUTE_NORMAL      |
             FILE_ATTRIBUTE_OFFLINE     |
             FILE_ATTRIBUTE_READONLY    |
             FILE_ATTRIBUTE_SPARSE_FILE |
             FILE_ATTRIBUTE_SYSTEM      |
             FILE_ATTRIBUTE_TEMPORARY   |
             FILE_ATTRIBUTE_VIRTUAL     |
             FILE_ATTRIBUTE_NO_SCRUB_DATA |
             FILE_ATTRIBUTE_REPARSE_POINT |
             FILE_ATTRIBUTE_RECALL_ON_OPEN |
             FILE_ATTRIBUTE_INTEGRITY_STREAM |
             FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
             FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

    decode_win_attributes(str, attrs);

    assert_string_equal(str, "ARCHIVE, COMPRESSED, DEVICE, DIRECTORY, ENCRYPTED, "
                             "HIDDEN, INTEGRITY_STREAM, NORMAL, NOT_CONTENT_INDEXED, "
                             "NO_SCRUB_DATA, OFFLINE, READONLY, RECALL_ON_DATA_ACCESS, "
                             "RECALL_ON_OPEN, REPARSE_POINT, SPARSE_FILE, SYSTEM, TEMPORARY, "
                             "VIRTUAL");
}

static void test_decode_win_attributes_no_attributes(void **state) {
    char str[OS_SIZE_256];
    unsigned int attrs = 0;

    decode_win_attributes(str, attrs);

    assert_string_equal(str, "");
}

static void test_decode_win_attributes_some_attributes(void **state) {
    char str[OS_SIZE_256];
    unsigned int attrs = 0;

    attrs |= FILE_ATTRIBUTE_ARCHIVE     |
             FILE_ATTRIBUTE_DEVICE      |
             FILE_ATTRIBUTE_ENCRYPTED   |
             FILE_ATTRIBUTE_NORMAL      |
             FILE_ATTRIBUTE_READONLY    |
             FILE_ATTRIBUTE_SPARSE_FILE |
             FILE_ATTRIBUTE_TEMPORARY   |
             FILE_ATTRIBUTE_NO_SCRUB_DATA |
             FILE_ATTRIBUTE_RECALL_ON_OPEN;

    decode_win_attributes(str, attrs);

    assert_string_equal(str, "ARCHIVE, DEVICE, ENCRYPTED, NORMAL, NO_SCRUB_DATA, "
                             "READONLY, RECALL_ON_OPEN, SPARSE_FILE, TEMPORARY");
}

/* decode_win_permissions tests */
static void test_decode_win_permissions_success_all_permissions(void **state) {
    char *raw_perm = calloc(OS_MAXSTR, sizeof(char));
    char *output;

    snprintf(raw_perm, OS_MAXSTR,  "|account,0,%ld",
        (long int)(GENERIC_READ |
        GENERIC_WRITE |
        GENERIC_EXECUTE |
        GENERIC_ALL |
        DELETE |
        READ_CONTROL |
        WRITE_DAC |
        WRITE_OWNER |
        SYNCHRONIZE |
        FILE_READ_DATA |
        FILE_WRITE_DATA |
        FILE_APPEND_DATA |
        FILE_READ_EA |
        FILE_WRITE_EA |
        FILE_EXECUTE |
        FILE_READ_ATTRIBUTES |
        FILE_WRITE_ATTRIBUTES));

    output = decode_win_permissions(raw_perm);

    free(raw_perm);
    *state = output;

    assert_string_equal(output, "account (allowed): generic_read|generic_write|generic_execute|"
        "generic_all|delete|read_control|write_dac|write_owner|synchronize|read_data|write_data|"
        "append_data|read_ea|write_ea|execute|read_attributes|write_attributes");
}

static void test_decode_win_permissions_success_no_permissions(void **state) {
    char *raw_perm = calloc(OS_MAXSTR, sizeof(char));
    char *output;

    snprintf(raw_perm, OS_MAXSTR,  "|account,0,%ld", (long int)0);

    output = decode_win_permissions(raw_perm);

    free(raw_perm);
    *state = output;

    assert_string_equal(output, "account (allowed):");
}

static void test_decode_win_permissions_success_some_permissions(void **state) {
    char *raw_perm = calloc(OS_MAXSTR, sizeof(char));
    char *output;

    snprintf(raw_perm, OS_MAXSTR,  "|account,0,%ld",
        (long int)(GENERIC_READ |
        GENERIC_EXECUTE |
        DELETE |
        WRITE_DAC |
        SYNCHRONIZE |
        FILE_WRITE_DATA |
        FILE_READ_EA |
        FILE_EXECUTE |
        FILE_WRITE_ATTRIBUTES));

    output = decode_win_permissions(raw_perm);

    free(raw_perm);
    *state = output;

    assert_string_equal(output, "account (allowed): generic_read|generic_execute|"
        "delete|write_dac|synchronize|write_data|read_ea|execute|write_attributes");
}

static void test_decode_win_permissions_success_multiple_accounts(void **state) {
    char *raw_perm = calloc(OS_MAXSTR, sizeof(char));
    char *output;

    snprintf(raw_perm, OS_MAXSTR,  "|first,0,%ld|second,1,%ld", (long int)GENERIC_READ, (long int)GENERIC_EXECUTE);

    output = decode_win_permissions(raw_perm);

    free(raw_perm);
    *state = output;

    assert_string_equal(output, "first (allowed): generic_read, second (denied): generic_execute");
}

static void test_decode_win_permissions_fail_no_account_name(void **state) {
    char *raw_perm = "|this wont pass";
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '|this wont pass'.");

    output = decode_win_permissions(raw_perm);

    *state = output;

    assert_null(output);
}

static void test_decode_win_permissions_fail_no_access_type(void **state) {
    char *raw_perm = strdup("|account,this wont pass");
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '|account,this wont pass'.");

    output = decode_win_permissions(raw_perm);

    free(raw_perm);
    *state = output;

    assert_null(output);
}

static void test_decode_win_permissions_fail_wrong_format(void **state) {
    char *raw_perm = strdup("this is not the proper format");
    char *output;

    output = decode_win_permissions(raw_perm);

    free(raw_perm);
    *state = output;

    assert_string_equal("", output);
}

/* attrs_to_json tests */
static void test_attrs_to_json_single_attribute(void **state) {
    char *input = "attribute";
    cJSON *output;
    char *string;

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    output = attrs_to_json(input);

    *state = output;

    string = cJSON_GetStringValue(cJSON_GetArrayItem(output, 0));
    assert_string_equal(string, "attribute");
}

static void test_attrs_to_json_multiple_attributes(void **state) {
    char *input = "attr1, attr2, attr3";
    cJSON *output;
    char *attr1, *attr2, *attr3;

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    output = attrs_to_json(input);

    *state = output;

    attr1 = cJSON_GetStringValue(cJSON_GetArrayItem(output, 0));
    attr2 = cJSON_GetStringValue(cJSON_GetArrayItem(output, 1));
    attr3 = cJSON_GetStringValue(cJSON_GetArrayItem(output, 2));

    assert_string_equal(attr1, "attr1");
    assert_string_equal(attr2, "attr2");
    assert_string_equal(attr3, "attr3");
}

static void test_attrs_to_json_unable_to_create_json_array(void **state)  {
    char *input = "attr1, attr2, attr3";
    cJSON *output;

    will_return(__wrap_cJSON_CreateArray, NULL);

    output = attrs_to_json(input);

    *state = output;

    assert_null(output);
}

// TODO: Validate this condition is required to be tested
static void test_attrs_to_json_null_attributes(void **state)  {
    expect_assert_failure(attrs_to_json(NULL));
}

/* win_perm_to_json tests*/
static void test_win_perm_to_json_all_permissions(void **state) {
    char *input = "account (allowed): generic_read|generic_write|generic_execute|"
        "generic_all|delete|read_control|write_dac|write_owner|synchronize|read_data|write_data|"
        "append_data|read_ea|write_ea|execute|read_attributes|write_attributes";
    cJSON *output;
    cJSON *user, *permissions_array;
    char *string;

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    will_return_always(__wrap_wstr_split, 1);  // use real wstr_split

    output = win_perm_to_json(input);

    *state = output;

    assert_int_equal(cJSON_GetArraySize(output), 1);

    user = cJSON_GetArrayItem(output, 0);

    string = cJSON_GetStringValue(cJSON_GetObjectItem(user, "name"));
    assert_string_equal(string, "account");

    permissions_array = cJSON_GetObjectItem(user, "allowed");

    assert_int_equal(cJSON_GetArraySize(permissions_array), 17);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "GENERIC_READ");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "GENERIC_WRITE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "GENERIC_EXECUTE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 3));
    assert_string_equal(string, "GENERIC_ALL");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 4));
    assert_string_equal(string, "DELETE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 5));
    assert_string_equal(string, "READ_CONTROL");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 6));
    assert_string_equal(string, "WRITE_DAC");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 7));
    assert_string_equal(string, "WRITE_OWNER");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 8));
    assert_string_equal(string, "SYNCHRONIZE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 9));
    assert_string_equal(string, "READ_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 10));
    assert_string_equal(string, "WRITE_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 11));
    assert_string_equal(string, "APPEND_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 12));
    assert_string_equal(string, "READ_EA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 13));
    assert_string_equal(string, "WRITE_EA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 14));
    assert_string_equal(string, "EXECUTE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 15));
    assert_string_equal(string, "READ_ATTRIBUTES");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 16));
    assert_string_equal(string, "WRITE_ATTRIBUTES");
}

static void test_win_perm_to_json_some_permissions(void **state) {
    char *input = "account (allowed): generic_read|generic_execute|delete|"
        "write_dac|synchronize|write_data|read_ea|execute|write_attributes";
    cJSON *output;
    cJSON *user, *permissions_array;
    char *string;

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    will_return_always(__wrap_wstr_split, 1);  // use real wstr_split

    output = win_perm_to_json(input);

    *state = output;

    assert_int_equal(cJSON_GetArraySize(output), 1);

    user = cJSON_GetArrayItem(output, 0);

    string = cJSON_GetStringValue(cJSON_GetObjectItem(user, "name"));
    assert_string_equal(string, "account");

    permissions_array = cJSON_GetObjectItem(user, "allowed");

    assert_int_equal(cJSON_GetArraySize(permissions_array), 9);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "GENERIC_READ");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "GENERIC_EXECUTE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "DELETE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 3));
    assert_string_equal(string, "WRITE_DAC");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 4));
    assert_string_equal(string, "SYNCHRONIZE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 5));
    assert_string_equal(string, "WRITE_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 6));
    assert_string_equal(string, "READ_EA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 7));
    assert_string_equal(string, "EXECUTE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 8));
    assert_string_equal(string, "WRITE_ATTRIBUTES");
}

static void test_win_perm_to_json_no_permissions(void **state) {
    char *input = "account (allowed)";
    cJSON *output;

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing a Windows permission from 'account (allowed)'.");

    output = win_perm_to_json(input);

    *state = output;

    assert_null(output);
}

static void test_win_perm_to_json_allowed_denied_permissions(void **state) {
    char *input = "account (denied): generic_read|generic_write|generic_execute|"
        "generic_all|delete|read_control|write_dac|write_owner, account (allowed): synchronize|read_data|write_data|"
        "append_data|read_ea|write_ea|execute|read_attributes|write_attributes";
    cJSON *output;
    cJSON *user, *permissions_array;
    char *string;

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    will_return_always(__wrap_wstr_split, 1);  // use real wstr_split

    output = win_perm_to_json(input);

    *state = output;

    assert_int_equal(cJSON_GetArraySize(output), 1);

    user = cJSON_GetArrayItem(output, 0);

    string = cJSON_GetStringValue(cJSON_GetObjectItem(user, "name"));
    assert_string_equal(string, "account");

    permissions_array = cJSON_GetObjectItem(user, "denied");
    assert_int_equal(cJSON_GetArraySize(permissions_array), 8);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "GENERIC_READ");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "GENERIC_WRITE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "GENERIC_EXECUTE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 3));
    assert_string_equal(string, "GENERIC_ALL");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 4));
    assert_string_equal(string, "DELETE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 5));
    assert_string_equal(string, "READ_CONTROL");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 6));
    assert_string_equal(string, "WRITE_DAC");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 7));
    assert_string_equal(string, "WRITE_OWNER");

    permissions_array = cJSON_GetObjectItem(user, "allowed");
    assert_int_equal(cJSON_GetArraySize(permissions_array), 9);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "SYNCHRONIZE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "READ_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "WRITE_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 3));
    assert_string_equal(string, "APPEND_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 4));
    assert_string_equal(string, "READ_EA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 5));
    assert_string_equal(string, "WRITE_EA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 6));
    assert_string_equal(string, "EXECUTE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 7));
    assert_string_equal(string, "READ_ATTRIBUTES");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 8));
    assert_string_equal(string, "WRITE_ATTRIBUTES");
}

static void test_win_perm_to_json_multiple_accounts(void **state) {
    char *input = "first (allowed): generic_read|generic_write|generic_execute,"
        " first (denied): generic_all|delete|read_control|write_dac|write_owner,"
        " second (allowed): synchronize|read_data|write_data,"
        " third (denied): append_data|read_ea|write_ea|execute|read_attributes|write_attributes";
    cJSON *output;
    cJSON *user, *permissions_array;
    char *string;

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());
    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());
    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    will_return_always(__wrap_wstr_split, 1);  // use real wstr_split

    output = win_perm_to_json(input);

    *state = output;

    assert_int_equal(cJSON_GetArraySize(output), 3);

    user = cJSON_GetArrayItem(output, 0);

    string = cJSON_GetStringValue(cJSON_GetObjectItem(user, "name"));
    assert_string_equal(string, "first");

    permissions_array = cJSON_GetObjectItem(user, "allowed");
    assert_int_equal(cJSON_GetArraySize(permissions_array), 3);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "GENERIC_READ");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "GENERIC_WRITE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "GENERIC_EXECUTE");

    permissions_array = cJSON_GetObjectItem(user, "denied");
    assert_int_equal(cJSON_GetArraySize(permissions_array), 5);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "GENERIC_ALL");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "DELETE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "READ_CONTROL");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 3));
    assert_string_equal(string, "WRITE_DAC");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 4));
    assert_string_equal(string, "WRITE_OWNER");

    user = cJSON_GetArrayItem(output, 1);

    string = cJSON_GetStringValue(cJSON_GetObjectItem(user, "name"));
    assert_string_equal(string, "second");

    permissions_array = cJSON_GetObjectItem(user, "allowed");
    assert_int_equal(cJSON_GetArraySize(permissions_array), 3);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "SYNCHRONIZE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "READ_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "WRITE_DATA");

    user = cJSON_GetArrayItem(output, 2);

    string = cJSON_GetStringValue(cJSON_GetObjectItem(user, "name"));
    assert_string_equal(string, "third");

    permissions_array = cJSON_GetObjectItem(user, "denied");
    assert_int_equal(cJSON_GetArraySize(permissions_array), 6);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "APPEND_DATA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "READ_EA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "WRITE_EA");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 3));
    assert_string_equal(string, "EXECUTE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 4));
    assert_string_equal(string, "READ_ATTRIBUTES");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 5));
    assert_string_equal(string, "WRITE_ATTRIBUTES");
}

static void test_win_perm_to_json_fragmented_acl(void **state) {
    char *input = "first (allowed): generic_read|generic_write|generic_execute,"
        " first (allowed): generic_all|delete|read_control|write_dac|write_owner,";
    cJSON *output;
    cJSON *user, *permissions_array;
    char *string;

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    will_return_always(__wrap_wstr_split, 1);  // use real wstr_split

    expect_string(__wrap__mdebug1, formatted_msg,
        "ACL [first (allowed): generic_read|generic_write|generic_execute, "
        "first (allowed): generic_all|delete|read_control|write_dac|write_owner,] fragmented. All permissions may not be displayed.");

    output = win_perm_to_json(input);

    *state = output;

    assert_int_equal(cJSON_GetArraySize(output), 1);

    user = cJSON_GetArrayItem(output, 0);

    string = cJSON_GetStringValue(cJSON_GetObjectItem(user, "name"));
    assert_string_equal(string, "first");

    permissions_array = cJSON_GetObjectItem(user, "allowed");
    assert_int_equal(cJSON_GetArraySize(permissions_array), 3);

    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 0));
    assert_string_equal(string, "GENERIC_READ");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 1));
    assert_string_equal(string, "GENERIC_WRITE");
    string = cJSON_GetStringValue(cJSON_GetArrayItem(permissions_array, 2));
    assert_string_equal(string, "GENERIC_EXECUTE");
}

// TODO: Validate this condition is required to be tested
static void test_win_perm_to_json_null_input(void **state) {
    expect_assert_failure(win_perm_to_json(NULL));
}

static void test_win_perm_to_json_unable_to_create_main_array(void **state) {
    char *input = "first (allowed): generic_read|generic_write|generic_execute,";
    cJSON *output;

    will_return(__wrap_cJSON_CreateArray, NULL);

    output = win_perm_to_json(input);

    assert_null(output);
}

static void test_win_perm_to_json_unable_to_create_sub_array(void **state) {
    char *input = "first (allowed): generic_read|generic_write|generic_execute,";
    cJSON *output;

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, NULL);

    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing a Windows permission from 'first (allowed): generic_read|generic_write|generic_execute,'.");

    output = win_perm_to_json(input);

    assert_null(output);
}

static void test_win_perm_to_json_unable_to_create_user_object(void **state) {
    char *input = "first (allowed): generic_read|generic_write|generic_execute,";
    cJSON *output;

    will_return(__wrap_cJSON_CreateObject, NULL);

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing a Windows permission from 'first (allowed): generic_read|generic_write|generic_execute,'.");

    output = win_perm_to_json(input);

    assert_null(output);
}

static void test_win_perm_to_json_incorrect_permission_format(void **state) {
    char *input = "This format is incorrect";
    cJSON *output;

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing a Windows permission from 'This format is incorrect'.");

    output = win_perm_to_json(input);

    assert_null(output);
}
static void test_win_perm_to_json_incorrect_permission_format_2(void **state) {
    char *input = "This format is incorrect (too";
    cJSON *output;

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing a Windows permission from 'This format is incorrect (too'.");

    output = win_perm_to_json(input);

    assert_null(output);
}

static void test_win_perm_to_json_error_splitting_permissions(void **state) {
    char *input = "first (allowed): generic_read|generic_write|generic_execute,";
    cJSON *output;

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    will_return_always(__wrap_wstr_split, 0);  // fail to split string

    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing a Windows permission from 'first (allowed): generic_read|generic_write|generic_execute,'.");

    output = win_perm_to_json(input);

    assert_null(output);
}

#ifdef TEST_WINAGENT
static void test_get_user_CreateFile_error_access_denied(void **state) {
    char **array = *state;

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, INVALID_HANDLE_VALUE);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    will_return(wrap_FormatMessage, "An error message");

    expect_string(__wrap__mdebug1, formatted_msg, "At get_user(C:\\a\\path): CreateFile(): An error message (5)");

    array[0] = get_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_user_CreateFile_error_sharing_violation(void **state) {
    char **array = *state;

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, INVALID_HANDLE_VALUE);

    will_return(wrap_GetLastError, ERROR_SHARING_VIOLATION);

    will_return(wrap_FormatMessage, "An error message");

    expect_string(__wrap__mdebug1, formatted_msg, "At get_user(C:\\a\\path): CreateFile(): An error message (32)");

    array[0] = get_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_user_CreateFile_error_generic(void **state) {
    char **array = *state;

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, INVALID_HANDLE_VALUE);

    will_return(wrap_GetLastError, 127);

    will_return(wrap_FormatMessage, "An error message");

    expect_string(__wrap__mwarn, formatted_msg, "At get_user(C:\\a\\path): CreateFile(): An error message (127)");

    array[0] = get_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_user_GetSecurityInfo_error(void **state) {
    char **array = *state;

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, (HANDLE)123456);

    will_return(wrap_GetSecurityInfo, ERROR_PATH_NOT_FOUND);

    expect_value(wrap_CloseHandle, hObject, (HANDLE)123456);
    will_return(wrap_CloseHandle, 0);

    will_return(wrap_ConvertSidToStringSid, NULL);
    will_return(wrap_ConvertSidToStringSid, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "The user's SID could not be extracted.");

    will_return(wrap_GetLastError, ERROR_INVALID_SID);

    expect_string(__wrap__merror, formatted_msg, "GetSecurityInfo error = 1337");

    array[0] = get_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_user_LookupAccountSid_error(void **state) {
    char **array = *state;

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, (HANDLE)123456);

    will_return(wrap_GetSecurityInfo, ERROR_SUCCESS);

    expect_value(wrap_CloseHandle, hObject, (HANDLE)123456);
    will_return(wrap_CloseHandle, 0);

    will_return(wrap_ConvertSidToStringSid, "sid");
    will_return(wrap_ConvertSidToStringSid, 1);

    will_return(wrap_LookupAccountSid, "accountName");
    will_return(wrap_LookupAccountSid, "domainName");
    will_return(wrap_LookupAccountSid, 0);

    will_return(wrap_GetLastError, ERROR_INVALID_SID);

    expect_string(__wrap__merror, formatted_msg, "Error in LookupAccountSid.");

    array[0] = get_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
    assert_string_equal(array[1], "sid");
}

static void test_get_user_LookupAccountSid_error_none_mapped(void **state) {
    char **array = *state;

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, (HANDLE)123456);

    will_return(wrap_GetSecurityInfo, ERROR_SUCCESS);

    expect_value(wrap_CloseHandle, hObject, (HANDLE)123456);
    will_return(wrap_CloseHandle, 0);

    will_return(wrap_ConvertSidToStringSid, "sid");
    will_return(wrap_ConvertSidToStringSid, 1);

    will_return(wrap_LookupAccountSid, "accountName");
    will_return(wrap_LookupAccountSid, "domainName");
    will_return(wrap_LookupAccountSid, 0);

    will_return(wrap_GetLastError, ERROR_NONE_MAPPED);

    expect_string(__wrap__mdebug1, formatted_msg, "Account owner not found for file 'C:\\a\\path'");

    array[0] = get_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
    assert_string_equal(array[1], "sid");
}

static void test_get_user_success(void **state) {
    char **array = *state;

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, (HANDLE)123456);

    will_return(wrap_GetSecurityInfo, ERROR_SUCCESS);

    expect_value(wrap_CloseHandle, hObject, (HANDLE)123456);
    will_return(wrap_CloseHandle, 0);

    will_return(wrap_ConvertSidToStringSid, "sid");
    will_return(wrap_ConvertSidToStringSid, 1);

    will_return(wrap_LookupAccountSid, "accountName");
    will_return(wrap_LookupAccountSid, "domainName");
    will_return(wrap_LookupAccountSid, 1);

    array[0] = get_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "accountName");
    assert_string_equal(array[1], "sid");
}

void test_w_get_account_info_LookupAccountSid_error_insufficient_buffer(void **state) {
    char **array = *state;
    int ret;
    SID input;

    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Name size
    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Domain size
    will_return(wrap_LookupAccountSid, 0);

    will_return(wrap_GetLastError, ERROR_INVALID_NAME);
    will_return(wrap_GetLastError, ERROR_INVALID_NAME);

    ret = w_get_account_info(&input, &array[0], &array[1]);

    assert_int_equal(ret, ERROR_INVALID_NAME);
}

void test_w_get_account_info_LookupAccountSid_error_second_call(void **state) {
    char **array = *state;
    int ret;
    SID input;

    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Name size
    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Domain size
    will_return(wrap_LookupAccountSid, 0);

    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    will_return(wrap_LookupAccountSid, "accountName");
    will_return(wrap_LookupAccountSid, "domainName");
    will_return(wrap_LookupAccountSid, 0);

    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    ret = w_get_account_info(&input, &array[0], &array[1]);

    assert_int_equal(ret, ERROR_INSUFFICIENT_BUFFER);
}

void test_w_get_account_info_success(void **state) {
    char **array = *state;
    int ret;
    SID input;

    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Name size
    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Domain size
    will_return(wrap_LookupAccountSid, 1);

    will_return(wrap_LookupAccountSid, "accountName");
    will_return(wrap_LookupAccountSid, "domainName");
    will_return(wrap_LookupAccountSid, 1);

    ret = w_get_account_info(&input, &array[0], &array[1]);

    assert_int_equal(ret, 0);
    assert_string_equal(array[0], "accountName");
    assert_string_equal(array[1], "domainName");
}

void test_copy_ace_info_invalid_ace(void **state) {
    int ret;
    char perm[OS_SIZE_1024];
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = SYSTEM_AUDIT_ACE_TYPE,
    };

    expect_string(__wrap__mdebug2, formatted_msg, "Invalid ACE type.");

    ret = copy_ace_info(&ace, perm, OS_SIZE_1024);

    assert_int_equal(ret, 0);
}

void test_copy_ace_info_invalid_sid(void **state) {
    int ret;
    char perm[OS_SIZE_1024];
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = ACCESS_DENIED_ACE_TYPE,
    };

    will_return(wrap_IsValidSid, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Invalid SID found in ACE.");

    ret = copy_ace_info(&ace, perm, OS_SIZE_1024);

    assert_int_equal(ret, 0);
}

void test_copy_ace_info_no_information_from_account_or_sid(void **state) {
    int ret;
    char perm[OS_SIZE_1024];
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = ACCESS_ALLOWED_ACE_TYPE,
    };

    will_return(wrap_IsValidSid, 1);

    // Inside w_get_account_info
    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Name size
    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Domain size
    will_return(wrap_LookupAccountSid, 0);

    will_return(wrap_GetLastError, ERROR_INVALID_NAME);
    will_return(wrap_GetLastError, ERROR_INVALID_NAME);

    expect_string(__wrap__mdebug2, formatted_msg, "No information could be extracted from the account linked to the SID. Error: 123.");

    will_return(wrap_ConvertSidToStringSid, NULL);
    will_return(wrap_ConvertSidToStringSid, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Could not extract the SID.");

    ret = copy_ace_info(&ace, perm, OS_SIZE_1024);

    assert_int_equal(ret, 0);
}

void test_copy_ace_info_success(void **state) {
    int ret;
    char perm[OS_SIZE_1024];
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = ACCESS_ALLOWED_ACE_TYPE,
        .Mask = 123456,
    };

    will_return(wrap_IsValidSid, 1);

    // Inside w_get_account_info
    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Name size
    will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Domain size
    will_return(wrap_LookupAccountSid, 1);

    will_return(wrap_LookupAccountSid, "accountName");
    will_return(wrap_LookupAccountSid, "domainName");
    will_return(wrap_LookupAccountSid, 1);

    ret = copy_ace_info(&ace, perm, OS_SIZE_1024);

    assert_int_equal(ret, 21);
    assert_string_equal(perm, "|accountName,0,123456");
}

void test_w_get_file_permissions_GetFileSecurity_error_on_size(void **state) {
    char permissions[OS_SIZE_1024];
    int ret;

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, 0);
    will_return(wrap_GetFileSecurity, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);
    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", permissions, OS_SIZE_1024);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
}

void test_w_get_file_permissions_GetFileSecurity_error(void **state) {
    char permissions[OS_SIZE_1024];
    int ret;

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, OS_SIZE_1024);
    will_return(wrap_GetFileSecurity, 1);

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, NULL);
    will_return(wrap_GetFileSecurity, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", permissions, OS_SIZE_1024);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
}

void test_w_get_file_permissions_GetSecurityDescriptorDacl_error(void **state) {
    char permissions[OS_SIZE_1024];
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, OS_SIZE_1024);
    will_return(wrap_GetFileSecurity, 1);

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, &sec_desc);
    will_return(wrap_GetFileSecurity, 1);

    will_return(wrap_GetSecurityDescriptorDacl, FALSE);
    will_return(wrap_GetSecurityDescriptorDacl, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "The DACL of the file could not be obtained.");

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", permissions, OS_SIZE_1024);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
}

void test_w_get_file_permissions_no_dacl(void **state) {
    char permissions[OS_SIZE_1024];
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, OS_SIZE_1024);
    will_return(wrap_GetFileSecurity, 1);

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, &sec_desc);
    will_return(wrap_GetFileSecurity, 1);

    will_return(wrap_GetSecurityDescriptorDacl, FALSE);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "'C:\\a\\path' has no DACL, so no permits can be extracted.");

    ret = w_get_file_permissions("C:\\a\\path", permissions, OS_SIZE_1024);

    assert_int_equal(ret, 0);
}

void test_w_get_file_permissions_GetAclInformation_error(void **state) {
    char permissions[OS_SIZE_1024];
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, OS_SIZE_1024);
    will_return(wrap_GetFileSecurity, 1);

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, &sec_desc);
    will_return(wrap_GetFileSecurity, 1);

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, NULL);
    will_return(wrap_GetAclInformation, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "No information could be obtained from the ACL.");

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", permissions, OS_SIZE_1024);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
}

void test_w_get_file_permissions_GetAce_error(void **state) {
    char permissions[OS_SIZE_1024];
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, OS_SIZE_1024);
    will_return(wrap_GetFileSecurity, 1);

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, &sec_desc);
    will_return(wrap_GetFileSecurity, 1);

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, NULL);
    will_return(wrap_GetAce, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "ACE number 0 could not be obtained.");

    ret = w_get_file_permissions("C:\\a\\path", permissions, OS_SIZE_1024);

    assert_int_equal(ret, -2);
    assert_string_equal(permissions, "");
}

void test_w_get_file_permissions_success(void **state) {
    char permissions[OS_SIZE_1024];
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = {
        .AceCount = 1,
    };
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = ACCESS_ALLOWED_ACE_TYPE,
    };

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, OS_SIZE_1024);
    will_return(wrap_GetFileSecurity, 1);

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, &sec_desc);
    will_return(wrap_GetFileSecurity, 1);

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, &ace);
    will_return(wrap_GetAce, 1);

    // Inside copy_ace_info
    {
        will_return(wrap_IsValidSid, 1);

        // Inside w_get_account_info
        will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Name size
        will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Domain size
        will_return(wrap_LookupAccountSid, 1);

        will_return(wrap_LookupAccountSid, "accountName");
        will_return(wrap_LookupAccountSid, "domainName");
        will_return(wrap_LookupAccountSid, 1);
    }

    ret = w_get_file_permissions("C:\\a\\path", permissions, OS_SIZE_1024);

    assert_int_equal(ret, 0);
    assert_string_equal(permissions, "|accountName,0,0");
}

void test_w_get_file_permissions_copy_ace_info_error(void **state) {
    char permissions[OS_SIZE_1024];
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = {
        .AceCount = 1,
    };
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = SYSTEM_AUDIT_ACE_TYPE,
    };

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, OS_SIZE_1024);
    will_return(wrap_GetFileSecurity, 1);

    expect_string(wrap_GetFileSecurity, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileSecurity, &sec_desc);
    will_return(wrap_GetFileSecurity, 1);

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, &ace);
    will_return(wrap_GetAce, 1);

    // Inside copy_ace_info
    expect_string(__wrap__mdebug2, formatted_msg, "Invalid ACE type.");

    expect_string(__wrap__mdebug1, formatted_msg,
        "The parameters of ACE number 0 from 'C:\\a\\path' could not be extracted. 1024 bytes remaining.");

    ret = w_get_file_permissions("C:\\a\\path", permissions, OS_SIZE_1024);

    assert_int_equal(ret, 0);
    assert_string_equal(permissions, "");
}

void test_w_get_file_attrs_error(void **state) {
    int ret;

    expect_string(wrap_GetFileAttributesA, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileAttributesA, INVALID_FILE_ATTRIBUTES);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug2, formatted_msg, "The attributes for 'C:\\a\\path' could not be obtained. Error '5'.");

    ret = w_get_file_attrs("C:\\a\\path");

    assert_int_equal(ret, 0);
}

void test_w_get_file_attrs_success(void **state) {
    int ret;

    expect_string(wrap_GetFileAttributesA, lpFileName, "C:\\a\\path");
    will_return(wrap_GetFileAttributesA, 123456);

    ret = w_get_file_attrs("C:\\a\\path");

    assert_int_equal(ret, 123456);
}

void test_w_directory_exists_null_path(void **state) {
    unsigned int ret;

    ret = w_directory_exists(NULL);

    assert_null(ret);
}

void test_w_directory_exists_error_getting_attrs(void **state) {
    unsigned int ret;

    // Inside w_get_file_attrs
    {
        expect_string(wrap_GetFileAttributesA, lpFileName, "C:\\a\\path");
        will_return(wrap_GetFileAttributesA, INVALID_FILE_ATTRIBUTES);

        will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

        expect_string(__wrap__mdebug2, formatted_msg,
            "The attributes for 'C:\\a\\path' could not be obtained. Error '5'.");
    }

    ret = w_directory_exists("C:\\a\\path");

    assert_null(ret);
}

void test_w_directory_exists_path_is_not_dir(void **state) {
    unsigned int ret;

    // Inside w_get_file_attrs
    {
        expect_string(wrap_GetFileAttributesA, lpFileName, "C:\\a\\path");
        will_return(wrap_GetFileAttributesA, FILE_ATTRIBUTE_NORMAL);
    }

    ret = w_directory_exists("C:\\a\\path");

    assert_null(ret);
}

void test_w_directory_exists_path_is_dir(void **state) {
    unsigned int ret;

    // Inside w_get_file_attrs
    {
        expect_string(wrap_GetFileAttributesA, lpFileName, "C:\\a\\path");
        will_return(wrap_GetFileAttributesA, FILE_ATTRIBUTE_DIRECTORY);
    }

    ret = w_directory_exists("C:\\a\\path");

    assert_non_null(ret);
}
#endif


int main(int argc, char *argv[]) {
    const struct CMUnitTest tests[] = {
        /* delete_target_file tests */
        cmocka_unit_test(test_delete_target_file_success),
        cmocka_unit_test(test_delete_target_file_rmdir_ex_error),
#ifdef TEST_WINAGENT
        cmocka_unit_test(test_delete_target_file_invalid_path),
#endif

        /* escape_syscheck_field tests */
        cmocka_unit_test_teardown(test_escape_syscheck_field_escape_all, teardown_string),
        cmocka_unit_test_teardown(test_escape_syscheck_field_null_input, teardown_string),

        /* normalize_path tests */
        cmocka_unit_test_teardown(test_normalize_path_success, teardown_string),
        cmocka_unit_test_teardown(test_normalize_path_linux_dir, teardown_string),
        cmocka_unit_test(test_normalize_path_null_input),

        /* remove_empty_folders tests */
        cmocka_unit_test(test_remove_empty_folders_success),
        cmocka_unit_test(test_remove_empty_folders_recursive_success),
        cmocka_unit_test(test_remove_empty_folders_null_input),
        cmocka_unit_test(test_remove_empty_folders_relative_path),
        cmocka_unit_test(test_remove_empty_folders_absolute_path),
        cmocka_unit_test(test_remove_empty_folders_non_empty_dir),
        cmocka_unit_test(test_remove_empty_folders_error_removing_dir),

#if defined(TEST_SERVER)
        /* sk_decode_sum tests */
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_decode, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_deleted_file, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_perm, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_missing_separator, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_uid, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_gid, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_md5, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_sha1, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_new_fields, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_win_perm_string, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_win_perm_encoded, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_gname, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_uname, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_mtime, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_inode, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_sha256, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_empty_sha256, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_no_attributes, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_non_numeric_attributes, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_win_encoded_attributes, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_empty, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_user_name, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_group_id, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_group_name, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_process_name, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_audit_uid, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_audit_name, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_effective_uid, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_effective_name, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_ppid, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_process_id, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_tag, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_symbolic_path, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_no_inode, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_all_fields, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_all_fields_silent, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_null_ppid, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_null_sum, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_sum_extra_data_null_c_sum, setup_sk_decode, teardown_sk_decode),

        /* sk_decode_extradata tests */
        cmocka_unit_test_setup_teardown(test_sk_decode_extradata_null_sum, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_extradata_null_c_sum, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_extradata_no_changes, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_extradata_no_date_alert, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_extradata_no_sym_path, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_decode_extradata_all_fields, setup_sk_decode, teardown_sk_decode),

        /* sk_fill_event tests */
        cmocka_unit_test_setup_teardown(test_sk_fill_event_full_event, setup_sk_fill_event, teardown_sk_fill_event),
        cmocka_unit_test_setup_teardown(test_sk_fill_event_empty_event, setup_sk_fill_event, teardown_sk_fill_event),
        cmocka_unit_test_setup_teardown(test_sk_fill_event_win_perm, setup_sk_fill_event, teardown_sk_fill_event),
        cmocka_unit_test_setup_teardown(test_sk_fill_event_null_eventinfo, setup_sk_fill_event, teardown_sk_fill_event),
        cmocka_unit_test_setup_teardown(test_sk_fill_event_null_f_name, setup_sk_fill_event, teardown_sk_fill_event),
        cmocka_unit_test_setup_teardown(test_sk_fill_event_null_sum, setup_sk_fill_event, teardown_sk_fill_event),

        /* sk_build_sum tests */
        cmocka_unit_test_setup_teardown(test_sk_build_sum_full_message, setup_sk_build_sum, teardown_sk_build_sum),
        cmocka_unit_test_setup_teardown(test_sk_build_sum_skip_fields_message, setup_sk_build_sum, teardown_sk_build_sum),
        cmocka_unit_test_setup_teardown(test_sk_build_sum_win_perm, setup_sk_build_sum, teardown_sk_build_sum),
        cmocka_unit_test_setup_teardown(test_sk_build_sum_insufficient_buffer_size, setup_sk_build_sum, teardown_sk_build_sum),
        cmocka_unit_test_setup_teardown(test_sk_build_sum_null_sum, setup_sk_build_sum, teardown_sk_build_sum),
        cmocka_unit_test_setup_teardown(test_sk_build_sum_null_output, setup_sk_build_sum, teardown_sk_build_sum),

        /* sk_sum_clean tests */
        cmocka_unit_test_setup_teardown(test_sk_sum_clean_full_message, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_sum_clean_shortest_valid_message, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_sum_clean_invalid_message, setup_sk_decode, teardown_sk_decode),
        cmocka_unit_test_setup_teardown(test_sk_sum_clean_null_sum, setup_sk_decode, teardown_sk_decode),
#endif
#ifndef TEST_WINAGENT
        /* unescape_syscheck_field tests */
        cmocka_unit_test_setup_teardown(test_unescape_syscheck_field_escaped_chars, setup_unescape_syscheck_field, teardown_unescape_syscheck_field),
        cmocka_unit_test_setup_teardown(test_unescape_syscheck_field_no_escaped_chars, setup_unescape_syscheck_field, teardown_unescape_syscheck_field),
        cmocka_unit_test_setup_teardown(test_unescape_syscheck_null_input, setup_unescape_syscheck_field, teardown_unescape_syscheck_field),
        cmocka_unit_test_setup_teardown(test_unescape_syscheck_empty_string, setup_unescape_syscheck_field, teardown_unescape_syscheck_field),

        /* get_user tests */
        cmocka_unit_test_teardown(test_get_user_success, teardown_string),
        cmocka_unit_test_teardown(test_get_user_uid_not_found, teardown_string),
        cmocka_unit_test_teardown(test_get_user_error, teardown_string),

        /* get_group tests */
        cmocka_unit_test(test_get_group_success),
        cmocka_unit_test(test_get_group_failure),

        /* ag_send_syscheck tests */
        cmocka_unit_test(test_ag_send_syscheck_success),
        cmocka_unit_test(test_ag_send_syscheck_unable_to_connect),
        cmocka_unit_test(test_ag_send_syscheck_error_sending_message),
#else
        cmocka_unit_test(test_get_group),
        cmocka_unit_test(test_ag_send_syscheck),
#endif

        /* decode_win_attributes tests */
        cmocka_unit_test(test_decode_win_attributes_all_attributes),
        cmocka_unit_test(test_decode_win_attributes_no_attributes),
        cmocka_unit_test(test_decode_win_attributes_some_attributes),

        /* decode_win_permissions tests */
        cmocka_unit_test_teardown(test_decode_win_permissions_success_all_permissions, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_success_no_permissions, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_success_some_permissions, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_success_multiple_accounts, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_fail_no_account_name, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_fail_no_access_type, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_fail_wrong_format, teardown_string),

        /* attrs_to_json tests */
        cmocka_unit_test_teardown(test_attrs_to_json_single_attribute, teardown_cjson),
        cmocka_unit_test_teardown(test_attrs_to_json_multiple_attributes, teardown_cjson),
        cmocka_unit_test_teardown(test_attrs_to_json_unable_to_create_json_array, teardown_cjson),
        cmocka_unit_test_teardown(test_attrs_to_json_null_attributes, teardown_cjson),

        /* win_perm_to_json tests*/
        cmocka_unit_test_teardown(test_win_perm_to_json_all_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_some_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_no_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_allowed_denied_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_multiple_accounts, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_fragmented_acl, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_null_input, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_unable_to_create_main_array, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_unable_to_create_sub_array, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_unable_to_create_user_object, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_incorrect_permission_format, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_incorrect_permission_format_2, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_error_splitting_permissions, teardown_cjson),

#ifdef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_get_user_CreateFile_error_access_denied, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_user_CreateFile_error_sharing_violation, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_user_CreateFile_error_generic, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_user_GetSecurityInfo_error, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_user_LookupAccountSid_error, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_user_LookupAccountSid_error_none_mapped, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_user_success, setup_string_array, teardown_string_array),

        cmocka_unit_test_setup_teardown(test_w_get_account_info_LookupAccountSid_error_insufficient_buffer, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_w_get_account_info_LookupAccountSid_error_second_call, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_w_get_account_info_success, setup_string_array, teardown_string_array),

        cmocka_unit_test(test_copy_ace_info_invalid_ace),
        cmocka_unit_test(test_copy_ace_info_invalid_sid),
        cmocka_unit_test(test_copy_ace_info_no_information_from_account_or_sid),
        cmocka_unit_test(test_copy_ace_info_success),

        cmocka_unit_test(test_w_get_file_permissions_GetFileSecurity_error_on_size),
        cmocka_unit_test(test_w_get_file_permissions_GetFileSecurity_error),
        cmocka_unit_test(test_w_get_file_permissions_GetSecurityDescriptorDacl_error),
        cmocka_unit_test(test_w_get_file_permissions_no_dacl),
        cmocka_unit_test(test_w_get_file_permissions_GetAclInformation_error),
        cmocka_unit_test(test_w_get_file_permissions_GetAce_error),
        cmocka_unit_test(test_w_get_file_permissions_success),
        cmocka_unit_test(test_w_get_file_permissions_copy_ace_info_error),

        cmocka_unit_test(test_w_get_file_attrs_error),
        cmocka_unit_test(test_w_get_file_attrs_success),

        cmocka_unit_test(test_w_directory_exists_null_path),
        cmocka_unit_test(test_w_directory_exists_error_getting_attrs),
        cmocka_unit_test(test_w_directory_exists_path_is_not_dir),
        cmocka_unit_test(test_w_directory_exists_path_is_dir),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
