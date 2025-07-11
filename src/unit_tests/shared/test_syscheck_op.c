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

#include "../headers/syscheck_op.h"
#include "../analysisd/eventinfo.h"

#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/posix/grp_wrappers.h"
#include "../wrappers/posix/pwd_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/string_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/privsep_op_wrappers.h"
#include "../wrappers/wazuh/shared/utf8_winapi_wrapper_wrappers.h"
#include "../wrappers/common.h"

#ifdef TEST_WINAGENT
#include "../wrappers/wazuh/syscheckd/syscom_wrappers.h"
#include "../wrappers/windows/sddl_wrappers.h"
#include "../wrappers/windows/winreg_wrappers.h"
#include "../wrappers/windows/aclapi_wrappers.h"
#include "../wrappers/windows/winbase_wrappers.h"
#include "../wrappers/windows/fileapi_wrappers.h"
#include "../wrappers/windows/handleapi_wrappers.h"
#include "../wrappers/windows/errhandlingapi_wrappers.h"
#include "../wrappers/windows/securitybaseapi_wrappers.h"
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

typedef struct __registry_group_information {
    char *name;
    char *id;
} registry_group_information_t;

#ifdef TEST_WINAGENT
#define BASE_WIN_ALLOWED_ACE "[" \
    "\"delete\"," \
    "\"read_control\"," \
    "\"write_dac\"," \
    "\"write_owner\"," \
    "\"synchronize\"," \
    "\"read_data\"," \
    "\"write_data\"," \
    "\"append_data\"," \
    "\"read_ea\"," \
    "\"write_ea\"," \
    "\"execute\"," \
    "\"read_attributes\"," \
    "\"write_attributes\"" \
"]"

#define BASE_WIN_DENIED_ACE "[" \
    "\"read_control\"," \
    "\"synchronize\"," \
    "\"read_data\"," \
    "\"read_ea\"," \
    "\"execute\"," \
    "\"read_attributes\"" \
"]"

#define BASE_WIN_ACE "{" \
    "\"name\": \"Users\"," \
    "\"allowed\": " BASE_WIN_ALLOWED_ACE "," \
    "\"denied\": " BASE_WIN_DENIED_ACE \
"}"

#define BASE_WIN_SID "S-1-5-32-636"

static cJSON *create_win_permissions_object() {
    static const char * const BASE_WIN_PERMS = "{\"" BASE_WIN_SID "\": " BASE_WIN_ACE "}";
    return cJSON_Parse(BASE_WIN_PERMS);
}
#endif

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
    test_mode = 1;

    return 0;
}

static int teardown_string_array(void **state) {
    char **array = *state;

    free_strarray(array);
    test_mode = 0;

    return 0;
}

static int setup_get_registry_group(void **state) {
    registry_group_information_t *group_information = (registry_group_information_t *)
                                                        calloc(1, sizeof(registry_group_information_t));

    if (group_information == NULL) {
        return -1;
    }

    group_information->name = (char *)calloc(OS_SIZE_6144 + 1, sizeof(char));
    group_information->id = (char *)calloc(OS_SIZE_6144 + 1, sizeof(char));

    if (group_information->name == NULL || group_information->id == NULL) {
        return -1;
    }

    *state = group_information;

    return 0;
}

static int teardown_get_registry_group(void **state) {
    registry_group_information_t *group_information = *state;

    free(group_information->name);
    free(group_information->id);
    free(group_information);

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
    char *test_string = strdup("unchanged/path");

    if(test_string != NULL) {
        *state = test_string;
    } else {
        fail();
    }

    normalize_path(test_string);

    assert_string_equal(test_string, "unchanged/path");
}

static void test_normalize_path_null_input(void **state) {
    char *test_string = NULL;

    expect_assert_failure(normalize_path(test_string));
}

/* remove_empty_folders tests */
static void test_remove_empty_folders_success(void **state) {
#ifndef TEST_WINAGENT
    char *input = "queue/diff/local/test-dir/";
    char *first_subdir = "queue/diff/local/test-dir";
    char *second_subdir = "queue/diff/local";
#else
    char *input = "queue/diff\\local\\test-dir\\";
    char *first_subdir = "queue/diff\\local\\test-dir";
    char *second_subdir = "queue/diff\\local";
#endif
    int ret = -1;
    char message[OS_SIZE_1024];
    char **mock_directory_content;

    if(mock_directory_content = calloc(2, sizeof(char*)), !mock_directory_content)
        fail();

    mock_directory_content[0] = strdup("some-file.tmp");
    mock_directory_content[1] = NULL;

    expect_wreaddir_call(first_subdir, NULL);

    snprintf(message, OS_SIZE_1024, "Removing empty directory '%s'.", first_subdir);
    expect_string(__wrap__mdebug1, formatted_msg, message);

    expect_rmdir_ex_call(first_subdir, 0);

    expect_wreaddir_call(second_subdir, mock_directory_content);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_recursive_success(void **state) {
#ifndef TEST_WINAGENT
    char *input = "queue/diff/local/dir1/dir2/";
    static const char *parent_dirs[] = {
        "queue/diff/local/dir1/dir2",
        "queue/diff/local/dir1",
        "queue/diff/local"
    };
#else
    char *input = "queue/diff\\local\\dir1\\dir2\\";
    static const char *parent_dirs[] = {
        "queue/diff\\local\\dir1\\dir2",
        "queue/diff\\local\\dir1",
        "queue/diff\\local"
    };
#endif
    char messages[3][OS_SIZE_1024];
    int ret = -1;
    char **mock_directory_content;

    if(mock_directory_content = calloc(2, sizeof(char*)), !mock_directory_content)
        fail();

    mock_directory_content[0] = strdup("some-file.tmp");
    mock_directory_content[1] = NULL;

    snprintf(messages[0], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[0]);
    snprintf(messages[1], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[1]);

    // Remove dir2
    expect_wreaddir_call(parent_dirs[0], NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);

    expect_rmdir_ex_call(parent_dirs[0], 0);

    // Remove dir1
    expect_wreaddir_call(parent_dirs[1], NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);

    expect_rmdir_ex_call(parent_dirs[1], 0);

    expect_wreaddir_call(parent_dirs[2], mock_directory_content);

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

    expect_wreaddir_call(parent_dirs[0], NULL);
    expect_wreaddir_call(parent_dirs[1], NULL);
    expect_wreaddir_call(parent_dirs[2], NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[2]);

    expect_rmdir_ex_call(parent_dirs[0], 0);
    expect_rmdir_ex_call(parent_dirs[1], 0);
    expect_rmdir_ex_call(parent_dirs[2], 0);

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

    expect_wreaddir_call(parent_dirs[0], NULL);
    expect_wreaddir_call(parent_dirs[1], NULL);
    expect_wreaddir_call(parent_dirs[2], NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[2]);

    expect_rmdir_ex_call(parent_dirs[0], 0);
    expect_rmdir_ex_call(parent_dirs[1], 0);
    expect_rmdir_ex_call(parent_dirs[2], 0);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_non_empty_dir(void **state) {
#ifndef TEST_WINAGENT
    char *input = "queue/diff/local/test-dir/";
    static const char *parent_dir = "queue/diff/local/test-dir";
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

    expect_wreaddir_call(parent_dir, subdir);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_error_removing_dir(void **state) {
#ifndef TEST_WINAGENT
    char *input = "queue/diff/local/test-dir/";
    static const char *parent_dir = "queue/diff/local/test-dir";
#else
    char *input = "queue/diff\\local\\test-dir\\";
    static const char *parent_dir = "queue/diff\\local\\test-dir";
#endif
    int ret = -1;
    char remove_dir_message[OS_SIZE_1024];
    char dir_not_deleted_message[OS_SIZE_1024];

    expect_wreaddir_call(parent_dir, NULL);

    snprintf(remove_dir_message, OS_SIZE_1024, "Removing empty directory '%s'.", parent_dir);
    expect_string(__wrap__mdebug1, formatted_msg, remove_dir_message);

    expect_rmdir_ex_call(parent_dir, -1);

    snprintf(dir_not_deleted_message, OS_SIZE_1024,
        "Empty directory '%s' couldn't be deleted. ('Directory not empty')", parent_dir);
    expect_string(__wrap__mwarn, formatted_msg, dir_not_deleted_message);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, -1);
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

    assert_string_equal(data->lf->fields[FIM_FILE].value, "f_name");
    assert_string_equal(data->lf->fields[FIM_FILE].value, "f_name");
    assert_string_equal(data->lf->fields[FIM_SIZE].value, "size");
    assert_string_equal(data->lf->fields[FIM_PERM].value, "361100");
    assert_string_equal(data->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(data->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(data->lf->fields[FIM_MD5].value, "md5");
    assert_string_equal(data->lf->fields[FIM_SHA1].value, "sha1");
    assert_string_equal(data->lf->fields[FIM_UNAME].value, "uname");
    assert_string_equal(data->lf->fields[FIM_GNAME].value, "gname");
    assert_string_equal(data->lf->fields[FIM_MTIME].value, "2345678");
    assert_string_equal(data->lf->fields[FIM_INODE].value, "3456789");
    assert_string_equal(data->lf->fields[FIM_SHA256].value, "sha256");
    assert_string_equal(data->lf->fields[FIM_ATTRS].value, "attributes");
    assert_string_equal(data->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(data->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(data->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(data->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(data->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(data->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(data->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(data->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(data->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");
    assert_string_equal(data->lf->fields[FIM_PPID].value, "ppid");
    assert_string_equal(data->lf->fields[FIM_PROC_ID].value, "process_id");

    assert_string_equal(data->lf->fields[FIM_TAG].value, "tag");

    assert_string_equal(data->lf->fields[FIM_SYM_PATH].value, "symbolic_path");
}

static void test_sk_fill_event_empty_event(void **state) {
    sk_fill_event_t *data = *state;

    data->f_name = strdup("f_name");

    sk_fill_event(data->lf, data->f_name, data->sum);

    assert_string_equal(data->lf->fields[FIM_FILE].value, "f_name");
    assert_null(data->lf->fields[FIM_SIZE].value);
    assert_null(data->lf->fields[FIM_PERM].value);
    assert_null(data->lf->fields[FIM_UID].value);
    assert_null(data->lf->fields[FIM_GID].value);
    assert_null(data->lf->fields[FIM_MD5].value);
    assert_null(data->lf->fields[FIM_SHA1].value);
    assert_null(data->lf->fields[FIM_UNAME].value);
    assert_null(data->lf->fields[FIM_GNAME].value);
    assert_null(data->lf->fields[FIM_MTIME].value);
    assert_null(data->lf->fields[FIM_INODE].value);
    assert_null(data->lf->fields[FIM_SHA256].value);
    assert_null(data->lf->fields[FIM_ATTRS].value);
    assert_null(data->lf->fields[FIM_USER_ID].value);
    assert_null(data->lf->fields[FIM_USER_NAME].value);
    assert_null(data->lf->fields[FIM_GROUP_ID].value);
    assert_null(data->lf->fields[FIM_GROUP_NAME].value);
    assert_null(data->lf->fields[FIM_PROC_NAME].value);
    assert_null(data->lf->fields[FIM_AUDIT_ID].value);
    assert_null(data->lf->fields[FIM_AUDIT_NAME].value);
    assert_null(data->lf->fields[FIM_EFFECTIVE_UID].value);
    assert_null(data->lf->fields[FIM_EFFECTIVE_NAME].value);
    assert_null(data->lf->fields[FIM_PPID].value);
    assert_null(data->lf->fields[FIM_PROC_ID].value);

    assert_null(data->lf->fields[FIM_TAG].value);

    assert_null(data->lf->fields[FIM_SYM_PATH].value);
}

static void test_sk_fill_event_win_perm(void **state) {
    sk_fill_event_t *data = *state;

    data->f_name = strdup("f_name");

    data->sum->win_perm = "win_perm";

    sk_fill_event(data->lf, data->f_name, data->sum);

    assert_string_equal(data->lf->fields[FIM_FILE].value, "f_name");
    assert_null(data->lf->fields[FIM_SIZE].value);
    assert_string_equal(data->lf->fields[FIM_PERM].value, "win_perm");
    assert_null(data->lf->fields[FIM_UID].value);
    assert_null(data->lf->fields[FIM_GID].value);
    assert_null(data->lf->fields[FIM_MD5].value);
    assert_null(data->lf->fields[FIM_SHA1].value);
    assert_null(data->lf->fields[FIM_UNAME].value);
    assert_null(data->lf->fields[FIM_GNAME].value);
    assert_null(data->lf->fields[FIM_MTIME].value);
    assert_null(data->lf->fields[FIM_INODE].value);
    assert_null(data->lf->fields[FIM_SHA256].value);
    assert_null(data->lf->fields[FIM_ATTRS].value);
    assert_null(data->lf->fields[FIM_USER_ID].value);
    assert_null(data->lf->fields[FIM_USER_NAME].value);
    assert_null(data->lf->fields[FIM_GROUP_ID].value);
    assert_null(data->lf->fields[FIM_GROUP_NAME].value);
    assert_null(data->lf->fields[FIM_PROC_NAME].value);
    assert_null(data->lf->fields[FIM_AUDIT_ID].value);
    assert_null(data->lf->fields[FIM_AUDIT_NAME].value);
    assert_null(data->lf->fields[FIM_EFFECTIVE_UID].value);
    assert_null(data->lf->fields[FIM_EFFECTIVE_NAME].value);
    assert_null(data->lf->fields[FIM_PPID].value);
    assert_null(data->lf->fields[FIM_PROC_ID].value);

    assert_null(data->lf->fields[FIM_TAG].value);

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

    expect_string(__wrap__mdebug2, formatted_msg, "Failed getting user_name for uid 1: (2): 'No such file or directory'\n");

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
    char *output;

    will_return(__wrap_sysconf, -1);

    expect_value(__wrap_w_getgrgid, gid, 1000);
    will_return(__wrap_w_getgrgid, &group);
    will_return(__wrap_w_getgrgid, NULL); // We don't care about member buffers
    will_return(__wrap_w_getgrgid, 1); // Success

    output = get_group(1000);

    assert_string_equal(output, group.gr_name);

    free(output);
}

static void test_get_group_no_group(void **state) {
    const char *output;

    errno = 0;

    will_return(__wrap_sysconf, 8);

    expect_value(__wrap_w_getgrgid, gid, 1000);
    will_return(__wrap_w_getgrgid, NULL);
    will_return(__wrap_w_getgrgid, NULL); // We don't care about member buffers
    will_return(__wrap_w_getgrgid, 0); // Fail

    expect_string(__wrap__mdebug2, formatted_msg, "Group with gid '1000' not found.\n");

    output = get_group(1000);

    assert_null(output);
}

static void test_get_group_error(void **state) {
    const char *output;

    errno = ENOENT;

    will_return(__wrap_sysconf, 8);

    expect_value(__wrap_w_getgrgid, gid, 1000);
    will_return(__wrap_w_getgrgid, NULL);
    will_return(__wrap_w_getgrgid, NULL); // We don't care about member buffers
    will_return(__wrap_w_getgrgid, 0); // Fail

    expect_string(__wrap__mdebug2, formatted_msg, "Failed getting group_name for gid 1000: (2): 'No such file or directory'\n");

    output = get_group(1000);

    assert_null(output);
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

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
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

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);

    will_return(__wrap_OS_ConnectUnixDomain, OS_SOCKTERR);

    errno = EADDRNOTAVAIL;

    expect_string(__wrap__mwarn, formatted_msg, "dbsync: cannot connect to syscheck: Cannot assign requested address (99)");

    ag_send_syscheck(input);

    errno = 0;
}
static void test_ag_send_syscheck_error_sending_message(void **state) {
    char *input = "This is a mock message, it wont be sent anywhere";

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);

    will_return(__wrap_OS_ConnectUnixDomain, 1234);

    expect_value(__wrap_OS_SendSecureTCP, sock, 1234);
    expect_value(__wrap_OS_SendSecureTCP, size, 48);
    expect_string(__wrap_OS_SendSecureTCP, msg, input);

    will_return(__wrap_OS_SendSecureTCP, OS_SOCKTERR);

    errno = EWOULDBLOCK;

    expect_string(__wrap__mwarn, formatted_msg, "Cannot send message to syscheck: Resource temporarily unavailable (11)");

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

/* decode_win_acl_json */
void assert_ace_full_perms(const cJSON * const ace) {
    int i;
    const char *it;
    cJSON *element;
    static const char * const perm_strings[] = {
        "generic_read",
        "generic_write",
        "generic_execute",
        "generic_all",
        "delete",
        "read_control",
        "write_dac",
        "write_owner",
        "synchronize",
        "read_data",
        "write_data",
        "append_data",
        "read_ea",
        "write_ea",
        "execute",
        "read_attributes",
        "write_attributes",
        NULL
    };

    assert_non_null(ace);
    assert_true(cJSON_IsArray(ace));

    for (i = 0, it = perm_strings[0]; it; it = perm_strings[++i]) {
        int fail = 1;
        cJSON_ArrayForEach(element, ace) {
            if (strcmp(cJSON_GetStringValue(element), it) == 0) {
                fail = 0;
                break;
            }
        }

        if (fail) {
            fail_msg("%s not found", it);
        }
    }
}

#define set_full_perms(x)                                                                                   \
    x |= GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | DELETE | READ_CONTROL | WRITE_DAC | \
         WRITE_OWNER | SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA |   \
         FILE_WRITE_EA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES

static void test_decode_win_acl_json_null_json(void **state) {
    expect_assert_failure(decode_win_acl_json(NULL));
}

static void test_decode_win_acl_fail_creating_object(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    cJSON_AddItemToObject(ace, "allowed", cJSON_CreateNumber(full_perms));

    will_return(__wrap_cJSON_CreateArray, NULL);

    expect_string(__wrap__mwarn, formatted_msg, FIM_CJSON_ERROR_CREATE_ITEM);

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);

    cJSON *denied = cJSON_GetObjectItem(ace, "denied");
    assert_null(denied);

    cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
    assert_non_null(allowed);
    assert_int_equal(full_perms, allowed->valueint);
}

static void test_decode_win_acl_json_allowed_ace_only(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    cJSON_AddItemToObject(ace, "allowed", cJSON_CreateNumber(full_perms));

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);

    cJSON *denied = cJSON_GetObjectItem(ace, "denied");
    assert_null(denied);

    cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
    assert_ace_full_perms(allowed);
}

static void test_decode_win_acl_json_denied_ace_only(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    cJSON_AddItemToObject(ace, "denied", cJSON_CreateNumber(full_perms));

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);

    cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
    assert_null(allowed);

    cJSON *denied = cJSON_GetObjectItem(ace, "denied");
    assert_ace_full_perms(denied);
}

static void test_decode_win_acl_json_both_ace_types(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    cJSON_AddItemToObject(ace, "name", cJSON_CreateString("username"));
    cJSON_AddItemToObject(ace, "denied", cJSON_CreateNumber(full_perms));
    cJSON_AddItemToObject(ace, "allowed", cJSON_CreateNumber(full_perms));

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);

    cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
    assert_ace_full_perms(allowed);

    cJSON *denied = cJSON_GetObjectItem(ace, "denied");
    assert_ace_full_perms(denied);

    // User name must be untouched, same as other unused fields
    cJSON *name = cJSON_GetObjectItem(ace, "name");
    assert_non_null(name);
    assert_string_equal("username", cJSON_GetStringValue(name));
}

static void test_decode_win_acl_json_empty_acl(void **state) {
    cJSON *acl = __real_cJSON_CreateObject();
    *state = acl;

    if (acl == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    decode_win_acl_json(acl);

    assert_int_equal(0, cJSON_GetArraySize(acl));
}

static void test_decode_win_acl_json_empty_ace(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);
    assert_int_equal(0, cJSON_GetArraySize(ace));
}

static void test_decode_win_acl_json_multiple_aces(void **state) {
    const char * const SIDS[] = {
        [0] = "S-1-5-32-636",
        [1] = "S-1-5-32-363",
        [2] = "S-1-5-32-444",
        [3] = NULL
    };
    const char * const USERNAMES[] = {
        [0] = "username",
        [1] = "someone",
        [2] = "anon",
        [3] = NULL
    };
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = NULL;
    cJSON *element;

    if (acl == NULL) {
        fail_msg("Failed to create ACL cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    for (i = 0, it = SIDS[0]; it; it = SIDS[++i]) {
        ace = __real_cJSON_CreateObject();
        if (ace == NULL) {
            fail_msg("Failed to create ACE cJSON object");
        }

        cJSON_AddItemToObject(acl, it, ace);

        cJSON_AddItemToObject(ace, "name", cJSON_CreateString(USERNAMES[i]));
        cJSON_AddItemToObject(ace, "denied", cJSON_CreateNumber(full_perms));
        cJSON_AddItemToObject(ace, "allowed", cJSON_CreateNumber(full_perms));

        will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
        will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    }

    decode_win_acl_json(acl);

    for (i = 0, it = SIDS[0]; it; it = SIDS[++i]) {
        ace = cJSON_GetObjectItem(acl, it);
        assert_non_null(ace);

        cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
        assert_ace_full_perms(allowed);

        cJSON *denied = cJSON_GetObjectItem(ace, "denied");
        assert_ace_full_perms(denied);

        // User name must be untouched, same as other unused fields
        cJSON *name = cJSON_GetObjectItem(ace, "name");
        assert_non_null(name);
        assert_string_equal(USERNAMES[i], cJSON_GetStringValue(name));
    }
}


/* decode_win_permissions tests */
static void test_decode_win_permissions_success_all_permissions(void **state) {
    char raw_perm[OS_SIZE_1024] = { '\0' };
    char *output;

    snprintf(raw_perm, OS_MAXSTR, "|account,0,%ld",
             (long int)(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | DELETE | READ_CONTROL |
                             WRITE_DAC | WRITE_OWNER | SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA |
                             FILE_APPEND_DATA | FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE | FILE_READ_ATTRIBUTES |
                             FILE_WRITE_ATTRIBUTES));

    output = decode_win_permissions(raw_perm);

    *state = output;

    assert_string_equal(output,
                        "account (allowed): generic_read|generic_write|generic_execute|"
                        "generic_all|delete|read_control|write_dac|write_owner|synchronize|read_data|write_data|"
                        "append_data|read_ea|write_ea|execute|read_attributes|write_attributes");
}

static void test_decode_win_permissions_success_no_permissions(void **state) {
    char raw_perm[OS_SIZE_1024] = { '\0' };
    char *output;

    snprintf(raw_perm, OS_MAXSTR,  "|account,0,%ld", (long int)0);

    output = decode_win_permissions(raw_perm);

    *state = output;

    assert_string_equal(output, "account (allowed):");
}

static void test_decode_win_permissions_success_some_permissions(void **state) {
    char raw_perm[OS_SIZE_1024] = { '\0' };
    char *output;

    snprintf(raw_perm, OS_MAXSTR, "|account,0,%ld",
             (long int)(GENERIC_READ | GENERIC_EXECUTE | DELETE | WRITE_DAC | SYNCHRONIZE | FILE_WRITE_DATA |
                        FILE_READ_EA | FILE_EXECUTE | FILE_WRITE_ATTRIBUTES));

    output = decode_win_permissions(raw_perm);

    *state = output;

    assert_string_equal(output, "account (allowed): generic_read|generic_execute|"
                                "delete|write_dac|synchronize|write_data|read_ea|execute|write_attributes");
}

static void test_decode_win_permissions_success_multiple_accounts(void **state) {
    char raw_perm[OS_SIZE_1024] = { '\0' };
    char *output;

    snprintf(raw_perm, OS_MAXSTR, "|first,0,%ld|second,1,%ld", (long int)(GENERIC_READ), (long int)(GENERIC_EXECUTE));

    output = decode_win_permissions(raw_perm);

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
    char raw_perm[OS_SIZE_1024] = { "|account,this wont pass" };
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '|account,this wont pass'.");

    output = decode_win_permissions(raw_perm);

    *state = output;

    assert_null(output);
}

static void test_decode_win_permissions_fail_wrong_format(void **state) {
    char raw_perm[OS_SIZE_1024] = { "this is not the proper format" };
    char *output;

    output = decode_win_permissions(raw_perm);

    *state = output;

    assert_string_equal("", output);
}

static void test_decode_win_permissions_overrun_inner_buffer(void **state) {
    char raw_perm[OS_MAXSTR] = { '\0' };
    int size = 0;
    char *output;

    while (size < MAX_WIN_PERM_SIZE) {
        size += snprintf(raw_perm + size, OS_MAXSTR,  "|account%d,0,%ld", size, (long int)(GENERIC_READ));
    }

    output = decode_win_permissions(raw_perm);

    *state = output;

    assert_true(strlen(output) < MAX_WIN_PERM_SIZE);
}

static void test_decode_win_permissions_empty_permissions(void **state) {
    char *raw_perm = "";
    char *output;

    output = decode_win_permissions(raw_perm);

    assert_string_equal(output, "");
    os_free(output);
}

static void test_decode_win_permissions_single_pipe(void **state) {
    char *raw_perm = "|";
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '|'.");
    output = decode_win_permissions(raw_perm);

    assert_null(output);
}

static void test_decode_win_permissions_bad_format_1(void **state) {
    char *raw_perm = "|,";
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '|,'.");
    output = decode_win_permissions(raw_perm);

    assert_null(output);
}


static void test_decode_win_permissions_bad_format_2(void **state) {

    char *raw_perm;
    w_strdup("|,|", raw_perm);
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '|,|'.");
    output = decode_win_permissions(raw_perm);

    os_free(raw_perm);

    assert_null(output);

}

static void test_decode_win_permissions_bad_format_3(void **state) {
    char *raw_perm;
    w_strdup("||", raw_perm);
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '||'.");
    output = decode_win_permissions(raw_perm);
    os_free(raw_perm);

    assert_null(output);
}

static void test_decode_win_permissions_bad_format_4(void **state) {
    char *raw_perm;
    w_strdup("|,|,|,", raw_perm);
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '|,|,|,'.");
    output = decode_win_permissions(raw_perm);
    os_free(raw_perm);

    assert_null(output);
}

static void test_decode_win_permissions_bad_format_5(void **state) {
    char *raw_perm;
    w_strdup("|account,0,123|", raw_perm);
    char *output;

    expect_string(__wrap__mdebug1, formatted_msg, "The file permissions could not be decoded: '|account,0,123|'.");
    output = decode_win_permissions(raw_perm);
    os_free(raw_perm);

    assert_null(output);
}


static void test_decode_win_permissions_incomplete_format_1(void **state) {
    char *raw_perm;
    w_strdup("|account,0,", raw_perm);
    char *output;

    output = decode_win_permissions(raw_perm);
    os_free(raw_perm);

    assert_string_equal(output, "account (allowed):");
    os_free(output);
}

static void test_decode_win_permissions_incomplete_format_2(void **state) {
    char *raw_perm;
    w_strdup("|account,0,0", raw_perm);
    char *output;

    output = decode_win_permissions(raw_perm);
    os_free(raw_perm);

    assert_string_equal(output, "account (allowed):");
    os_free(output);
}


/* compare_win_permissions */
#define BASE_WIN_ALLOWED_ACE "[" \
    "\"delete\"," \
    "\"read_control\"," \
    "\"write_dac\"," \
    "\"write_owner\"," \
    "\"synchronize\"," \
    "\"read_data\"," \
    "\"write_data\"," \
    "\"append_data\"," \
    "\"read_ea\"," \
    "\"write_ea\"," \
    "\"execute\"," \
    "\"read_attributes\"," \
    "\"write_attributes\"" \
"]"

#define BASE_WIN_DENIED_ACE "[" \
    "\"read_control\"," \
    "\"synchronize\"," \
    "\"read_data\"," \
    "\"read_ea\"," \
    "\"execute\"," \
    "\"read_attributes\"" \
"]"

#define BASE_WIN_ACE "{" \
    "\"name\": \"Users\"," \
    "\"allowed\": " BASE_WIN_ALLOWED_ACE "," \
    "\"denied\": " BASE_WIN_DENIED_ACE \
"}"

static const char * const BASE_WIN_PERMS = "{\"S-1-5-32-636\": " BASE_WIN_ACE "}";

static void test_compare_win_permissions_equal_acls(void **state) {
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = cJSON_Parse(BASE_WIN_PERMS);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_true(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_null_acl1(void **state) {
    cJSON *acl1 = NULL;
    cJSON *acl2 = cJSON_Parse(BASE_WIN_PERMS);

    assert_non_null(acl2);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_null_acl2(void **state) {
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = NULL;

    assert_non_null(acl1);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
}

static void test_compare_win_permissions_both_acls_null(void **state) {
    cJSON *acl1 = NULL;
    cJSON *acl2 = NULL;

    assert_true(compare_win_permissions(acl1, acl2));
}

static void test_compare_win_permissions_acl1_larger_than_acl2(void **state) {
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = cJSON_Parse(BASE_WIN_PERMS);

    assert_non_null(acl1);
    assert_non_null(acl2);

    cJSON_AddItemToObject(acl1, "S-1-5-18", __real_cJSON_CreateObject());

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_acl2_larger_than_acl1(void **state) {
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = cJSON_Parse(BASE_WIN_PERMS);

    assert_non_null(acl1);
    assert_non_null(acl2);

    cJSON_AddItemToObject(acl2, "S-1-5-18", __real_cJSON_CreateObject());

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_different_entries(void **state) {
    const char * const ACL2 = "{ \"S-1-5-18\":" BASE_WIN_ACE "}";
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = cJSON_Parse(ACL2);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_no_allowed_ace(void **state) {
    const char *const NO_ALLOWED_ACE = "{\"S-1-5-32-636\": {"
                                       "\"name\": \"Users\","
                                       "\"denied\": " BASE_WIN_DENIED_ACE "}}";
    cJSON *acl1 = cJSON_Parse(NO_ALLOWED_ACE);
    cJSON *acl2 = cJSON_Parse(NO_ALLOWED_ACE);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_true(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_no_allowed_ace1(void **state) {
    const char *const NO_ALLOWED_ACE = "{\"S-1-5-32-636\": {"
                                       "\"name\": \"Users\","
                                       "\"denied\": " BASE_WIN_DENIED_ACE "}}";
    cJSON *acl1 = cJSON_Parse(NO_ALLOWED_ACE);
    cJSON *acl2 = cJSON_Parse(BASE_WIN_PERMS);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_no_allowed_ace2(void **state) {
    const char *const NO_ALLOWED_ACE = "{\"S-1-5-32-636\": {"
                                       "\"name\": \"Users\","
                                       "\"denied\": " BASE_WIN_DENIED_ACE "}}";
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = cJSON_Parse(NO_ALLOWED_ACE);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_no_denied_ace(void **state) {
    const char *const NO_DENIED_ACE = "{\"S-1-5-32-636\": {"
                                       "\"name\": \"Users\","
                                       "\"allowed\": " BASE_WIN_ALLOWED_ACE "}}";
    cJSON *acl1 = cJSON_Parse(NO_DENIED_ACE);
    cJSON *acl2 = cJSON_Parse(NO_DENIED_ACE);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_true(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_no_denied_ace1(void **state) {
    const char *const NO_DENIED_ACE = "{\"S-1-5-32-636\": {"
                                       "\"name\": \"Users\","
                                       "\"allowed\": " BASE_WIN_ALLOWED_ACE "}}";
    cJSON *acl1 = cJSON_Parse(NO_DENIED_ACE);
    cJSON *acl2 = cJSON_Parse(BASE_WIN_PERMS);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_no_denied_ace2(void **state) {
    const char *const NO_DENIED_ACE = "{\"S-1-5-32-636\": {"
                                       "\"name\": \"Users\","
                                       "\"allowed\": " BASE_WIN_ALLOWED_ACE "}}";
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = cJSON_Parse(NO_DENIED_ACE);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_different_allowed_ace(void **state) {
    const char *const CUSTOM_WIN_PERMS = "{\"S-1-5-32-636\": {"
                                       "\"name\": \"Users\","
                                       "\"allowed\": [\"read_control\"],"
                                       "\"denied\": " BASE_WIN_DENIED_ACE "}}";
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = cJSON_Parse(CUSTOM_WIN_PERMS);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
}

static void test_compare_win_permissions_different_denied_ace(void **state) {
    const char *const CUSTOM_WIN_PERMS = "{\"S-1-5-32-636\": {"
                                       "\"name\": \"Users\","
                                       "\"denied\": [\"read_control\"],"
                                       "\"allowed\": " BASE_WIN_ALLOWED_ACE "}}";
    cJSON *acl1 = cJSON_Parse(BASE_WIN_PERMS);
    cJSON *acl2 = cJSON_Parse(CUSTOM_WIN_PERMS);

    assert_non_null(acl1);
    assert_non_null(acl2);

    assert_false(compare_win_permissions(acl1, acl2));

    cJSON_Delete(acl1);
    cJSON_Delete(acl2);
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

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    output = win_perm_to_json(input);

    *state = output;

    assert_non_null(output);

    const cJSON *ace = cJSON_GetArrayItem(output, 0);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ace, "name")), "account");
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(ace, "allowed")), 0);
}

static void test_win_perm_to_json_empty_permissions(void **state) {
    char *input = "account (allowed):,";
    cJSON *output;

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    output = win_perm_to_json(input);

    *state = output;

    assert_non_null(output);

    const cJSON *ace = cJSON_GetArrayItem(output, 0);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ace, "name")), "account");
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(ace, "allowed")), 0);
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

static void test_win_perm_to_json_malformed_permission_1(void **state) {
    char *input = "first (allowed): generic_read|generic_write|generic_execute,"
        " first (denied): generic_all|delete|read_control|write_dac|write_owner,"
        " second (allowed): synchronize|read_data|write_data,"
        " third (denied): append_data|read_ea|write_ea|execute|read_attributes|write_attributes,"
        " fourth ";
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
    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing the username from 'fourth '. Skipping permission.");
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

static void test_win_perm_to_json_malformed_permission_2(void **state) {
    char *input = "first (allowed): generic_read|generic_write|generic_execute,"
        " first (denied): generic_all|delete|read_control|write_dac|write_owner,"
        " second (allowed): synchronize|read_data|write_data,"
        " third (error,"
        " fourth (denied): append_data|read_ea|write_ea|execute|read_attributes|write_attributes";
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
    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing the permission type from 'error'. Skipping permission.");
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
        "Uncontrolled condition when parsing the username from 'This format is incorrect'. Skipping permission.");

    output = win_perm_to_json(input);

    assert_null(output);
}
static void test_win_perm_to_json_incorrect_permission_format_2(void **state) {
    char *input = "This format is incorrect (too";
    cJSON *output;

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    expect_string(__wrap__mdebug1, formatted_msg,
        "Uncontrolled condition when parsing the permission type from 'too'. Skipping permission.");

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

static void test_get_file_user_CreateFile_error_access_denied(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)INVALID_HANDLE_VALUE);

    expect_GetLastError_call(ERROR_ACCESS_DENIED);

    expect_FormatMessage_call("An error message");

    expect_string(__wrap__mdebug1, formatted_msg, "At get_user(C:\\a\\path): wCreateFile(): An error message (5)");

    expect_CloseHandle_call(INVALID_HANDLE_VALUE, 1);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_file_user_CreateFile_error_sharing_violation(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)INVALID_HANDLE_VALUE);

    expect_GetLastError_call(ERROR_SHARING_VIOLATION);

    expect_FormatMessage_call("An error message");

    expect_string(__wrap__mdebug1, formatted_msg, "At get_user(C:\\a\\path): wCreateFile(): An error message (32)");

    expect_CloseHandle_call(INVALID_HANDLE_VALUE, 1);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_file_user_CreateFile_error_generic(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)INVALID_HANDLE_VALUE);

    expect_GetLastError_call(127);

    expect_FormatMessage_call("An error message");

    expect_string(__wrap__mwarn, formatted_msg, "At get_user(C:\\a\\path): wCreateFile(): An error message (127)");

    expect_CloseHandle_call(INVALID_HANDLE_VALUE, 1);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_file_user_GetSecurityInfo_error(void **state) {
    char **array = *state;
    char error_msg[OS_SIZE_1024];

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    expect_CloseHandle_call((HANDLE)1234, 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_ACCESS_DENIED);

    expect_ConvertSidToStringSid_call("", FALSE);

    will_return(__wrap_win_strerror,"Access denied.");

    expect_string(__wrap__mdebug1, formatted_msg, "The user's SID could not be extracted.");

    snprintf(error_msg,
             OS_SIZE_1024,
             "GetSecurityInfo error code = (%lu), 'Access denied.'",
             ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug1, formatted_msg, error_msg);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_file_user_LookupAccountSid_error(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    expect_CloseHandle_call((HANDLE)1234, 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("sid", TRUE);

    expect_LookupAccountSid_call("", "domainname", FALSE);
    expect_GetLastError_call(ERROR_ACCESS_DENIED);
    expect_FormatMessage_call("Access is denied.");
    expect_string(__wrap__mwarn, formatted_msg, "(6950): Error in LookupAccountSid getting user. (5): Access is denied.");

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
    assert_string_equal(array[1], "sid");
}

static void test_get_file_user_LookupAccountSid_error_none_mapped(void **state) {
    char **array = *state;
    char error_msg[OS_SIZE_1024];

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    expect_CloseHandle_call((HANDLE)1234, 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("sid", TRUE);

    expect_LookupAccountSid_call("", "domainname", FALSE);
    expect_GetLastError_call(ERROR_NONE_MAPPED);

    snprintf(error_msg,
             OS_SIZE_1024,
             "Account owner not found for '%s'",
             "C:\\a\\path");

    expect_string(__wrap__mdebug1, formatted_msg, error_msg);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
    assert_string_equal(array[1], "sid");
}

static void test_get_file_user_success(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    expect_CloseHandle_call((HANDLE)1234, 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("sid", TRUE);

    expect_LookupAccountSid_call("accountName", "domainname", TRUE);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

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

void test_w_get_file_permissions_GetFileSecurity_error_on_size(void **state) {
    cJSON *permissions = NULL;
    int ret;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, 0);
    will_return(__wrap_utf8_GetFileSecurity, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_w_get_file_permissions_GetFileSecurity_error(void **state) {
    cJSON *permissions = NULL;
    int ret;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, NULL);
    will_return(__wrap_utf8_GetFileSecurity, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_w_get_file_permissions_create_cjson_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mwarn, formatted_msg, FIM_CJSON_ERROR_CREATE_ITEM);

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, -1);
    assert_null(permissions);
}

void test_w_get_file_permissions_GetSecurityDescriptorDacl_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, FALSE);
    will_return(wrap_GetSecurityDescriptorDacl, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "GetSecurityDescriptorDacl failed. GetLastError returned: 5");

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_w_get_file_permissions_no_dacl(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, FALSE);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "No DACL was found (all access is denied), or a NULL DACL (unrestricted access) was found.");

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, -2);
    assert_null(permissions);
}

void test_w_get_file_permissions_GetAclInformation_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, NULL);
    will_return(wrap_GetAclInformation, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug2, formatted_msg, "GetAclInformation failed. GetLastError returned: 5");

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_w_get_file_permissions_GetAce_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, NULL);
    will_return(wrap_GetAce, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);
    expect_string(__wrap__mdebug2, formatted_msg, "GetAce failed. GetLastError returned: 5");

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, 0);
    assert_non_null(permissions);
    cJSON_Delete(permissions);
}

void test_w_get_file_permissions_success(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = {
        .AceCount = 1,
    };
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = ACCESS_ALLOWED_ACE_TYPE,
    };

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, &ace);
    will_return(wrap_GetAce, 1);

    // Inside process_ace_info
    {
        will_return(wrap_IsValidSid, 1);

        // Inside w_get_account_info
        will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Name size
        will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Domain size
        will_return(wrap_LookupAccountSid, 1);

        will_return(wrap_LookupAccountSid, "accountName");
        will_return(wrap_LookupAccountSid, "domainName");
        will_return(wrap_LookupAccountSid, 1);

        expect_ConvertSidToStringSid_call(BASE_WIN_SID, TRUE);
    }

    // Inside add_ace_to_json
    {
        will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());
    }

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, 0);
    assert_non_null(permissions);

    cJSON *ace_json = cJSON_GetObjectItem(permissions, BASE_WIN_SID);
    assert_non_null(ace_json);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ace_json, "name")), "accountName");
    assert_int_equal(cJSON_GetObjectItem(ace_json, "allowed")->valueint, 0);
    assert_null(cJSON_GetObjectItem(ace_json, "denied"));

    cJSON_Delete(permissions);
}

void test_w_get_file_permissions_process_ace_info_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = {
        .AceCount = 1,
    };
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = SYSTEM_AUDIT_ACE_TYPE,
    };

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, &ace);
    will_return(wrap_GetAce, 1);

    // Inside process_ace_info
    expect_string(__wrap__mdebug2, formatted_msg, "Invalid ACE type.");

    expect_string(__wrap__mdebug1, formatted_msg,
        "ACE number 0 could not be processed.");

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, 0);
    assert_non_null(permissions);
}

void test_w_get_file_attrs_error(void **state) {
    int ret;

    expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileAttributes, INVALID_FILE_ATTRIBUTES);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug2, formatted_msg, "The attributes for 'C:\\a\\path' could not be obtained. Error '5'.");

    ret = w_get_file_attrs("C:\\a\\path");

    assert_int_equal(ret, 0);
}

void test_w_get_file_attrs_success(void **state) {
    int ret;

    expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileAttributes, 123456);

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
        expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
        will_return(__wrap_utf8_GetFileAttributes, INVALID_FILE_ATTRIBUTES);

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
        expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
        will_return(__wrap_utf8_GetFileAttributes, FILE_ATTRIBUTE_NORMAL);
    }

    ret = w_directory_exists("C:\\a\\path");

    assert_null(ret);
}

void test_w_directory_exists_path_is_dir(void **state) {
    unsigned int ret;

    // Inside w_get_file_attrs
    {
        expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
        will_return(__wrap_utf8_GetFileAttributes, FILE_ATTRIBUTE_DIRECTORY);
    }

    ret = w_directory_exists("C:\\a\\path");

    assert_non_null(ret);
}

void test_get_registry_group_GetSecurityInfo_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;
    char error_msg[OS_SIZE_1024];

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_ACCESS_DENIED);
    expect_ConvertSidToStringSid_call("", TRUE);
    will_return(__wrap_win_strerror, "Access denied.");

    snprintf(error_msg,
             OS_SIZE_1024,
             "GetSecurityInfo error code = (%lu), 'Access denied.'",
             ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug1, formatted_msg, error_msg);

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "");
    assert_string_equal(group_id, "");
}

void test_get_registry_group_ConvertSidToStringSid_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("dummy", FALSE);

    expect_string(__wrap__mdebug1, formatted_msg, "The user's SID could not be extracted.");

    expect_LookupAccountSid_call("groupname", "domainname", TRUE);

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "groupname");
    assert_string_equal(group_id, "");
}

void test_get_registry_group_LookupAccountSid_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("groupid", TRUE);

    expect_LookupAccountSid_call("", "domainname", FALSE);
    expect_GetLastError_call(ERROR_ACCESS_DENIED);
    expect_FormatMessage_call("Access is denied.");
    expect_string(__wrap__mwarn, formatted_msg, "(6950): Error in LookupAccountSid getting group. (5): Access is denied.");

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "");
    assert_string_equal(group_id, "groupid");
}

void test_get_registry_group_LookupAccountSid_not_found(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("groupid", TRUE);

    expect_LookupAccountSid_call("", "domainname", FALSE);
    expect_GetLastError_call(ERROR_NONE_MAPPED);

    expect_string(__wrap__mdebug1, formatted_msg, "Group not found for registry key");

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "");
    assert_string_equal(group_id, "groupid");
}

void test_get_registry_group_success(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("groupid", TRUE);

    expect_LookupAccountSid_call("groupname", "domainname", TRUE);

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "groupname");
    assert_string_equal(group_id, "groupid");
}

void test_get_registry_permissions_RegGetKeySecurity_insufficient_buffer(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_ACCESS_DENIED);

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_get_registry_permissions_RegGetKeySecurity_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_ACCESS_DENIED);

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_get_registry_permissions_GetSecurityDescriptorDacl_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)0, FALSE);

    expect_GetLastError_call(ERROR_SUCCESS);
    expect_string(__wrap__mdebug2, formatted_msg, "GetSecurityDescriptorDacl failed. GetLastError returned: 0");

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_SUCCESS);
    assert_null(permissions);
}

void test_get_registry_permissions_GetSecurityDescriptorDacl_no_DACL(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;
    char error_msg[OS_SIZE_1024];

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)0, TRUE);

    snprintf(error_msg,
             OS_SIZE_1024,
             "%s",
             "No DACL was found (all access is denied), or a NULL DACL (unrestricted access) was found.");

    expect_string(__wrap__mdebug2, formatted_msg, error_msg);

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_not_equal(retval, ERROR_SUCCESS);
    assert_null(permissions);
}

void test_get_registry_permissions_GetAclInformation_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)4321, TRUE);

    expect_GetAclInformation_call(NULL, FALSE);

    expect_GetLastError_call(ERROR_SUCCESS);
    expect_string(__wrap__mdebug2, formatted_msg, "GetAclInformation failed. GetLastError returned: 0");

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_SUCCESS);
    assert_null(permissions);
}

void test_get_registry_permissions_GetAce_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)4321, TRUE);

    expect_GetAclInformation_call(&acl_size, TRUE);

    expect_GetAce_call(NULL, FALSE);

    expect_GetLastError_call(ERROR_SUCCESS);
    expect_string(__wrap__mdebug2, formatted_msg, "GetAce failed. GetLastError returned: 0");

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_SUCCESS);
    assert_non_null(permissions);
}

void test_get_registry_permissions_success(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = ACCESS_ALLOWED_ACE_TYPE,
    };

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)4321, TRUE);

    expect_GetAclInformation_call(&acl_size, TRUE);

    expect_GetAce_call((LPVOID*)&ace, TRUE);

    // Inside process_ace_info
    {
        will_return(wrap_IsValidSid, 1);

        // Inside w_get_account_info
        will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Name size
        will_return(wrap_LookupAccountSid, OS_SIZE_1024);   // Domain size
        will_return(wrap_LookupAccountSid, 1);

        will_return(wrap_LookupAccountSid, "accountName");
        will_return(wrap_LookupAccountSid, "domainName");
        will_return(wrap_LookupAccountSid, 1);

        expect_ConvertSidToStringSid_call(BASE_WIN_SID, TRUE);

        will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());
    }

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_SUCCESS);
    assert_non_null(permissions);

    cJSON *ace_json = cJSON_GetObjectItem(permissions, BASE_WIN_SID);
    assert_non_null(ace_json);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ace_json, "name")), "accountName");
    assert_int_equal(cJSON_GetObjectItem(ace_json, "allowed")->valueint, 0);
    assert_null(cJSON_GetObjectItem(ace_json, "denied"));

    cJSON_Delete(permissions);
}

void test_get_registry_mtime_RegQueryInfoKeyA_fails(void **state) {
    FILETIME last_write_time;
    unsigned int retval = 0;
    HKEY hndl = (HKEY)123456;

    expect_RegQueryInfoKeyA_call(&last_write_time, ERROR_MORE_DATA);

    expect_string(__wrap__mwarn, formatted_msg, "Couldn't get modification time for registry key.");

    retval = get_registry_mtime(hndl);

    assert_int_equal(retval, 0);
}

void test_get_registry_mtime_success(void **state) {
    FILETIME last_write_time;
    unsigned int retval = 0;
    HKEY hndl = (HKEY)123456;

    expect_RegQueryInfoKeyA_call(&last_write_time, ERROR_SUCCESS);

    retval = get_registry_mtime(hndl);

    assert_int_not_equal(retval, 0);
}

void test_get_subkey(void **state)
{
    char* test_vector_path[4] = {
        "HKEY_SOMETHING\\*\\A",
        "HKEY_SOMETHING\\A\\B\\*",
        "HKEY_SOMETHING\\A?",
        "HKEY_SOMETHING\\A\\B\\C?"
    };

    char* expected_subkey[4] = {
        "",
        "A\\B",
        "",
        "A\\B"
    };

    for (int scenario = 0; scenario < 4; scenario++) {
        char* result_function = get_subkey(test_vector_path[scenario]);
        assert_string_equal(result_function, expected_subkey[scenario]);
    }
}

void test_w_is_still_a_wildcard(void **state) {
    int ret;
    reg_path_struct** test_reg;
    int has_wildcard_vec[4] = {0, 1, 1, 0};
    int checked_vec[4] = {0, 1, 0, 1};
    int expected_result[4] = {0, 0, 1, 0};

    test_reg    = (reg_path_struct**)calloc(2, sizeof(reg_path_struct*));
    test_reg[0] = (reg_path_struct*)calloc(1, sizeof(reg_path_struct));
    test_reg[1] = NULL;

    for(int scenario = 0; scenario < 4; scenario++) {
        test_reg[0]->has_wildcard = has_wildcard_vec[scenario];
        test_reg[0]->checked = checked_vec[scenario];
        ret = w_is_still_a_wildcard(test_reg);
        assert_int_equal(expected_result[scenario], ret);
    }

    os_free(test_reg[0]);
    os_free(test_reg);
}

void test_w_list_all_keys_subkey_notnull(void** state) {
    HKEY root_key = HKEY_LOCAL_MACHINE;
    HKEY keyhandle;
    FILETIME last_write_time = { 0, 1000 };

    char* subkey = "HARDWARE";
    char* result[4] = {
        "ACPI",
        "DESCRIPTION",
        "DEVICEMAP",
        "RESOURCEMAP"
    };

    expect_RegOpenKeyEx_call(root_key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(4, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("ACPI", 5, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("DESCRIPTION", 12, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("DEVICEMAP", 10, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("RESOURCEMAP", 12, ERROR_SUCCESS);

    char** query_result = w_list_all_keys(root_key, subkey);

    for (int idx = 0; idx < 4; idx++) {
        assert_string_equal(query_result[idx], result[idx]);
        os_free(query_result[idx]);
    }
}

void test_w_list_all_keys_subkey_null(void** state) {
    HKEY root_key = HKEY_LOCAL_MACHINE;
    HKEY keyhandle;
    FILETIME last_write_time = { 0, 1000 };

    char* subkey = "";
    char* result[6] = {
        "BCD00000000",
        "HARDWARE",
        "SAM",
        "SECURITY",
        "SOFTWARE",
        "SYSTEM",
    };

    expect_RegOpenKeyEx_call(root_key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(6, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("BCD00000000", 12, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("HARDWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SAM", 4, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SECURITY", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SOFTWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SYSTEM", 7, ERROR_SUCCESS);

    char** query_result = w_list_all_keys(root_key, subkey);

    for (int idx = 0; idx < 6; idx++) {
        assert_string_equal(query_result[idx], result[idx]);
        os_free(query_result[idx]);
    }
}

void test_w_switch_root_key(void** state) {
    char* root_key_valid_lm = "HKEY_LOCAL_MACHINE";
    char* root_key_valid_cr = "HKEY_CLASSES_ROOT";
    char* root_key_valid_cc = "HKEY_CURRENT_CONFIG";
    char* root_key_valid_us = "HKEY_USERS";
    char* root_key_valid_cu = "HKEY_CURRENT_USER";

    char* root_key_invalid  = "HKEY_SOMETHING";

    expect_any_always(__wrap__mdebug1, formatted_msg);

    HKEY ret;

    ret = w_switch_root_key(root_key_valid_lm);
    assert_int_equal(ret, HKEY_LOCAL_MACHINE);

    ret = w_switch_root_key(root_key_valid_cr);
    assert_int_equal(ret, HKEY_CLASSES_ROOT);

    ret = w_switch_root_key(root_key_valid_cc);
    assert_int_equal(ret, HKEY_CURRENT_CONFIG);

    ret = w_switch_root_key(root_key_valid_us);
    assert_int_equal(ret, HKEY_USERS);

    ret = w_switch_root_key(root_key_valid_cu);
    assert_int_equal(ret, HKEY_CURRENT_USER);

    ret = w_switch_root_key(root_key_invalid);
    assert_null(ret);
}

void test_expand_wildcard_registers_star_only(void **state){
    char* entry     = "HKEY_LOCAL_MACHINE\\*";
    char** paths    = NULL;
    os_calloc(OS_SIZE_1024, sizeof(char*), paths);
    char* subkey    = "";
    HKEY root_key   = HKEY_LOCAL_MACHINE;

    char* result[6] = {
        "HKEY_LOCAL_MACHINE\\BCD00000000",
        "HKEY_LOCAL_MACHINE\\HARDWARE",
        "HKEY_LOCAL_MACHINE\\SAM",
        "HKEY_LOCAL_MACHINE\\SECURITY",
        "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "HKEY_LOCAL_MACHINE\\SYSTEM",
    };

    HKEY keyhandle;
    FILETIME last_write_time = { 0, 1000 };

    expect_RegOpenKeyEx_call(root_key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(6, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("BCD00000000", 12, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("HARDWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SAM", 4, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SECURITY", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SOFTWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SYSTEM", 7, ERROR_SUCCESS);

    expand_wildcard_registers(entry, paths);

    int i = 0;
    while(*paths != NULL){
        assert_string_equal(*paths, result[i]);
        os_free(*paths);
        paths++;
        i++;
    }
}

void test_expand_wildcard_registers_invalid_path(void **state){
    char* entry     = "HKEY_LOCAL_MACHINE\\????";
    char** paths    = NULL;
    os_calloc(OS_SIZE_1024, sizeof(char*), paths);
    char* subkey    = "";
    HKEY root_key   = HKEY_LOCAL_MACHINE;

    FILETIME last_write_time = { 0, 1000 };

    expect_RegOpenKeyEx_call(root_key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(6, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("BCD00000000", 12, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("HARDWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SAM", 4, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SECURITY", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SOFTWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SYSTEM", 7, ERROR_SUCCESS);

    expand_wildcard_registers(entry, paths);

    assert_null(*paths);
    os_free(paths);

}

#endif


int main(int argc, char *argv[]) {
    const struct CMUnitTest tests[] = {
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
        cmocka_unit_test(test_get_group_no_group),
        cmocka_unit_test_teardown(test_get_group_error, teardown_string),

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

        /* decode_win_acl_json */
        cmocka_unit_test(test_decode_win_acl_json_null_json),
        cmocka_unit_test_teardown(test_decode_win_acl_fail_creating_object, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_allowed_ace_only, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_denied_ace_only, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_both_ace_types, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_empty_acl, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_empty_ace, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_multiple_aces, teardown_cjson),

        /* decode_win_permissions tests */
        cmocka_unit_test_teardown(test_decode_win_permissions_success_all_permissions, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_success_no_permissions, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_success_some_permissions, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_success_multiple_accounts, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_fail_no_account_name, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_fail_no_access_type, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_fail_wrong_format, teardown_string),
        cmocka_unit_test_teardown(test_decode_win_permissions_overrun_inner_buffer, teardown_string),
        cmocka_unit_test(test_decode_win_permissions_empty_permissions),
        cmocka_unit_test(test_decode_win_permissions_single_pipe),
        cmocka_unit_test(test_decode_win_permissions_bad_format_1),
        cmocka_unit_test(test_decode_win_permissions_bad_format_2),
        cmocka_unit_test(test_decode_win_permissions_bad_format_3),
        cmocka_unit_test(test_decode_win_permissions_bad_format_4),
        cmocka_unit_test(test_decode_win_permissions_bad_format_5),
        cmocka_unit_test(test_decode_win_permissions_incomplete_format_1),
        cmocka_unit_test(test_decode_win_permissions_incomplete_format_2),



        /* compare_win_permissions */
        cmocka_unit_test(test_compare_win_permissions_equal_acls),
        cmocka_unit_test(test_compare_win_permissions_null_acl1),
        cmocka_unit_test(test_compare_win_permissions_null_acl2),
        cmocka_unit_test(test_compare_win_permissions_both_acls_null),
        cmocka_unit_test(test_compare_win_permissions_acl1_larger_than_acl2),
        cmocka_unit_test(test_compare_win_permissions_acl2_larger_than_acl1),
        cmocka_unit_test(test_compare_win_permissions_different_entries),
        cmocka_unit_test(test_compare_win_permissions_no_allowed_ace),
        cmocka_unit_test(test_compare_win_permissions_no_allowed_ace1),
        cmocka_unit_test(test_compare_win_permissions_no_allowed_ace2),
        cmocka_unit_test(test_compare_win_permissions_no_denied_ace),
        cmocka_unit_test(test_compare_win_permissions_no_denied_ace1),
        cmocka_unit_test(test_compare_win_permissions_no_denied_ace2),
        cmocka_unit_test(test_compare_win_permissions_different_allowed_ace),
        cmocka_unit_test(test_compare_win_permissions_different_denied_ace),

        /* attrs_to_json tests */
        cmocka_unit_test_teardown(test_attrs_to_json_single_attribute, teardown_cjson),
        cmocka_unit_test_teardown(test_attrs_to_json_multiple_attributes, teardown_cjson),
        cmocka_unit_test_teardown(test_attrs_to_json_unable_to_create_json_array, teardown_cjson),
        cmocka_unit_test_teardown(test_attrs_to_json_null_attributes, teardown_cjson),

        /* win_perm_to_json tests*/
        cmocka_unit_test_teardown(test_win_perm_to_json_all_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_some_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_no_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_empty_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_allowed_denied_permissions, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_multiple_accounts, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_malformed_permission_1, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_malformed_permission_2, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_fragmented_acl, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_null_input, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_unable_to_create_main_array, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_unable_to_create_sub_array, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_unable_to_create_user_object, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_incorrect_permission_format, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_incorrect_permission_format_2, teardown_cjson),
        cmocka_unit_test_teardown(test_win_perm_to_json_error_splitting_permissions, teardown_cjson),

#ifdef TEST_WINAGENT
        /* get_file_user tests */
        cmocka_unit_test_setup_teardown(test_get_file_user_CreateFile_error_access_denied, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_CreateFile_error_sharing_violation, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_CreateFile_error_generic, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_GetSecurityInfo_error, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_LookupAccountSid_error, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_LookupAccountSid_error_none_mapped, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_success, setup_string_array, teardown_string_array),

        /* w_get_account_info tests */
        cmocka_unit_test_setup_teardown(test_w_get_account_info_LookupAccountSid_error_insufficient_buffer, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_w_get_account_info_LookupAccountSid_error_second_call, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_w_get_account_info_success, setup_string_array, teardown_string_array),

        /* w_get_file_permissions tests */
        cmocka_unit_test(test_w_get_file_permissions_GetFileSecurity_error_on_size),
        cmocka_unit_test(test_w_get_file_permissions_GetFileSecurity_error),
        cmocka_unit_test(test_w_get_file_permissions_create_cjson_error),
        cmocka_unit_test(test_w_get_file_permissions_GetSecurityDescriptorDacl_error),
        cmocka_unit_test(test_w_get_file_permissions_no_dacl),
        cmocka_unit_test(test_w_get_file_permissions_GetAclInformation_error),
        cmocka_unit_test(test_w_get_file_permissions_GetAce_error),
        cmocka_unit_test(test_w_get_file_permissions_success),
        cmocka_unit_test(test_w_get_file_permissions_process_ace_info_error),

        /* w_get_file_attrs tests */
        cmocka_unit_test(test_w_get_file_attrs_error),
        cmocka_unit_test(test_w_get_file_attrs_success),

        /* w_directory_exists tests */
        cmocka_unit_test(test_w_directory_exists_null_path),
        cmocka_unit_test(test_w_directory_exists_error_getting_attrs),
        cmocka_unit_test(test_w_directory_exists_path_is_not_dir),
        cmocka_unit_test(test_w_directory_exists_path_is_dir),

        /* get_registry_group tests */
        cmocka_unit_test_setup_teardown(test_get_registry_group_GetSecurityInfo_fails, setup_get_registry_group, teardown_get_registry_group),
        cmocka_unit_test_setup_teardown(test_get_registry_group_ConvertSidToStringSid_fails, setup_get_registry_group, teardown_get_registry_group),
        cmocka_unit_test_setup_teardown(test_get_registry_group_LookupAccountSid_fails, setup_get_registry_group, teardown_get_registry_group),
        cmocka_unit_test_setup_teardown(test_get_registry_group_LookupAccountSid_not_found, setup_get_registry_group, teardown_get_registry_group),
        cmocka_unit_test_setup_teardown(test_get_registry_group_success, setup_get_registry_group, teardown_get_registry_group),


        /* get_registry_permissions tests */
        cmocka_unit_test(test_get_registry_permissions_RegGetKeySecurity_insufficient_buffer),
        cmocka_unit_test(test_get_registry_permissions_RegGetKeySecurity_fails),
        cmocka_unit_test(test_get_registry_permissions_GetSecurityDescriptorDacl_fails),
        cmocka_unit_test(test_get_registry_permissions_GetSecurityDescriptorDacl_no_DACL),
        cmocka_unit_test(test_get_registry_permissions_GetAclInformation_fails),
        cmocka_unit_test(test_get_registry_permissions_GetAce_fails),
        cmocka_unit_test(test_get_registry_permissions_success),

        /* get_registry_mtime tests */
        cmocka_unit_test(test_get_registry_mtime_RegQueryInfoKeyA_fails),
        cmocka_unit_test(test_get_registry_mtime_success),

        /* expand_wildcard_register */
        cmocka_unit_test(test_get_subkey),
        cmocka_unit_test(test_w_is_still_a_wildcard),
        cmocka_unit_test(test_w_list_all_keys_subkey_notnull),
        cmocka_unit_test(test_w_list_all_keys_subkey_null),
        cmocka_unit_test(test_w_switch_root_key),
        cmocka_unit_test(test_expand_wildcard_registers_star_only),
        cmocka_unit_test(test_expand_wildcard_registers_invalid_path),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
