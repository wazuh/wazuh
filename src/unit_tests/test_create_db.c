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

/* redefinitons/wrapping */

int __wrap__minfo()
{
    return 0;
}

int __wrap__merror()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

int __wrap_rbtree_insert() {
    return mock();
}

int __wrap_rbtree_replace() {
    return mock();
}

int __wrap_rbtree_delete() {
    return 1;
}

int __wrap_OSHash_Add() {
    return mock();
}

int __wrap_OSHash_Delete() {
    return mock();
}

int __wrap_lstat(const char *path, struct stat *buf) {
    buf->st_dev = 1;
    buf->st_ino = 999;
    buf->st_uid = 0;
    buf->st_gid = 0;
    buf->st_mtime = 1433395216;
    return mock();
}

int __wrap_fim_send_scan_info() {
    return 1;
}

int __wrap_send_syscheck_msg() {
    return 1;
}

fim_entry_data *__wrap_rbtree_get() {
    fim_entry_data *data = mock_type(fim_entry_data *);
    return data;
}

fim_inode_data *__wrap_OSHash_Get() {
    fim_inode_data *data = mock_type(fim_inode_data *);
    return data;
}

fim_inode_data *__wrap_OSHash_Get_ex() {
    fim_inode_data *data = mock_type(fim_inode_data *);
    return data;
}

struct dirent * __wrap_readdir() {
    return mock_type(struct dirent *);
}

int __wrap_opendir() {
    return mock();
}

int __wrap_closedir() {
    return 1;
}

void syscheck_set_internals()
{
    syscheck.tsleep = 1;
    syscheck.sleep_after = 100;
    syscheck.rt_delay = 1;
    syscheck.max_depth = 256;
    syscheck.file_max_size = 1024;
}


static int delete_json(void **state)
{
    cJSON *data = *state;
    cJSON_Delete(data);
    return 0;
}


static int delete_entry_data(void **state)
{
    fim_entry_data *data = *state;
    free_entry_data(data);
    return 0;
}


char ** __wrap_rbtree_keys() {
    return mock_type(char **);
}

/* tests */

static fim_entry_data *fill_entry_struct(
    unsigned int size,
    const char * perm,
    const char * attributes,
    const char * uid,
    const char * gid,
    const char * user_name,
    const char * group_name,
    unsigned int mtime,
    unsigned long int inode,
    const char * hash_md5,
    const char * hash_sha1,
    const char * hash_sha256,
    fim_event_mode mode,
    time_t last_event,
    const char * entry_type,
    unsigned long int dev,
    unsigned int scanned,
    int options,
    os_sha1 checksum
) {
    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));
    data->size = size;
    data->perm = strdup(perm);
    data->attributes = strdup(attributes);
    data->uid = strdup(uid);
    data->gid = strdup(gid);
    data->user_name = strdup(user_name);
    data->group_name = strdup(group_name);;
    data->mtime = mtime;
    data->inode = inode;
    strcpy(data->hash_md5, hash_md5);
    strcpy(data->hash_sha1, hash_sha1);
    strcpy(data->hash_sha256, hash_sha256);
    data->mode = mode;
    data->last_event = last_event;
    data->entry_type = entry_type;
    data->dev = dev;
    data->scanned = scanned;
    data->options = options;
    strcpy(data->checksum, checksum);
    return data;
}


void test_fim_json_event(void **state)
{
    (void) state;
    cJSON *ret;

    // Load syscheck default values
    Read_Syscheck_Config("test_syscheck.conf");

    fim_entry_data *old_data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    fim_entry_data *new_data = fill_entry_struct(
        1501,
        "0666",
        "rw-rw-rw-",
        "101",
        "1001",
        "test1",
        "testing1",
        1570184224,
        606060,
        "3691689a513ace7e508297b583d7550d",
        "07f05add1049244e7e75ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e9959643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184221,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    ret = fim_json_event(
        "test.file",
        old_data,
        new_data,
        1,
        FIM_MODIFICATION,
        FIM_REALTIME,
        NULL
    );

    *state = ret;
    free_entry_data(old_data);
    free_entry_data(new_data);

    assert_non_null(ret);
    cJSON *data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    assert_non_null(changed_attributes);
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);

    assert_int_equal(cJSON_GetArraySize(changed_attributes), 10);
    assert_int_equal(cJSON_GetArraySize(attributes), 13);
    assert_int_equal(cJSON_GetArraySize(old_attributes), 13);
}


void test_fim_json_event_whodata(void **state)
{
    (void) state;
    cJSON *ret;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    whodata_evt *w_evt;
    w_evt = calloc(1, sizeof(whodata_evt));
    w_evt->user_id = strdup("100");
    w_evt->user_name = strdup("test");
    w_evt->group_id = strdup("1000");
    w_evt->group_name = strdup("testing");
    w_evt->process_name = strdup("test_proc");
    w_evt->path = strdup("./test/test.file");
    w_evt->audit_uid = strdup("99");
    w_evt->audit_name = strdup("audit_user");
    w_evt->effective_uid = strdup("999");
    w_evt->effective_name = strdup("effective_user");
    w_evt->inode = strdup("606060");
    w_evt->dev = strdup("12345678");
    w_evt->ppid = 1000;
    w_evt->process_id = 1001;

    fim_entry_data *old_data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    fim_entry_data *new_data = fill_entry_struct(
        1501,
        "0666",
        "rw-rw-rw-",
        "101",
        "1001",
        "test1",
        "testing1",
        1570184224,
        606060,
        "3691689a513ace7e508297b583d7550d",
        "07f05add1049244e7e75ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e9959643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184221,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    ret = fim_json_event(
        "test.file",
        old_data,
        new_data,
        1,
        FIM_MODIFICATION,
        FIM_WHODATA,
        w_evt
    );

    *state = ret;
    free_entry_data(old_data);
    free_entry_data(new_data);
    free_whodata_event(w_evt);

    assert_non_null(ret);
    cJSON *data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    assert_non_null(audit);
    assert_int_equal(cJSON_GetArraySize(audit), 12);
}


void test_fim_json_event_no_changes(void **state)
{
    (void) state;
    cJSON *ret;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    ret = fim_json_event(
        "test.file",
        data,
        data,
        1,
        FIM_MODIFICATION,
        FIM_WHODATA,
        NULL
    );

    *state = ret;

    free_entry_data(data);

    assert_null(ret);
}


void test_fim_attributes_json(void **state)
{
    (void) state;
    cJSON *ret;

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    ret = fim_attributes_json(data);
    *state = ret;

    free_entry_data(data);

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 13);
}


void test_fim_entry_json(void **state)
{
    (void) state;
    cJSON *ret;
    const char *f_path = "/dir/test";

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    ret = fim_entry_json(f_path, data);
    *state = ret;

    free_entry_data(data);

    assert_non_null(ret);
    cJSON *path = cJSON_GetObjectItem(ret, "path");
    assert_non_null(path);
    assert_string_equal(path->valuestring, f_path);
    cJSON *timestamp = cJSON_GetObjectItem(ret, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184220);
}


void test_fim_json_compare_attrs(void **state)
{
    (void) state;
    cJSON *ret;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    fim_entry_data *old_data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    fim_entry_data *new_data = fill_entry_struct(
        1501,
        "0666",
        "rw-rw-rw-",
        "101",
        "1001",
        "test1",
        "testing1",
        1570184224,
        606061,
        "3691689a513ace7e508297b583d7550d",
        "07f05add1049244e7e75ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e9959643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184221,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    ret = fim_json_compare_attrs(
        old_data,
        new_data
    );

    *state = ret;
    free_entry_data(old_data);
    free_entry_data(new_data);

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 11);
}


void test_fim_audit_json(void **state)
{
    (void) state;
    cJSON *ret;

    whodata_evt *w_evt;
    w_evt = calloc(1, sizeof(whodata_evt));
    w_evt->user_id = strdup("100");
    w_evt->user_name = strdup("test");
    w_evt->group_id = strdup("1000");
    w_evt->group_name = strdup("testing");
    w_evt->process_name = strdup("test_proc");
    w_evt->path = strdup("./test/test.file");
    w_evt->audit_uid = strdup("99");
    w_evt->audit_name = strdup("audit_user");
    w_evt->effective_uid = strdup("999");
    w_evt->effective_name = strdup("effective_user");
    w_evt->inode = strdup("606060");
    w_evt->dev = strdup("12345678");
    w_evt->ppid = 1000;
    w_evt->process_id = 1001;

    ret = fim_audit_json(w_evt);

    *state = ret;
    free_whodata_event(w_evt);

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 12);
}


void test_fim_check_ignore_strncasecmp(void **state)
{
    (void) state;
    int ret;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    ret = fim_check_ignore("/EtC/dumPDateS");

    assert_int_equal(ret, 1);
}


void test_fim_check_ignore_regex(void **state)
{
    (void) state;
    int ret;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    ret = fim_check_ignore("/test/files/test.swp");

    assert_int_equal(ret, 1);
}


void test_fim_check_ignore_failure(void **state)
{
    (void) state;
    int ret;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    ret = fim_check_ignore("/test/files/test.sp");

    assert_int_equal(ret, 0);
}


void test_fim_check_restrict_success(void **state)
{
    (void) state;
    int ret;

    OSMatch *restriction;
    restriction = calloc(1, sizeof(OSMatch));
    OSMatch_Compile("test$", restriction, 0);

    ret = fim_check_restrict("my_test", restriction);
    OSMatch_FreePattern(restriction);

    assert_int_equal(ret, 0);
}


void test_fim_check_restrict_failure(void **state)
{
    (void) state;
    int ret;

    OSMatch *restriction;
    restriction = calloc(1, sizeof(OSMatch));
    OSMatch_Compile("test$", restriction, 0);

    ret = fim_check_restrict("my_test_", restriction);
    OSMatch_FreePattern(restriction);

    assert_int_equal(ret, 1);
}


void test_fim_scan_info_json_start(void **state)
{
    (void) state;
    cJSON *ret;

    ret = fim_scan_info_json(FIM_SCAN_START, 1570184220);
    *state = ret;

    assert_non_null(ret);
    cJSON *type = cJSON_GetObjectItem(ret, "type");;
    assert_string_equal(type->valuestring, "scan_start");
}


void test_fim_scan_info_json_end(void **state)
{
    (void) state;
    cJSON *ret;

    ret = fim_scan_info_json(FIM_SCAN_END, 1570184220);
    *state = ret;

    assert_non_null(ret);
    cJSON *type = cJSON_GetObjectItem(ret, "type");;
    assert_string_equal(type->valuestring, "scan_end");
}


void test_fim_get_checksum(void **state)
{
    (void) state;
    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        ""
    );

    *state = data;
    fim_get_checksum(data);
    assert_string_equal(data->checksum, "2bbaf80d6c1af7d5b2c89c27e8a21eda17de6019");
}


void test_fim_get_checksum_wrong_size(void **state)
{
    (void) state;
    fim_entry_data *data = fill_entry_struct(
        -1,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        ""
    );

    *state = data;
    fim_get_checksum(data);
    assert_string_equal(data->checksum, "551cab7f774d4633a3be09207b4cdea1db03b9c0");
}


void test_fim_check_depth_success(void **state)
{
    (void) state;
    int ret;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    char * path = "/usr/bin/folder1/folder2/folder3/file";
    // Pos 1 = "/usr/bin"
    ret = fim_check_depth(path, 1);

    assert_int_equal(ret, 3);

}


void test_fim_check_depth_failure_strlen(void **state)
{
    (void) state;
    int ret;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    char * path = "fl/fd";
    // Pos 1 = "/usr/bin"
    ret = fim_check_depth(path, 1);

    assert_int_equal(ret, -1);

}


void test_fim_insert_success_new(void **state)
{
    (void) state;
    int ret;
    int status;

    char * file = "test-file.tst";
    struct stat file_stat;
    file_stat.st_dev = 2050;
    file_stat.st_ino = 922287;

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    // Not duplicated
    will_return(__wrap_rbtree_insert, 1);
    // Not in hash table
    will_return(__wrap_OSHash_Get, NULL);
    // Added
    will_return(__wrap_OSHash_Add, 2);

    ret = fim_insert(file, data, file_stat);

    assert_int_equal(ret, 0);

}


void test_fim_insert_success_add(void **state)
{
    (void) state;
    int ret;
    int status;

    char * file = "test-file.tst";
    struct stat file_stat;
    file_stat.st_dev = 2050;
    file_stat.st_ino = 922287;

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    // Not duplicated
    will_return(__wrap_rbtree_insert, 1);
    // Already in hash table
    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray(file, inode_data->paths);
    will_return(__wrap_OSHash_Get, inode_data);

    ret = fim_insert(file, data, file_stat);

    assert_int_equal(ret, 0);
}


void test_fim_insert_failure_new(void **state)
{
    (void) state;
    int ret;
    int status;

    char * file = "test-file.tst";
    struct stat file_stat;
    file_stat.st_dev = 2050;
    file_stat.st_ino = 922287;

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    // Not duplicated
    will_return(__wrap_rbtree_insert, 1);
    // Not in hash table
    will_return(__wrap_OSHash_Get, NULL);
    // Errod adding
    will_return(__wrap_OSHash_Add, 1);

    ret = fim_insert(file, data, file_stat);

    assert_int_equal(ret, -1);
}


void test_fim_insert_failure_duplicated(void **state)
{
    (void) state;
    int ret;
    int status;

    char * file = "test-file.tst";
    struct stat file_stat;
    file_stat.st_dev = 2050;
    file_stat.st_ino = 922287;

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    // Duplicated
    will_return(__wrap_rbtree_insert, 0);

    ret = fim_insert(file, data, file_stat);

    assert_int_equal(ret, -1);
}


void test_fim_update_success(void **state)
{
    (void) state;
    int ret;

    char * file = "test-file.tst";

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    // (fim_update_inode) In hash table
    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray("test.file", inode_data->paths);
    will_return(__wrap_OSHash_Get, inode_data);

    will_return(__wrap_rbtree_replace, 1);

    ret = fim_update(file, data, data);

    assert_int_equal(ret, 0);
}


void test_fim_update_failure_nofile(void **state)
{
    (void) state;
    int ret;

    char * file = "test-file.tst";

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    ret = fim_update(NULL, data, data);

    assert_int_equal(ret, -1);
}


void test_fim_update_failure_rbtree(void **state)
{
    (void) state;
    int ret;

    char * file = "test-file.tst";

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    // (fim_update_inode) In hash table
    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray("test.file", inode_data->paths);
    will_return(__wrap_OSHash_Get, inode_data);

    will_return(__wrap_rbtree_replace, 0);

    ret = fim_update(file, data, data);

    assert_int_equal(ret, -1);
}


void test_fim_delete_no_data(void **state)
{
    (void) state;
    int ret;

    char * file_name = "test-file.tst";
    will_return(__wrap_rbtree_get, NULL);

    fim_delete(file_name);
}


void test_fim_update_inode_in_hash(void **state)
{
    (void) state;
    int ret;

    char * file = "test-file.tst";
    char * inode_key = "1212:9090";

    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray("test.file", inode_data->paths);
    will_return(__wrap_OSHash_Get, inode_data);

    ret = fim_update_inode(file, inode_key);

    free(inode_data);

    assert_int_equal(ret, 0);
}


void test_fim_update_inode_not_in_hash(void **state)
{
    (void) state;
    int ret;

    char * file = "test-file.tst";
    char * inode_key = "1212:9090";

    will_return(__wrap_OSHash_Get, NULL);
    will_return(__wrap_OSHash_Add, 2);

    ret = fim_update_inode(file, inode_key);

    assert_int_equal(ret, 0);
}


void test_fim_update_inode_not_in_hash_not_added(void **state)
{
    (void) state;
    int ret;

    char * file = "test-file.tst";
    char * inode_key = "1212:9090";

    will_return(__wrap_OSHash_Get, NULL);
    will_return(__wrap_OSHash_Add, 1);

    ret = fim_update_inode(file, inode_key);

    assert_int_equal(ret, -1);
}


void test_fim_configuration_directory_no_path(void **state)
{
    (void) state;
    int ret;

    const char * entry = "file";

    ret = fim_configuration_directory(NULL, entry);

    assert_int_equal(ret, -1);
}


void test_fim_configuration_directory_file(void **state)
{
    (void) state;
    int ret;

    const char * path = "/media";
    const char * entry = "file";

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, 3);
}


void test_fim_configuration_directory_not_found(void **state)
{
    (void) state;
    int ret;

    const char *path = "/invalid";
    const char *entry = "file";

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, -1);
}


void test_init_fim_data_entry(void **state)
{
    (void) state;

    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));

    init_fim_data_entry(data);
    *state = data;

    assert_int_equal(data->size, 0);
    assert_null(data->perm);
    assert_null(data->attributes);
    assert_null(data->uid);
    assert_null(data->gid);
    assert_null(data->user_name);
    assert_null(data->group_name);
    assert_int_equal(data->mtime, 0);
    assert_int_equal(data->inode, 0);
    assert_int_equal(data->hash_md5[0], 0);
    assert_int_equal(data->hash_sha1[0], 0);
    assert_int_equal(data->hash_sha256[0], 0);
}


void test_fim_audit_inode_event_modify(void **state)
{
    (void) state;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    char * file = "/test/test.file2";
    char * inode_key = "1212:9090";

    whodata_evt *w_evt;
    w_evt = calloc(1, sizeof(whodata_evt));
    w_evt->user_id = strdup("100");
    w_evt->user_name = strdup("test");
    w_evt->group_id = strdup("1000");
    w_evt->group_name = strdup("testing");
    w_evt->process_name = strdup("test_proc");
    w_evt->path = strdup("/test/test.file");
    w_evt->audit_uid = strdup("99");
    w_evt->audit_name = strdup("audit_user");
    w_evt->effective_uid = strdup("999");
    w_evt->effective_name = strdup("effective_user");
    w_evt->inode = strdup("606060");
    w_evt->dev = strdup("12345678");
    w_evt->ppid = 1000;
    w_evt->process_id = 1001;

    // Already in hash table
    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray(file, inode_data->paths);
    will_return(__wrap_OSHash_Get_ex, inode_data);

    fim_audit_inode_event(file, inode_key, FIM_WHODATA, w_evt);

    free_whodata_event(w_evt);
}


void test_fim_audit_inode_event_add(void **state)
{
    (void) state;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    char * file = "/test/test.file2";
    char * inode_key = "1212:9090";

    whodata_evt *w_evt;
    w_evt = calloc(1, sizeof(whodata_evt));
    w_evt->user_id = strdup("100");
    w_evt->user_name = strdup("test");
    w_evt->group_id = strdup("1000");
    w_evt->group_name = strdup("testing");
    w_evt->process_name = strdup("test_proc");
    w_evt->path = strdup("/test/test.file");
    w_evt->audit_uid = strdup("99");
    w_evt->audit_name = strdup("audit_user");
    w_evt->effective_uid = strdup("999");
    w_evt->effective_name = strdup("effective_user");
    w_evt->inode = strdup("606060");
    w_evt->dev = strdup("12345678");
    w_evt->ppid = 1000;
    w_evt->process_id = 1001;

    // Not in hash table
    will_return(__wrap_OSHash_Get_ex, NULL);

    fim_audit_inode_event(file, inode_key, FIM_WHODATA, w_evt);

    free_whodata_event(w_evt);
}


void test_fim_checker_file(void **state)
{
    (void) state;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    whodata_evt *w_evt;
    w_evt = calloc(1, sizeof(whodata_evt));
    w_evt->user_id = strdup("100");
    w_evt->user_name = strdup("test");
    w_evt->group_id = strdup("1000");
    w_evt->group_name = strdup("testing");
    w_evt->process_name = strdup("test_proc");
    w_evt->path = strdup("/test/test.file");
    w_evt->audit_uid = strdup("99");
    w_evt->audit_name = strdup("audit_user");
    w_evt->effective_uid = strdup("999");
    w_evt->effective_name = strdup("effective_user");
    w_evt->inode = strdup("606060");
    w_evt->dev = strdup("12345678");
    w_evt->ppid = 1000;
    w_evt->process_id = 1001;

    char * path = "/media/test.file";
    fim_element *item = calloc(1, sizeof(fim_element));
    struct stat buf;
    buf.st_mode = S_IFREG;
    item->index = 3;
    item->statbuf = buf;
    will_return(__wrap_lstat, 0);

    fim_checker(path, item, w_evt, 1);

    free(item);
    free_whodata_event(w_evt);
}


void test_fim_checker_directory(void **state)
{
    (void) state;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    char * path = "/media/test.file";
    fim_element *item = calloc(1, sizeof(fim_element));
    struct stat buf;
    buf.st_mode = S_IFDIR;
    item->index = 3;
    item->statbuf = buf;
    will_return(__wrap_lstat, 0);
    will_return(__wrap_opendir, 0);

    fim_checker(path, item, NULL, 1);

    free(item);
}


void test_fim_checker_link(void **state)
{
    (void) state;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    char * path = "/media/test.file";
    fim_element *item = calloc(1, sizeof(fim_element));
    struct stat buf;
    buf.st_mode = S_IFLNK;

    item->index = 3;
    item->statbuf = buf;
    item->configuration = 511;
    item->mode = 1;

    will_return(__wrap_lstat, 0);
    will_return(__wrap_rbtree_get, NULL);
    will_return(__wrap_rbtree_insert, 0);

    fim_checker(path, item, NULL, 1);

    free(item);
}


void test_fim_checker_deleted(void **state)
{
    (void) state;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    char * path = "/media/test.file";
    fim_element *item = calloc(1, sizeof(fim_element));
    struct stat buf;
    buf.st_mode = S_IFREG;
    item->index = 3;
    item->statbuf = buf;

    will_return(__wrap_lstat, -1);
    errno = 1;

    fim_checker(path, item, NULL, 1);

    free(item);
}


void test_fim_checker_deleted_enoent(void **state)
{
    (void) state;

    // Load syscheck default values
    syscheck_set_internals();
    Read_Syscheck_Config("test_syscheck.conf");

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    char * path = "/media/test.file";
    fim_element *item = calloc(1, sizeof(fim_element));
    struct stat buf;
    buf.st_mode = S_IFREG;
    item->index = 3;
    item->statbuf = buf;

    will_return(__wrap_lstat, -1);
    errno = ENOENT;
    will_return(__wrap_rbtree_get, data);
    will_return(__wrap_rbtree_get, NULL);

    fim_checker(path, item, NULL, 1);

    free(item);
}


void test_fim_scan(void **state)
{
    (void) state;
    int ret;
    Read_Syscheck_Config("test_syscheck.conf");

    char ** keys = malloc(2 * sizeof(char *));
    keys[0] = NULL;

    will_return(__wrap_rbtree_keys, keys);

    will_return_always(__wrap_lstat, 0);

    will_return_always(__wrap_OSHash_Get_ex, NULL);

    fim_scan();
}


void test_fim_directory_nodir(void **state)
{
    (void) state;
    int ret;

    ret = fim_directory(NULL, NULL, NULL, 1);

    assert_int_equal(ret, -1);
}


void test_fim_directory(void **state)
{
    (void) state;
    int ret;

    struct dirent *entry = calloc(1, sizeof(struct dirent));
    strcpy(entry->d_name, "test");

    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, entry);
    will_return(__wrap_readdir, NULL);

    fim_element *item = calloc(1, sizeof(fim_element));
    item->index = 1;

    ret = fim_directory("test", item, NULL, 1);
    free(entry);
    free(item);

    assert_int_equal(ret, 0);
}


void test_fim_get_data(void **state)
{
    (void) state;

    fim_entry_data *data;

    fim_element *item = calloc(1, sizeof(fim_element));
    item->index = 1;
    item->configuration = CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM | CHECK_MTIME | \
                          CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP;
    struct stat buf;
    buf.st_mode = S_IFREG | 00444 ;
    buf.st_size = 1500;
    buf.st_uid = 0;
    buf.st_gid = 0;
    item->statbuf = buf;

    data = fim_get_data("test", item);
    *state = data;
    free(item);

    assert_string_equal(data->perm, "r--r--r--");
    assert_string_equal(data->hash_md5, "d41d8cd98f00b204e9800998ecf8427e");
    assert_string_equal(data->hash_sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_string_equal(data->hash_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}


void test_fim_delete(void **state)
{
    (void) state;

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    will_return(__wrap_rbtree_get, data);
    will_return(__wrap_OSHash_Get, NULL);

    fim_delete("test");

}


void test_fim_realtime_event_add(void **state)
{
    (void) state;

    will_return(__wrap_lstat, 1);
    will_return(__wrap_OSHash_Get_ex, NULL);

    fim_realtime_event("test");
}


void test_fim_realtime_event_deleted(void **state)
{
    (void) state;

    will_return(__wrap_lstat, -1);
    will_return(__wrap_rbtree_get, NULL);

    fim_realtime_event("test");
}


void test_fim_realtime_event_deleted_saved(void **state)
{
    (void) state;

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    will_return(__wrap_lstat, -1);
    will_return(__wrap_rbtree_get, data);
    will_return(__wrap_OSHash_Get_ex, NULL);

    fim_realtime_event("test");
}


void test_check_deleted_files(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("test", keys);

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        12345,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    will_return(__wrap_rbtree_keys, keys);
    will_return(__wrap_rbtree_get, data);

    check_deleted_files();
}

void test_check_deleted_files_scanned(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("test", keys);

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        0,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    will_return(__wrap_rbtree_keys, keys);
    will_return(__wrap_rbtree_get, data);

    check_deleted_files();
}


void test_fim_file_new(void **state)
{
    (void) state;
    int ret;

    fim_element *item = calloc(1, sizeof(fim_element));
    item->index = 1;

    will_return(__wrap_rbtree_get, NULL);

    will_return(__wrap_rbtree_insert, 1);
    will_return(__wrap_OSHash_Get, NULL);
    will_return(__wrap_OSHash_Add, 2);

    ret = fim_file("file", item, NULL, 1);

    free(item);

    assert_int_equal(ret, 0);
}


void test_fim_file_check(void **state)
{
    (void) state;
    int ret;

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        12345678,
        0,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );
    *state = data;

    fim_element *item = calloc(1, sizeof(fim_element));
    item->index = 1;
    item->configuration = 511;

    will_return(__wrap_rbtree_get, data);

    will_return_count(__wrap_OSHash_Get, NULL, 2);
    will_return(__wrap_rbtree_replace, 1);
    will_return(__wrap_OSHash_Add, 2);

    ret = fim_file("file", item, NULL, 1);

    free(item);

    assert_int_equal(ret, 0);
}


void test_free_inode_data(void **state)
{
    (void) state;

    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray("test.file", inode_data->paths);

    free_inode_data(&inode_data);

    assert_null(inode_data);
}


void test_delete_inode_item(void **state)
{
    (void) state;

    char * file = "test-file.tst";
    char * inode_key = "1212:9090";

    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray(file, inode_data->paths);
    will_return(__wrap_OSHash_Get, inode_data);

    will_return(__wrap_OSHash_Delete, 0);

    delete_inode_item(inode_key, file);

    free_inode_data(&inode_data);
}


void test_delete_inode_item_paths(void **state)
{
    (void) state;

    char * file = "test-file.tst";
    char * inode_key = "1212:9090";

    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 2;
    inode_data->paths = os_AddStrArray(file, inode_data->paths);
    inode_data->paths = os_AddStrArray(file, inode_data->paths);
    will_return(__wrap_OSHash_Get, inode_data);

    delete_inode_item(inode_key, file);

    free_inode_data(&inode_data);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_fim_json_event, delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_whodata, delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_no_changes, delete_json),
        cmocka_unit_test_teardown(test_fim_attributes_json, delete_json),
        cmocka_unit_test_teardown(test_fim_entry_json, delete_json),
        cmocka_unit_test_teardown(test_fim_json_compare_attrs, delete_json),
        cmocka_unit_test_teardown(test_fim_audit_json, delete_json),
        cmocka_unit_test(test_fim_check_ignore_strncasecmp),
        cmocka_unit_test(test_fim_check_ignore_regex),
        cmocka_unit_test(test_fim_check_ignore_failure),
        cmocka_unit_test(test_fim_check_restrict_success),
        cmocka_unit_test(test_fim_check_restrict_failure),
        cmocka_unit_test_teardown(test_fim_scan_info_json_start, delete_json),
        cmocka_unit_test_teardown(test_fim_scan_info_json_end, delete_json),
        cmocka_unit_test_teardown(test_fim_get_checksum, delete_entry_data),
        cmocka_unit_test_teardown(test_fim_get_checksum_wrong_size, delete_entry_data),
        cmocka_unit_test(test_fim_check_depth_success),
        cmocka_unit_test(test_fim_check_depth_failure_strlen),
        cmocka_unit_test_teardown(test_fim_insert_success_new, delete_entry_data),
        cmocka_unit_test_teardown(test_fim_insert_success_add, delete_entry_data),
        cmocka_unit_test_teardown(test_fim_insert_failure_duplicated, delete_entry_data),
        cmocka_unit_test_teardown(test_fim_insert_failure_new, delete_entry_data),
        cmocka_unit_test_teardown(test_fim_update_success, delete_entry_data),
        cmocka_unit_test_teardown(test_fim_update_failure_nofile, delete_entry_data),
        cmocka_unit_test_teardown(test_fim_update_failure_rbtree, delete_entry_data),
        cmocka_unit_test(test_fim_delete_no_data),
        cmocka_unit_test(test_fim_update_inode_in_hash),
        cmocka_unit_test(test_fim_update_inode_not_in_hash),
        cmocka_unit_test(test_fim_update_inode_not_in_hash_not_added),
        cmocka_unit_test(test_fim_configuration_directory_no_path),
        cmocka_unit_test(test_fim_configuration_directory_file),
        cmocka_unit_test(test_fim_configuration_directory_not_found),
        cmocka_unit_test_teardown(test_init_fim_data_entry, delete_entry_data),
        cmocka_unit_test(test_fim_audit_inode_event_modify),
        cmocka_unit_test(test_fim_audit_inode_event_add),
        cmocka_unit_test(test_fim_scan),
        cmocka_unit_test(test_fim_checker_file),
        cmocka_unit_test(test_fim_checker_directory),
        cmocka_unit_test(test_fim_checker_deleted),
        cmocka_unit_test(test_fim_checker_link),
        cmocka_unit_test_teardown(test_fim_checker_deleted_enoent, delete_entry_data),
        cmocka_unit_test(test_fim_directory_nodir),
        cmocka_unit_test(test_fim_directory),
        cmocka_unit_test_teardown(test_fim_get_data, delete_entry_data),
        cmocka_unit_test_teardown(test_fim_delete, delete_entry_data),
        cmocka_unit_test(test_fim_realtime_event_add),
        cmocka_unit_test(test_fim_realtime_event_deleted),
        cmocka_unit_test_teardown(test_fim_realtime_event_deleted_saved, delete_entry_data),
        cmocka_unit_test_teardown(test_check_deleted_files, delete_entry_data),
        cmocka_unit_test_teardown(test_check_deleted_files_scanned, delete_entry_data),
        cmocka_unit_test(test_fim_file_new),
        cmocka_unit_test_teardown(test_fim_file_check, delete_entry_data),
        cmocka_unit_test(test_free_inode_data),
        cmocka_unit_test(test_delete_inode_item),
        cmocka_unit_test(test_delete_inode_item_paths),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
