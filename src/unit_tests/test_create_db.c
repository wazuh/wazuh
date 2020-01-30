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
#include "../syscheckd/fim_db.h"

/* auxiliary structs */
typedef struct __fim_data_s {
    fim_element *item;
    whodata_evt *w_evt;
    fim_entry *fentry;
    fim_inode_data *inode_data;
    fim_entry_data *new_data;
    fim_entry_data *old_data;
    fim_entry_data *local_data; // Used on certain tests, not affected by group setup/teardown
    struct dirent *entry;       // Used on fim_directory tests, not affected by group setup/teardown
    cJSON *json;
}fim_data_t;

/* redefinitons/wrapping */

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
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

void __wrap_send_syscheck_msg(char *msg) {
    return;
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

int __wrap_realtime_adddir(const char *dir, __attribute__((unused)) int whodata) {
    check_expected(dir);

    return 0;
}

bool __wrap_HasFilesystem(__attribute__((unused))const char * path, __attribute__((unused))fs_set set) {
    check_expected(path);

    return mock();
}

fim_entry *__wrap_fim_db_get_path(fdb_t *fim_sql, const char *file_path) {
    check_expected_ptr(fim_sql);
    check_expected(file_path);

    return mock_type(fim_entry*);
}

char **__wrap_fim_db_get_paths_from_inode(fdb_t *fim_sql, const unsigned long int inode, const unsigned long int dev) {
    check_expected_ptr(fim_sql);
    check_expected(inode);
    check_expected(dev);

    return mock_type(char **);
}

int __wrap_delete_target_file(const char *path) {
    check_expected(path);

    return mock();
}

int __wrap_fim_db_insert_data(fdb_t *fim_sql, const char *file_path, fim_entry_data *entry) {
    check_expected_ptr(fim_sql);
    check_expected(file_path);

    return mock();
}

int __wrap_OS_MD5_SHA1_SHA256_File(const char *fname, const char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output, os_sha256 sha256output, int mode, size_t max_size) {
    check_expected(fname);
    check_expected(prefilter_cmd);
    check_expected(md5output);
    check_expected(sha1output);
    check_expected(sha256output);
    check_expected(mode);
    check_expected(max_size);

    return mock();
}

int __wrap_fim_db_delete_not_scanned(fdb_t * fim_sql) {
    check_expected_ptr(fim_sql);

    return mock();
}

/* setup/teardowns */
static int setup_group(void **state) {
    fim_data_t *fim_data = calloc(1, sizeof(fim_data_t));

    if(fim_data == NULL)
        return -1;

    if(fim_data->item = calloc(1, sizeof(fim_element)), fim_data->item == NULL)
        return -1;

    if(fim_data->w_evt = calloc(1, sizeof(whodata_evt)), fim_data->w_evt == NULL)
        return -1;

    if(fim_data->fentry = calloc(1, sizeof(fim_entry)), fim_data->fentry == NULL)
        return -1;

    if(fim_data->new_data = calloc(1, sizeof(fim_entry_data)), fim_data->new_data == NULL)
        return -1;

    if(fim_data->old_data = calloc(1, sizeof(fim_entry_data)), fim_data->old_data == NULL)
        return -1;

    // Setup mock whodata event
    fim_data->w_evt->user_id = strdup("100");
    fim_data->w_evt->user_name = strdup("test");
    fim_data->w_evt->group_id = strdup("1000");
    fim_data->w_evt->group_name = strdup("testing");
    fim_data->w_evt->process_name = strdup("test_proc");
    fim_data->w_evt->path = strdup("./test/test.file");
    fim_data->w_evt->audit_uid = strdup("99");
    fim_data->w_evt->audit_name = strdup("audit_user");
    fim_data->w_evt->effective_uid = strdup("999");
    fim_data->w_evt->effective_name = strdup("effective_user");
    fim_data->w_evt->inode = strdup("606060");
    fim_data->w_evt->dev = strdup("12345678");
    fim_data->w_evt->ppid = 1000;
    fim_data->w_evt->process_id = 1001;

    // Setup mock old fim_entry
    fim_data->old_data->size = 1500;
    fim_data->old_data->perm = strdup("0664");
    fim_data->old_data->attributes = strdup("r--r--r--");
    fim_data->old_data->uid = strdup("100");
    fim_data->old_data->gid = strdup("1000");
    fim_data->old_data->user_name = strdup("test");
    fim_data->old_data->group_name = strdup("testing");;
    fim_data->old_data->mtime = 1570184223;
    fim_data->old_data->inode = 606060;
    strcpy(fim_data->old_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->old_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->old_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->old_data->mode = FIM_REALTIME;
    fim_data->old_data->last_event = 1570184220;
    fim_data->old_data->entry_type = FIM_TYPE_FILE;
    fim_data->old_data->dev = 12345678;
    fim_data->old_data->scanned = 123456;
    fim_data->old_data->options = 511;
    strcpy(fim_data->old_data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    // Setup mock new fim_entry
    fim_data->new_data->size = 1501;
    fim_data->new_data->perm = strdup("0666");
    fim_data->new_data->attributes = strdup("rw-rw-rw-");
    fim_data->new_data->uid = strdup("101");
    fim_data->new_data->gid = strdup("1001");
    fim_data->new_data->user_name = strdup("test1");
    fim_data->new_data->group_name = strdup("testing1");;
    fim_data->new_data->mtime = 1570184224;
    fim_data->new_data->inode = 606061;
    strcpy(fim_data->new_data->hash_md5, "3691689a513ace7e508297b583d7550d");
    strcpy(fim_data->new_data->hash_sha1, "07f05add1049244e7e75ad0f54f24d8094cd8f8b");
    strcpy(fim_data->new_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e9959643c6262667b61fbe57694df224d40");
    fim_data->new_data->mode = FIM_REALTIME;
    fim_data->new_data->last_event = 1570184221;
    fim_data->new_data->entry_type = FIM_TYPE_FILE;
    fim_data->new_data->dev = 12345678;
    fim_data->new_data->scanned = 123456;
    fim_data->new_data->options = 511;
    strcpy(fim_data->new_data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    fim_data->json = NULL;

    *state = fim_data;

    // Read and setup global values.
    Read_Syscheck_Config("test_syscheck.conf");

    syscheck.tsleep = 1;
    syscheck.sleep_after = 100;
    syscheck.rt_delay = 1;
    syscheck.max_depth = 256;
    syscheck.file_max_size = 1024;

    return 0;
}

static int teardown_group(void **state) {
    fim_data_t *fim_data = *state;

    free(fim_data->item);
    free_whodata_event(fim_data->w_evt);
    free_entry_data(fim_data->new_data);
    free_entry_data(fim_data->old_data);
    free(fim_data);

    Free_Syscheck(&syscheck);

    return 0;
}

static int teardown_delete_json(void **state) {
    fim_data_t *fim_data = *state;
    cJSON_Delete(fim_data->json);
    return 0;
}

static int setup_local_data(void **state) {
    fim_data_t *fim_data = *state;

    if(fim_data->local_data = calloc(1, sizeof(fim_entry_data)), fim_data->local_data == NULL)
        return -1;

    return 0;
}

static int teardown_local_data(void **state) {
    fim_data_t *fim_data = *state;

    free_entry_data(fim_data->local_data);
    return 0;
}

static int setup_inode_data(void **state) {
    fim_data_t *fim_data = *state;


    if(fim_data->inode_data = calloc(1, sizeof(fim_inode_data)), fim_data->inode_data == NULL)
        return -1;

    return 0;
}

static int teardown_inode_data(void **state) {
    fim_data_t *fim_data = *state;

    free_inode_data(&fim_data->inode_data);

    return 0;
}

static int setup_struct_dirent(void **state) {
    fim_data_t *fim_data = *state;

    if(fim_data->entry = calloc(1, sizeof(struct dirent)), fim_data->entry == NULL)
        return -1;

    return 0;
}

static int teardown_struct_dirent(void **state) {
    fim_data_t *fim_data = *state;

    free(fim_data->entry);

    return 0;
}

/* tests */
static void test_fim_json_event(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_json_event(
                    "test.file",
                    fim_data->old_data,
                    fim_data->new_data,
                    1,
                    FIM_MODIFICATION,
                    FIM_REALTIME,
                    NULL
                );

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "event");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *path = cJSON_GetObjectItem(data, "path");
    assert_string_equal(cJSON_GetStringValue(path), "test.file");
    cJSON *mode = cJSON_GetObjectItem(data, "mode");
    assert_string_equal(cJSON_GetStringValue(mode), "real-time");
    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    assert_string_equal(cJSON_GetStringValue(data_type), "modified");
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184221);
    cJSON *tags = cJSON_GetObjectItem(data, "tags");
    assert_string_equal(cJSON_GetStringValue(tags), "tag1,tag2");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    assert_non_null(changed_attributes);
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);

    assert_int_equal(cJSON_GetArraySize(changed_attributes), 11);
    assert_int_equal(cJSON_GetArraySize(attributes), 13);
    assert_int_equal(cJSON_GetArraySize(old_attributes), 13);
}


static void test_fim_json_event_whodata(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_json_event(
        "test.file",
        fim_data->old_data,
        fim_data->new_data,
        1,
        FIM_MODIFICATION,
        FIM_WHODATA,
        fim_data->w_evt
    );

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "event");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *path = cJSON_GetObjectItem(data, "path");
    assert_string_equal(cJSON_GetStringValue(path), "test.file");
    cJSON *mode = cJSON_GetObjectItem(data, "mode");
    assert_string_equal(cJSON_GetStringValue(mode), "whodata");
    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    assert_string_equal(cJSON_GetStringValue(data_type), "modified");
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184221);
    cJSON *tags = cJSON_GetObjectItem(data, "tags");
    assert_string_equal(cJSON_GetStringValue(tags), "tag1,tag2");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    assert_non_null(audit);
    assert_int_equal(cJSON_GetArraySize(audit), 12);
}


static void test_fim_json_event_no_changes(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_json_event(
                        "test.file",
                        fim_data->new_data,
                        fim_data->new_data,
                        1,
                        FIM_MODIFICATION,
                        FIM_WHODATA,
                        NULL
                    );

    assert_null(fim_data->json);
}


static void test_fim_attributes_json(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_attributes_json(fim_data->old_data);

    assert_non_null(fim_data->json);
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 13);

    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "file");
    cJSON *size = cJSON_GetObjectItem(fim_data->json, "size");
    assert_non_null(size);
    assert_int_equal(size->valueint, 1500);
    cJSON *perm = cJSON_GetObjectItem(fim_data->json, "perm");
    assert_string_equal(cJSON_GetStringValue(perm), "0664");
    cJSON *uid = cJSON_GetObjectItem(fim_data->json, "uid");
    assert_string_equal(cJSON_GetStringValue(uid), "100");
    cJSON *gid = cJSON_GetObjectItem(fim_data->json, "gid");
    assert_string_equal(cJSON_GetStringValue(gid), "1000");
    cJSON *user_name = cJSON_GetObjectItem(fim_data->json, "user_name");
    assert_string_equal(cJSON_GetStringValue(user_name), "test");
    cJSON *group_name = cJSON_GetObjectItem(fim_data->json, "group_name");
    assert_string_equal(cJSON_GetStringValue(group_name), "testing");
    cJSON *inode = cJSON_GetObjectItem(fim_data->json, "inode");
    assert_non_null(inode);
    assert_int_equal(inode->valueint, 606060);
    cJSON *mtime = cJSON_GetObjectItem(fim_data->json, "mtime");
    assert_non_null(mtime);
    assert_int_equal(mtime->valueint, 1570184223);
    cJSON *hash_md5 = cJSON_GetObjectItem(fim_data->json, "hash_md5");
    assert_string_equal(cJSON_GetStringValue(hash_md5), "3691689a513ace7e508297b583d7050d");
    cJSON *hash_sha1 = cJSON_GetObjectItem(fim_data->json, "hash_sha1");
    assert_string_equal(cJSON_GetStringValue(hash_sha1), "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    cJSON *hash_sha256 = cJSON_GetObjectItem(fim_data->json, "hash_sha256");
    assert_string_equal(cJSON_GetStringValue(hash_sha256), "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    cJSON *checksum = cJSON_GetObjectItem(fim_data->json, "checksum");
    assert_string_equal(cJSON_GetStringValue(checksum), "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}


static void test_fim_entry_json(void **state) {
    fim_data_t *fim_data = *state;
    const char *f_path = "/dir/test";

    fim_data->json = fim_entry_json(f_path, fim_data->old_data);

    assert_non_null(fim_data->json);
    cJSON *path = cJSON_GetObjectItem(fim_data->json, "path");
    assert_non_null(path);
    assert_string_equal(path->valuestring, f_path);
    cJSON *timestamp = cJSON_GetObjectItem(fim_data->json, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184220);
}

static void test_fim_entry_json_null_path(void **state) {
    fim_data_t *fim_data = *state;

    expect_assert_failure(fim_entry_json(NULL, fim_data->old_data));
}
static void test_fim_entry_json_null_data(void **state) {
    expect_assert_failure(fim_entry_json("/a/path", NULL));
}

static void test_fim_json_compare_attrs(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_json_compare_attrs(
        fim_data->old_data,
        fim_data->new_data
    );

    assert_non_null(fim_data->json);
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 11);

    cJSON *size = cJSON_GetArrayItem(fim_data->json, 0);
    assert_string_equal(cJSON_GetStringValue(size), "size");
    cJSON *permission = cJSON_GetArrayItem(fim_data->json, 1);
    assert_string_equal(cJSON_GetStringValue(permission), "permission");
    cJSON *uid = cJSON_GetArrayItem(fim_data->json, 2);
    assert_string_equal(cJSON_GetStringValue(uid), "uid");
    cJSON *user_name = cJSON_GetArrayItem(fim_data->json, 3);
    assert_string_equal(cJSON_GetStringValue(user_name), "user_name");
    cJSON *gid = cJSON_GetArrayItem(fim_data->json, 4);
    assert_string_equal(cJSON_GetStringValue(gid), "gid");
    cJSON *group_name = cJSON_GetArrayItem(fim_data->json, 5);
    assert_string_equal(cJSON_GetStringValue(group_name), "group_name");
    cJSON *mtime = cJSON_GetArrayItem(fim_data->json, 6);
    assert_string_equal(cJSON_GetStringValue(mtime), "mtime");
    cJSON *inode = cJSON_GetArrayItem(fim_data->json, 7);
    assert_string_equal(cJSON_GetStringValue(inode), "inode");
    cJSON *md5 = cJSON_GetArrayItem(fim_data->json, 8);
    assert_string_equal(cJSON_GetStringValue(md5), "md5");
    cJSON *sha1 = cJSON_GetArrayItem(fim_data->json, 9);
    assert_string_equal(cJSON_GetStringValue(sha1), "sha1");
    cJSON *sha256 = cJSON_GetArrayItem(fim_data->json, 10);
    assert_string_equal(cJSON_GetStringValue(sha256), "sha256");

}


static void test_fim_audit_json(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_audit_json(fim_data->w_evt);

    assert_non_null(fim_data->json);
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 12);

    cJSON *path = cJSON_GetObjectItem(fim_data->json, "path");
    assert_string_equal(cJSON_GetStringValue(path), "./test/test.file");
    cJSON *user_id = cJSON_GetObjectItem(fim_data->json, "user_id");
    assert_string_equal(cJSON_GetStringValue(user_id), "100");
    cJSON *user_name = cJSON_GetObjectItem(fim_data->json, "user_name");
    assert_string_equal(cJSON_GetStringValue(user_name), "test");
    cJSON *process_name = cJSON_GetObjectItem(fim_data->json, "process_name");
    assert_string_equal(cJSON_GetStringValue(process_name), "test_proc");
    cJSON *process_id = cJSON_GetObjectItem(fim_data->json, "process_id");
    assert_non_null(process_id);
    assert_int_equal(process_id->valueint, 1001);
    cJSON *group_id = cJSON_GetObjectItem(fim_data->json, "group_id");
    assert_string_equal(cJSON_GetStringValue(group_id), "1000");
    cJSON *group_name = cJSON_GetObjectItem(fim_data->json, "group_name");
    assert_string_equal(cJSON_GetStringValue(group_name), "testing");
    cJSON *audit_uid = cJSON_GetObjectItem(fim_data->json, "audit_uid");
    assert_string_equal(cJSON_GetStringValue(audit_uid), "99");
    cJSON *audit_name = cJSON_GetObjectItem(fim_data->json, "audit_name");
    assert_string_equal(cJSON_GetStringValue(audit_name), "audit_user");
    cJSON *effective_uid = cJSON_GetObjectItem(fim_data->json, "effective_uid");
    assert_string_equal(cJSON_GetStringValue(effective_uid), "999");
    cJSON *effective_name = cJSON_GetObjectItem(fim_data->json, "effective_name");
    assert_string_equal(cJSON_GetStringValue(effective_name), "effective_user");
    cJSON *ppid = cJSON_GetObjectItem(fim_data->json, "ppid");
    assert_non_null(ppid);
    assert_int_equal(ppid->valueint, 1000);
}


static void test_fim_check_ignore_strncasecmp(void **state) {
   int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "(6204): Ignoring 'file' '/EtC/dumPDateS' due to '/etc/dumpdates'");

    ret = fim_check_ignore("/EtC/dumPDateS");

    assert_int_equal(ret, 1);
}


static void test_fim_check_ignore_regex(void **state) {
   int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "(6205): Ignoring 'file' '/test/files/test.swp' due to sregex '.log$|.swp$'");

    ret = fim_check_ignore("/test/files/test.swp");

    assert_int_equal(ret, 1);
}


static void test_fim_check_ignore_failure(void **state) {
   int ret;

    ret = fim_check_ignore("/test/files/test.sp");

    assert_int_equal(ret, 0);
}


static void test_fim_check_restrict_success(void **state) {
   int ret;

    OSMatch *restriction;
    restriction = calloc(1, sizeof(OSMatch));
    OSMatch_Compile("test$", restriction, 0);

    ret = fim_check_restrict("my_test", restriction);
    OSMatch_FreePattern(restriction);
    free(restriction);

    assert_int_equal(ret, 0);
}


static void test_fim_check_restrict_failure(void **state) {
   int ret;

    OSMatch *restriction;
    restriction = calloc(1, sizeof(OSMatch));
    OSMatch_Compile("test$", restriction, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6203): Ignoring file 'my_test_' due to restriction 'test$'");

    ret = fim_check_restrict("my_test_", restriction);
    OSMatch_FreePattern(restriction);
    free(restriction);

    assert_int_equal(ret, 1);
}

static void test_fim_check_restrict_null_filename(void **state) {
   int ret;

    OSMatch *restriction;
    restriction = calloc(1, sizeof(OSMatch));
    OSMatch_Compile("test$", restriction, 0);

    expect_string(__wrap__merror, formatted_msg, "(1105): Attempted to use null string.");

    ret = fim_check_restrict(NULL, restriction);
    OSMatch_FreePattern(restriction);
    free(restriction);

    assert_int_equal(ret, 1);
}

static void test_fim_check_restrict_null_restriction(void **state) {
   int ret;

    ret = fim_check_restrict("my_test", NULL);

    assert_int_equal(ret, 0);
}


static void test_fim_scan_info_json_start(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_scan_info_json(FIM_SCAN_START, 1570184220);

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");;
    assert_string_equal(type->valuestring, "scan_start");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184220);
}


static void test_fim_scan_info_json_end(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_scan_info_json(FIM_SCAN_END, 1570184220);

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");;
    assert_string_equal(type->valuestring, "scan_end");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184220);
}


static void test_fim_get_checksum(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");;
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    fim_get_checksum(fim_data->local_data);
    assert_string_equal(fim_data->local_data->checksum, "2bbaf80d6c1af7d5b2c89c27e8a21eda17de6019");
}


static void test_fim_get_checksum_wrong_size(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->local_data->size = -1;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");;
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    fim_get_checksum(fim_data->local_data);
    assert_string_equal(fim_data->local_data->checksum, "551cab7f774d4633a3be09207b4cdea1db03b9c0");
}


static void test_fim_check_depth_success(void **state) {
    int ret;

    char * path = "/usr/bin/folder1/folder2/folder3/file";
    // Pos 1 = "/usr/bin"
    ret = fim_check_depth(path, 1);

    assert_int_equal(ret, 3);

}


static void test_fim_check_depth_failure_strlen(void **state) {
   int ret;

    char * path = "fl/fd";
    // Pos 1 = "/usr/bin"
    ret = fim_check_depth(path, 1);

    assert_int_equal(ret, -1);

}

static void test_fim_check_depth_failure_null_directory(void **state) {
   int ret;

    char * path = "/usr/bin";
    // Pos 1 = "/usr/bin"
    ret = fim_check_depth(path, 6);

    assert_int_equal(ret, -1);

}

static void test_fim_configuration_directory_no_path(void **state) {
    int ret;

    const char * entry = "file";

    ret = fim_configuration_directory(NULL, entry);

    assert_int_equal(ret, -1);
}


static void test_fim_configuration_directory_file(void **state) {
    int ret;

    const char * path = "/media";
    const char * entry = "file";

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, 3);
}


static void test_fim_configuration_directory_not_found(void **state) {
    int ret;

    const char *path = "/invalid";
    const char *entry = "file";

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/invalid'");

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, -1);
}


static void test_init_fim_data_entry(void **state) {
    fim_data_t *fim_data = *state;

    init_fim_data_entry(fim_data->local_data);

    assert_int_equal(fim_data->local_data->size, 0);
    assert_null(fim_data->local_data->perm);
    assert_null(fim_data->local_data->attributes);
    assert_null(fim_data->local_data->uid);
    assert_null(fim_data->local_data->gid);
    assert_null(fim_data->local_data->user_name);
    assert_null(fim_data->local_data->group_name);
    assert_int_equal(fim_data->local_data->mtime, 0);
    assert_int_equal(fim_data->local_data->inode, 0);
    assert_int_equal(fim_data->local_data->hash_md5[0], 0);
    assert_int_equal(fim_data->local_data->hash_sha1[0], 0);
    assert_int_equal(fim_data->local_data->hash_sha256[0], 0);
}


static void test_fim_audit_inode_event_modify(void **state) {
    fim_data_t *data = *state;

    char * file = "/test/test.file2";
    char **paths = calloc(2, sizeof(char*));

    if(paths == NULL)
        fail();

    paths[0] = strdup(file);
    paths[1] = NULL;

    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 606060);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 12345678);
    will_return(__wrap_fim_db_get_paths_from_inode, paths);

    // Inside fim_checker
    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/test/test.file2'");

    fim_audit_inode_event(file, FIM_WHODATA, data->w_evt);
}


static void test_fim_audit_inode_event_add(void **state) {
    fim_data_t *fim_data = *state;

    char * file = "/test/test.file2";
    char **paths = calloc(2, sizeof(char*));

    if(paths == NULL)
        fail();

    paths[0] = NULL;

    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 606060);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 12345678);
    will_return(__wrap_fim_db_get_paths_from_inode, paths);

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/test/test.file2'");

    fim_audit_inode_event(file, FIM_WHODATA, fim_data->w_evt);
}


static void test_fim_checker_file(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/test.file");
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/media/test.file");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_value(__wrap_fim_db_insert_data, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert_data, file_path, "/media/test.file");
    will_return(__wrap_fim_db_insert_data, 0);

    fim_checker(path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 33279);
    assert_int_equal(fim_data->item->index, 3);
}


static void test_fim_checker_directory(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/";
    struct stat buf;
    buf.st_mode = S_IFDIR;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    will_return_always(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/");
    expect_string(__wrap_HasFilesystem, path, "/media/test");
    will_return_always(__wrap_HasFilesystem, 0);

    expect_string(__wrap_realtime_adddir, dir, "/media/");
    expect_string(__wrap_realtime_adddir, dir, "/media/test");

    strcpy(fim_data->entry->d_name, "test");

    will_return_always(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_readdir, NULL);

    fim_checker(path, fim_data->item, NULL, 1);
}

static void test_fim_checker_link(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    struct stat buf;
    buf.st_mode = S_IFLNK;

    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    fim_data->item->configuration = 511;
    fim_data->item->mode = 1;

    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/test.file");
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/media/test.file");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_value(__wrap_fim_db_insert_data, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert_data, file_path, "/media/test.file");
    will_return(__wrap_fim_db_insert_data, 0);

    fim_checker(path, fim_data->item, NULL, 1);
}


static void test_fim_checker_deleted(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;

    will_return(__wrap_lstat, -1);
    errno = 1;

    fim_checker(path, fim_data->item, NULL, 1);
}


static void test_fim_checker_deleted_enoent(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;

    will_return(__wrap_lstat, -1);
    errno = ENOENT;

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/media/test.file");
    will_return(__wrap_fim_db_get_path, NULL);

    fim_checker(path, fim_data->item, NULL, 1);

    errno = 0;
}


static void test_fim_scan(void **state) {
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // In fim_checker
    will_return_count(__wrap_lstat, 0, 6);

    expect_string(__wrap_HasFilesystem, path, "/etc");
    expect_string(__wrap_HasFilesystem, path, "/usr/bin");
    expect_string(__wrap_HasFilesystem, path, "/usr/sbin");
    expect_string(__wrap_HasFilesystem, path, "/media");
    expect_string(__wrap_HasFilesystem, path, "/home");
    expect_string(__wrap_HasFilesystem, path, "/boot");
    will_return_count(__wrap_HasFilesystem, 0, 6);

    expect_string(__wrap_realtime_adddir, dir, "/media");
    expect_string(__wrap_realtime_adddir, dir, "/home");
    expect_string(__wrap_realtime_adddir, dir, "/boot");

    expect_value(__wrap_fim_db_delete_not_scanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_delete_not_scanned, FIMDB_OK);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

/* fim_directory */
static void test_fim_directory(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    strcpy(fim_data->entry->d_name, "test");

    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'test/test'");

    fim_data->item->index = 1;

    ret = fim_directory("test", fim_data->item, NULL, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_directory_nodir(void **state) {
    int ret;

    expect_string(__wrap__merror, formatted_msg, "(1105): Attempted to use null string.");

    ret = fim_directory(NULL, NULL, NULL, 1);

    assert_int_equal(ret, OS_INVALID);
}

static void test_fim_directory_opendir_error(void **state) {
    int ret;

    will_return(__wrap_opendir, 0);

    expect_string(__wrap__mwarn, formatted_msg, "(6922): Cannot open 'test': Permission denied");

    errno = EACCES;

    ret = fim_directory("test", NULL, NULL, 1);

    errno = 0;

    assert_int_equal(ret, OS_INVALID);
}

/* fim_get_data */
static void test_fim_get_data(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->item->index = 1;
    fim_data->item->configuration = CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM | CHECK_MTIME | \
                          CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP;
    struct stat buf;
    buf.st_mode = S_IFREG | 00444 ;
    buf.st_size = 1000;
    buf.st_uid = 0;
    buf.st_gid = 0;
    fim_data->item->statbuf = buf;

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "test");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    fim_data->local_data = fim_get_data("test", fim_data->item);

    assert_string_equal(fim_data->local_data->perm, "r--r--r--");
    assert_string_equal(fim_data->local_data->hash_md5, "d41d8cd98f00b204e9800998ecf8427e");
    assert_string_equal(fim_data->local_data->hash_sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_string_equal(fim_data->local_data->hash_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_fim_get_data_hash_error(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->item->index = 1;
    fim_data->item->configuration = CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM | CHECK_MTIME | \
                          CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP;
    struct stat buf;
    buf.st_mode = S_IFREG | 00444 ;
    buf.st_size = 1000;
    buf.st_uid = 0;
    buf.st_gid = 0;
    fim_data->item->statbuf = buf;

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "test");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, -1);

    fim_data->local_data = fim_get_data("test", fim_data->item);

    assert_null(fim_data->local_data);
}


static void test_check_deleted_files(void **state) {
    expect_value(__wrap_fim_db_delete_not_scanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_delete_not_scanned, FIMDB_OK);

    check_deleted_files();
}

static void test_check_deleted_files_error(void **state) {
    expect_value(__wrap_fim_db_delete_not_scanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_delete_not_scanned, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, FIM_DB_ERROR_RM_NOT_SCANNED);

    check_deleted_files();
}


static void test_fim_file_add(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    fim_data->item->index = 1;

    // Inside fim_get_data
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "file");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "file");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_value(__wrap_fim_db_insert_data, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert_data, file_path, "file");
    will_return(__wrap_fim_db_insert_data, 0);

    ret = fim_file("file", fim_data->item, NULL, 1);

    assert_int_equal(ret, 0);
}


static void test_fim_file_modify(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    fim_data->item->index = 1;
    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");;
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    // Inside fim_get_data
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "file");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "file");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

    expect_value(__wrap_fim_db_insert_data, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert_data, file_path, "file");
    will_return(__wrap_fim_db_insert_data, 0);

    ret = fim_file("file", fim_data->item, NULL, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_file_no_attributes(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    fim_data->item->index = 1;
    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");;
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    // Inside fim_get_data
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "file");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, -1);

    ret = fim_file("file", fim_data->item, NULL, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_file_error_on_insert(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    fim_data->item->index = 1;
    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");;
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    // Inside fim_get_data
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "file");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "file");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

    expect_value(__wrap_fim_db_insert_data, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert_data, file_path, "file");
    will_return(__wrap_fim_db_insert_data, -1);

    ret = fim_file("file", fim_data->item, NULL, 1);

    assert_int_equal(ret, OS_INVALID);
}

static void test_free_inode_data(void **state) {
    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray("test.file", inode_data->paths);

    free_inode_data(&inode_data);

    assert_null(inode_data);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_json_event */
        cmocka_unit_test_teardown(test_fim_json_event, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_whodata, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_no_changes, teardown_delete_json),

        /* fim_attributes_json */
        cmocka_unit_test_teardown(test_fim_attributes_json, teardown_delete_json),

        /* fim_entry_json */
        cmocka_unit_test_teardown(test_fim_entry_json, teardown_delete_json),
        cmocka_unit_test(test_fim_entry_json_null_path),
        cmocka_unit_test(test_fim_entry_json_null_data),

        /* fim_json_compare_attrs */
        cmocka_unit_test_teardown(test_fim_json_compare_attrs, teardown_delete_json),

        /* fim_audit_json */
        cmocka_unit_test_teardown(test_fim_audit_json, teardown_delete_json),

        /* fim_check_ignore */
        cmocka_unit_test(test_fim_check_ignore_strncasecmp),
        cmocka_unit_test(test_fim_check_ignore_regex),
        cmocka_unit_test(test_fim_check_ignore_failure),

        /* fim_check_restrict */
        cmocka_unit_test(test_fim_check_restrict_success),
        cmocka_unit_test(test_fim_check_restrict_failure),
        cmocka_unit_test(test_fim_check_restrict_null_filename),
        cmocka_unit_test(test_fim_check_restrict_null_restriction),

        /* fim_scan_info */
        cmocka_unit_test_teardown(test_fim_scan_info_json_start, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_scan_info_json_end, teardown_delete_json),

        /* fim_get_checksum */
        cmocka_unit_test_setup_teardown(test_fim_get_checksum, setup_local_data, teardown_local_data),
        cmocka_unit_test_setup_teardown(test_fim_get_checksum_wrong_size, setup_local_data, teardown_local_data),

        /* fim_check_depth */
        cmocka_unit_test(test_fim_check_depth_success),
        cmocka_unit_test(test_fim_check_depth_failure_strlen),
        cmocka_unit_test(test_fim_check_depth_failure_null_directory),

        /* fim_configuration_directory */
        cmocka_unit_test(test_fim_configuration_directory_no_path),
        cmocka_unit_test(test_fim_configuration_directory_file),
        cmocka_unit_test(test_fim_configuration_directory_not_found),

        /* init_fim_data_entry */
        cmocka_unit_test_setup_teardown(test_init_fim_data_entry, setup_local_data, teardown_local_data),

        /* fim_audit_inode_event */
        cmocka_unit_test_setup_teardown(test_fim_audit_inode_event_modify, setup_inode_data, teardown_inode_data),
        cmocka_unit_test(test_fim_audit_inode_event_add),

        cmocka_unit_test(test_fim_scan),

        /* fim_checker */
        cmocka_unit_test(test_fim_checker_file),
        cmocka_unit_test_setup_teardown(test_fim_checker_directory, setup_struct_dirent, teardown_struct_dirent),
        cmocka_unit_test(test_fim_checker_deleted),
        cmocka_unit_test(test_fim_checker_link),
        cmocka_unit_test(test_fim_checker_deleted_enoent),

        /* fim_directory */
        cmocka_unit_test_setup_teardown(test_fim_directory, setup_struct_dirent, teardown_struct_dirent),
        cmocka_unit_test(test_fim_directory_nodir),
        cmocka_unit_test(test_fim_directory_opendir_error),

        /* fim_get_data */
        cmocka_unit_test_teardown(test_fim_get_data, teardown_local_data),
        cmocka_unit_test(test_fim_get_data_hash_error),

        /* check_deleted_files */
        cmocka_unit_test(test_check_deleted_files),
        cmocka_unit_test(test_check_deleted_files_error),

        /* fim_file */
        cmocka_unit_test(test_fim_file_add),
        cmocka_unit_test_setup(test_fim_file_modify, setup_local_data),
        cmocka_unit_test_setup(test_fim_file_no_attributes, setup_local_data),
        cmocka_unit_test_setup(test_fim_file_error_on_insert, setup_local_data),

        /* free_inode */
        cmocka_unit_test(test_free_inode_data),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
