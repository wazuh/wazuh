/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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

#include "../../headers/shared.h"
#include "../../logcollector/logcollector.h"
#include <math.h>
#include <pthread.h>
#include "../../os_crypto/sha1/sha1_op.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/os_crypto/sha1_op_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"
<<<<<<< HEAD
=======

>>>>>>> Fix logcollector UT after adding only_future_events for macOS ULS

extern OSHash *files_status;

bool w_get_hash_context(logreader *lf, SHA_CTX *context, int64_t position);
void w_initialize_file_status();
ssize_t w_set_to_pos(logreader *lf, long pos, int mode);
char * w_save_files_status_to_cJSON();
void w_save_file_status();
void w_load_files_status(cJSON *global_json);
void w_initialize_file_status();
int w_update_hash_node(char * path, int64_t pos);
int w_set_to_last_line_read(logreader *lf);

extern macos_log_vault_t macos_log_vault;


/* setup/teardown */

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}
static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

/* wraps */

/* tests */

/* w_get_hash_context */

void test_w_get_hash_context_NULL_file_exist(void ** state) {

    SHA_CTX * context;
    os_calloc(1, sizeof(SHA_CTX), context);
    int64_t position = 10;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("/test_path", lf->file);

    int mode = OS_BINARY;

    ino_t fd_check = 0;

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, lf->file);
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_string(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fname, lf->file);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, nbytes, position);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fd_check, fd_check);
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, 0);

    bool ret = w_get_hash_context (lf, context, position);

    assert_true(ret);

    os_free(context);
}

void test_w_get_hash_context_NULL_file_not_exist(void ** state) {

    SHA_CTX * context;
    os_calloc(1, sizeof(SHA_CTX), context);
    int64_t position = 10;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("/test_path", lf->file);

    int mode = OS_BINARY;

    ino_t fd_check = 0;

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, lf->file);
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_string(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fname, lf->file);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, nbytes, position);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fd_check, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, -1);

    bool ret = w_get_hash_context (lf, context, position);

    assert_false(ret);

    os_free(context);
}

void test_w_get_hash_context_done(void ** state) {

    SHA_CTX * context;
    os_calloc(1, sizeof(SHA_CTX), context);
    int64_t position = 10;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("/test_path", lf->file);

    os_file_status_t data = {0};
    data.context.num = 123;

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, lf->file);
    will_return(__wrap_OSHash_Get_ex, &data);

    bool ret = w_get_hash_context (lf, context, position);

    assert_memory_equal(&(data.context), context, sizeof(SHA_CTX));
    assert_true(ret);

    os_free(context);
}

/* w_update_file_status */

void test_w_update_file_status_fail_update_add_table_hash(void ** state) {
    test_mode = 1;

    char * path = "test/test.log";
    long pos = 0;
    SHA_CTX context = {0};

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, path);
    will_return(__wrap_OSHash_Add_ex, 0);

    int retval = w_update_file_status(path, pos, &context);

    assert_int_equal(retval,-1);

}

void test_w_update_file_status_update_fail_add_OK(void ** state) {
    test_mode = 1;

    char * path = "test/test.log";
    long pos = 0;
    SHA_CTX context = {0};

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, path);
    will_return(__wrap_OSHash_Add_ex, 2);

    int retval = w_update_file_status(path, pos, &context);

    assert_int_equal(retval,0);

}

void test_w_update_file_status_update_OK(void ** state) {
    test_mode = 1;

    char * path = "test/test.log";
    long pos = 0;
    SHA_CTX context = {0};

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 1);

    int retval = w_update_file_status(path, pos, &context);

    assert_int_equal(retval,0);

}

/* w_set_to_pos */

void test_w_set_to_pos_localfile_NULL(void ** state) {
    test_mode = 1;
    logreader *lf = NULL;
    long pos = 0;
    int mode = OS_BINARY;

    int retval = w_set_to_pos(lf, pos, mode);

    assert_int_equal(retval, -1);

}

void test_w_set_to_pos_fseek_error(void ** state) {
    test_mode = 1;
    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);
    long pos = 0;
    int mode = OS_BINARY;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, -1);

    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file 'test' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int retval = w_set_to_pos(lf, pos, mode);

    assert_int_equal(retval, -1);

    os_free(lf->file);
    os_free(lf->fp);
    os_free(lf);

}

void test_w_set_to_pos_OK(void ** state) {
    test_mode = 1;
    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);
    long pos = 0;
    int mode = OS_BINARY;

    os_calloc(1, sizeof(fpos_t), test_position);
    test_position->__pos = 1;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    expect_value(__wrap_w_ftell, x, 1);
    will_return(__wrap_w_ftell, 1);

    ssize_t retval = w_set_to_pos(lf, pos, mode);

    assert_int_equal(retval, 1);

    os_free(lf->file);
    os_free(lf);
    os_free(test_position);

}

/* w_save_files_status_to_cJSON */

void test_w_save_files_status_to_cJSON_begin_NULL(void ** state) {
    test_mode = 1;

    OSHashNode *hash_node = NULL;

    expect_function_call(__wrap_pthread_rwlock_rdlock);    
    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    char * ret = w_save_files_status_to_cJSON();
    assert_null(ret);

}

void test_w_save_files_status_to_cJSON_OK(void ** state) {
    test_mode = 1;

    os_file_status_t * data;
    os_calloc(1, sizeof(os_file_status_t), data);
    strcpy(data->hash,"test1234");
    data->offset = 5;

    OSHashNode *hash_node = NULL;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = data;

    expect_function_call(__wrap_pthread_rwlock_rdlock);    
    strcpy(macos_log_vault.timestamp,"hi 123");

    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddArrayToObject, name, "files");
    will_return(__wrap_cJSON_AddArrayToObject, (cJSON *) 1);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "path");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "hash");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test1234");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "offset");
    expect_string(__wrap_cJSON_AddStringToObject, string, "5");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    expect_value(__wrap_OSHash_Next, self, files_status);
    will_return(__wrap_OSHash_Next, NULL);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_string(__wrap_cJSON_CreateString, string, "hi 123");
    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    will_return(__wrap_cJSON_PrintUnformatted, "test_1234");

    expect_function_call(__wrap_cJSON_Delete);

    char * ret = w_save_files_status_to_cJSON();

    assert_string_equal(ret, "test_1234");

    os_free(data);
    os_free(hash_node);

}

/* w_save_files_status_to_cJSON */

void test_w_save_file_status_str_NULL(void ** state) {
    test_mode = 1;

    //test_w_save_files_status_to_cJSON_begin_NULL
    OSHashNode *hash_node = NULL;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    w_save_file_status();

}

void test_w_save_file_status_wfopen_error(void ** state) {
    test_mode = 1;

    //test_w_save_files_status_to_cJSON_OK
    os_file_status_t * data;
    os_calloc(1, sizeof(os_file_status_t), data);
    strcpy(data->hash,"test1234");
    data->offset = 5;

    OSHashNode *hash_node = NULL;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = data;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    strcpy(macos_log_vault.timestamp,"hi 123");

    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddArrayToObject, name, "files");
    will_return(__wrap_cJSON_AddArrayToObject, (cJSON *) 1);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "path");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "hash");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test1234");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "offset");
    expect_string(__wrap_cJSON_AddStringToObject, string, "5");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    expect_value(__wrap_OSHash_Next, self, files_status);
    will_return(__wrap_OSHash_Next, NULL);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_string(__wrap_cJSON_CreateString, string, "hi 123");
    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    will_return(__wrap_cJSON_PrintUnformatted, strdup("test_1234"));

    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_wfopen, __filename, "queue/logcollector/file_status.json");
    expect_string(__wrap_wfopen, __modes, "w");
    will_return(__wrap_wfopen, 0);

    expect_string(__wrap__merror_exit, formatted_msg, "(1103): Could not open file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");

    w_save_file_status();

    os_free(data);
    os_free(hash_node);

}

void test_w_save_file_status_fwrite_error(void ** state) {
    test_mode = 1;

    //test_w_save_files_status_to_cJSON_OK
    os_file_status_t * data;
    os_calloc(1, sizeof(os_file_status_t), data);
    strcpy(data->hash,"test1234");
    data->offset = 5;

    OSHashNode *hash_node = NULL;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = data;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    strcpy(macos_log_vault.timestamp,"hi 123");

    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddArrayToObject, name, "files");
    will_return(__wrap_cJSON_AddArrayToObject, (cJSON *) 1);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "path");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "hash");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test1234");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "offset");
    expect_string(__wrap_cJSON_AddStringToObject, string, "5");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    expect_value(__wrap_OSHash_Next, self, files_status);
    will_return(__wrap_OSHash_Next, NULL);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_string(__wrap_cJSON_CreateString, string, "hi 123");
    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    will_return(__wrap_cJSON_PrintUnformatted, strdup("test_1234"));

    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_wfopen, __filename, "queue/logcollector/file_status.json");
    expect_string(__wrap_wfopen, __modes, "w");
    will_return(__wrap_wfopen, "test");

    will_return(__wrap_fwrite, 0);

    expect_string(__wrap__merror, formatted_msg, "(1110): Could not write file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");

    expect_function_call(__wrap_clearerr);
    expect_string(__wrap_clearerr, __stream, "test");

    expect_value(__wrap_fclose, _File, "test");
    will_return(__wrap_fclose, 1);

    w_save_file_status();

    os_free(data);
    os_free(hash_node);

}

void test_w_save_file_status_OK(void ** state) {
    test_mode = 1;

    //test_w_save_files_status_to_cJSON_OK
    os_file_status_t * data;
    os_calloc(1, sizeof(os_file_status_t), data);
    strcpy(data->hash,"test1234");
    data->offset = 5;

    OSHashNode *hash_node = NULL;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = data;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    strcpy(macos_log_vault.timestamp,"hi 123");

    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddArrayToObject, name, "files");
    will_return(__wrap_cJSON_AddArrayToObject, (cJSON *) 1);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "path");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "hash");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test1234");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "offset");
    expect_string(__wrap_cJSON_AddStringToObject, string, "5");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    expect_value(__wrap_OSHash_Next, self, files_status);
    will_return(__wrap_OSHash_Next, NULL);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_string(__wrap_cJSON_CreateString, string, "hi 123");
    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    will_return(__wrap_cJSON_PrintUnformatted, strdup("test_1234"));

    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_wfopen, __filename, "queue/logcollector/file_status.json");
    expect_string(__wrap_wfopen, __modes, "w");
    will_return(__wrap_wfopen, "test");

    will_return(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, "test");
    will_return(__wrap_fclose, 1);

    w_save_file_status();

    os_free(data);
    os_free(hash_node);

}

/* w_load_files_status */

void test_w_load_files_status_empty_array(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_path_NULL(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_path_str_NULL(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_no_file(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, -1);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_hash_NULL(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_hash_str_NULL(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_offset_NULL(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    //Offset
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_offset_str_NULL(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    //Offset
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_invalid_offset(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    //Offset
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "-1");

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_update_add_fail(void ** state) {
    test_mode = 1;

    char * file = "test";

    cJSON *global_json = (cJSON*)1;

    int mode = OS_BINARY;
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    //Offset
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, file);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 0);

    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, file);
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "(1298): Failure to add 'test' to 'file_status' hash table");

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_update_hash_fail (void ** state) {

    test_mode = 1;

    char * file = "test";

    cJSON *global_json = (cJSON*)1;

    int mode = OS_BINARY;
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    //Offset
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, file);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "(9000): File 'test' no longer exists.");

    w_load_files_status(global_json);
}

void test_w_load_files_status_update_fail(void ** state) {
    test_mode = 1;

    char * file = "test";

    cJSON *global_json = (cJSON*)1;

    int mode = OS_BINARY;
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    //Offset
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, file);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 0);

    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, file);
    will_return(__wrap_OSHash_Add_ex, 2);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    w_load_files_status(global_json);

}

void test_w_load_files_status_OK(void ** state) {
    test_mode = 1;

    char * file = "test";

    cJSON *global_json = (cJSON*)1;

    int mode = OS_BINARY;
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    //Offset
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, file);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 1);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);
    w_load_files_status(global_json);

}

/* w_initialize_file_status */

void test_w_initialize_file_status_OSHash_Create_fail(void ** state) {
    test_mode = 1;

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(1296): Unable to create a 'file_status' hash table");

    will_return(__wrap_OSHash_setSize, 1);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap_fopen, path, LOCALFILE_STATUS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");

    w_initialize_file_status();

}

void test_w_initialize_file_status_OSHash_setSize_fail(void ** state) {
    test_mode = 1;

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(1297): Unable to set size of 'file_status' hash table");

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap_fopen, path, LOCALFILE_STATUS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");

    w_initialize_file_status();

}

void test_w_initialize_file_status_fopen_fail(void ** state) {
    test_mode = 1;

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, 1);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap_fopen, path, LOCALFILE_STATUS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");

    w_initialize_file_status();

}

void test_w_initialize_file_status_fread_fail(void ** state) {
    test_mode = 1;

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, 1);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap_fopen, path, LOCALFILE_STATUS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, "test");

    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 0);

    expect_string(__wrap__merror, formatted_msg, "(1115): Could not read from file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");

    expect_function_call(__wrap_clearerr);
    expect_string(__wrap_clearerr, __stream, "test");

    expect_value(__wrap_fclose, _File, "test");
    will_return(__wrap_fclose, 1);

    w_initialize_file_status();

}

void test_w_initialize_file_status_OK(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, 1);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap_fopen, path, LOCALFILE_STATUS);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, "test");

    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 1);

    //w_load_files_status
    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "test");

    expect_string(__wrap_stat, __file, file);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    //Hash
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    //Offset
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "1");

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, file);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 1);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    expect_function_call(__wrap_cJSON_Delete);

    expect_value(__wrap_fclose, _File, "test");
    will_return(__wrap_fclose, 1);

    w_initialize_file_status();

}

/* w_update_hash_node */

void test_w_update_hash_node_path_NULL(void ** state) {
    test_mode = 1;

    char * path = NULL;

    int ret = w_update_hash_node(path, 0);

    assert_int_equal(ret, -1);

}

void test_w_update_hash_node_update_fail(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    char * path = "test";

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, path);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 0);

    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, path);
    will_return(__wrap_OSHash_Add_ex, 2);

    int ret = w_update_hash_node(path, 0);

    assert_int_equal(ret, 0);

}

void test_w_update_hash_node_sha_fail(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    char * path = "test";

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, path);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, -1);

    expect_string(__wrap__merror, formatted_msg, "(1969): Failure to generate the SHA1 hash from file 'test'");

    int ret = w_update_hash_node(path, 0);

    assert_int_equal(ret, -1);

}

void test_w_update_hash_node_add_fail(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    char * path = "test";

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, path);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 0);

    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, path);
    will_return(__wrap_OSHash_Add_ex, 0);

    int ret = w_update_hash_node(path, 0);

    assert_int_equal(ret, -1);

}

void test_w_update_hash_node_OK(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    char * path = "test";

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, path);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 1);

    int ret = w_update_hash_node(path, 0);

    assert_int_equal(ret, 0);

}

/*  w_set_to_last_line_read */
void test_w_set_to_last_line_read_null_reader(void ** state) {

    test_mode = 1;

    logreader lf = {0};
    int ret = w_set_to_last_line_read(&lf);
    assert_int_equal(ret, 0);

}

void test_w_set_to_last_line_read_OSHash_Get_ex_fail(void ** state) {
    test_mode = 1;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, NULL);

    //w_set_pos
    long pos = 0;
    int mode = OS_BINARY;

    os_calloc(1, sizeof(fpos_t), test_position);
    test_position->__pos = 1;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    expect_value(__wrap_w_ftell, x, 1);
    will_return(__wrap_w_ftell, 1);

    expect_value(__wrap_w_ftell, x, 1);
    will_return(__wrap_w_ftell, 1);


    //w_update_hash_node
    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, lf->file);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 1);

    int ret = w_set_to_last_line_read(lf);

    assert_int_equal(ret, 0);

    os_free(lf->file);
    os_free(lf);
    os_free(test_position);

}

void test_w_set_to_last_line_read_fstat_fail(void ** state) {
    test_mode = 1;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, 1);

    expect_value(__wrap_fileno, __stream, lf->fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fstat, __fd, 1);
    will_return(__wrap_fstat, 0040000);
    will_return(__wrap_fstat, 0);
    will_return(__wrap_fstat, -1);

    expect_string(__wrap__merror, formatted_msg, "(1118): Could not retrieve information of file 'test' due to [(0)-(Success)].");


    int ret = w_set_to_last_line_read(lf);

    assert_int_equal(ret, -1);

    os_free(lf->file);
    os_free(lf);

}

void test_w_set_to_last_line_read_OS_SHA1_File_Nbytes_fail(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);

    os_file_status_t data = {0};

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, lf->fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fstat, __fd, 1);
    will_return(__wrap_fstat, 0040000);
    will_return(__wrap_fstat, 0);
    will_return(__wrap_fstat, 1);

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, "test");
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, -1);

    expect_string(__wrap__merror, formatted_msg, "(1969): Failure to generate the SHA1 hash from file 'test'");

    int ret = w_set_to_last_line_read(lf);

    assert_int_equal(ret, -1);

    os_free(lf->file);
    os_free(lf);

}

void test_w_set_to_last_line_read_diferent_file(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);

    os_file_status_t data = {0};
    strcpy(data.hash, "1234");
    data.offset = 1;

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, lf->fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fstat, __fd, 1);
    will_return(__wrap_fstat, 0040000);
    will_return(__wrap_fstat, 0);
    will_return(__wrap_fstat, 1);

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, "test");
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    //w_set_pos
    long pos = 0;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, -1);

    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file 'test' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = w_set_to_last_line_read(lf);

    assert_int_equal(ret, -1);

    os_free(lf->file);
    os_free(lf);
    os_free(test_position);

}

void test_w_set_to_last_line_read_same_file(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);
    lf->diff_max_size = 0;

    os_file_status_t data = {0};
    strcpy(data.hash, "1234");
    data.offset = 1;

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, lf->fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fstat, __fd, 1);
    will_return(__wrap_fstat, 0040000);
    will_return(__wrap_fstat, 1);
    will_return(__wrap_fstat, 1);

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, "test");
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "1234");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    //w_set_pos
    long pos = 0;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 1);
    will_return(__wrap_w_fseek, -1);

    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file 'test' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = w_set_to_last_line_read(lf);

    assert_int_equal(ret, -1);

    os_free(lf->file);
    os_free(lf);
    os_free(test_position);

}

void test_w_set_to_last_line_read_same_file_rotate(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);
    lf->diff_max_size = 0;

    os_file_status_t data = {0};
    strcpy(data.hash, "1234");
    data.offset = 1;

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, lf->fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fstat, __fd, 1);
    will_return(__wrap_fstat, 0040000);
    will_return(__wrap_fstat, 10);
    will_return(__wrap_fstat, 1);

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, "test");
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "1234");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    //w_set_pos
    long pos = 0;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, -1);

    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file 'test' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = w_set_to_last_line_read(lf);

    assert_int_equal(ret, -1);

    os_free(lf->file);
    os_free(lf);
    os_free(test_position);

}

void test_w_set_to_last_line_read_update_hash_node_error(void ** state) {
    test_mode = 1;

    int mode = OS_BINARY;

    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);
    lf->diff_max_size = 0;

    os_file_status_t data = {0};
    strcpy(data.hash, "1234");
    data.offset = 1;

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, lf->fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fstat, __fd, 1);
    will_return(__wrap_fstat, 0040000);
    will_return(__wrap_fstat, 10);
    will_return(__wrap_fstat, 1);

    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, "test");
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "1234");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    //w_set_pos
    long pos = 0;

    os_calloc(1, sizeof(fpos_t), test_position);
    test_position->__pos = 1;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    expect_value(__wrap_w_ftell, x, 1);
    will_return(__wrap_w_ftell, 1);

    //w_update_hash_node
    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, "test");
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "1234");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, lf->file);
    will_return(__wrap_OSHash_Add_ex, 0);

    will_return(__wrap_OSHash_Update_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "(1299): Failure to update 'test' to 'file_status' hash table");

    int ret = w_set_to_last_line_read(lf);

    assert_int_equal(ret, 1);

    os_free(lf->file);
    os_free(lf);
    os_free(test_position);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_get_hash_context
        cmocka_unit_test(test_w_get_hash_context_NULL_file_exist),
        cmocka_unit_test(test_w_get_hash_context_NULL_file_not_exist),
        cmocka_unit_test(test_w_get_hash_context_done),

        // Test w_update_file_status
        cmocka_unit_test(test_w_update_file_status_fail_update_add_table_hash),
        cmocka_unit_test(test_w_update_file_status_update_fail_add_OK),
        cmocka_unit_test(test_w_update_file_status_update_OK),

        // Test w_set_to_pos
        cmocka_unit_test(test_w_set_to_pos_localfile_NULL),
        cmocka_unit_test(test_w_set_to_pos_fseek_error),
        cmocka_unit_test(test_w_set_to_pos_OK),

        // Test w_save_files_status_to_cJSON
        cmocka_unit_test(test_w_save_files_status_to_cJSON_begin_NULL),
        cmocka_unit_test(test_w_save_files_status_to_cJSON_OK),

        // Test w_save_file_status
        cmocka_unit_test(test_w_save_file_status_str_NULL),
        cmocka_unit_test(test_w_save_file_status_wfopen_error),
        cmocka_unit_test(test_w_save_file_status_fwrite_error),
        cmocka_unit_test(test_w_save_file_status_OK),

        // Test w_load_files_status
        cmocka_unit_test(test_w_load_files_status_empty_array),
        cmocka_unit_test(test_w_load_files_status_path_NULL),
        cmocka_unit_test(test_w_load_files_status_path_str_NULL),
        cmocka_unit_test(test_w_load_files_status_no_file),
        cmocka_unit_test(test_w_load_files_status_hash_NULL),
        cmocka_unit_test(test_w_load_files_status_hash_str_NULL),
        cmocka_unit_test(test_w_load_files_status_offset_NULL),
        cmocka_unit_test(test_w_load_files_status_offset_str_NULL),
        cmocka_unit_test(test_w_load_files_status_invalid_offset),
        cmocka_unit_test(test_w_load_files_status_update_add_fail),
        cmocka_unit_test(test_w_load_files_status_update_hash_fail),
        cmocka_unit_test(test_w_load_files_status_update_fail),
        cmocka_unit_test(test_w_load_files_status_OK),

        // Test w_initialize_file_status
        cmocka_unit_test(test_w_initialize_file_status_OSHash_Create_fail),
        cmocka_unit_test(test_w_initialize_file_status_OSHash_setSize_fail),
        cmocka_unit_test(test_w_initialize_file_status_fopen_fail),
        cmocka_unit_test(test_w_initialize_file_status_fread_fail),
        cmocka_unit_test(test_w_initialize_file_status_OK),

        // Test w_update_hash_node
        cmocka_unit_test(test_w_update_hash_node_path_NULL),
        cmocka_unit_test(test_w_update_hash_node_sha_fail),
        cmocka_unit_test(test_w_update_hash_node_update_fail),
        cmocka_unit_test(test_w_update_hash_node_add_fail),
        cmocka_unit_test(test_w_update_hash_node_OK),

        // Test w_set_to_last_line_read
        cmocka_unit_test(test_w_set_to_last_line_read_null_reader),
        cmocka_unit_test(test_w_set_to_last_line_read_OSHash_Get_ex_fail),
        cmocka_unit_test(test_w_set_to_last_line_read_fstat_fail),
        cmocka_unit_test(test_w_set_to_last_line_read_OS_SHA1_File_Nbytes_fail),
        cmocka_unit_test(test_w_set_to_last_line_read_diferent_file),
        cmocka_unit_test(test_w_set_to_last_line_read_same_file),
        cmocka_unit_test(test_w_set_to_last_line_read_same_file_rotate),
        cmocka_unit_test(test_w_set_to_last_line_read_update_hash_node_error)
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
