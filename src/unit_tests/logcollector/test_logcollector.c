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
#include "../wrappers/posix/signal_wrappers.h"


extern OSHash *files_status;

bool w_get_hash_context(logreader *lf, EVP_MD_CTX **context, int64_t position);
ssize_t w_set_to_pos(logreader *lf, long pos, int mode);
char * w_save_files_status_to_cJSON();
void w_save_file_status();
void w_load_files_status(cJSON *global_json);
void w_initialize_file_status();
int w_update_hash_node(char * path, int64_t pos);
int w_set_to_last_line_read(logreader *lf);
void free_files_status_data(os_file_status_t *data);

// Auxiliar structs
typedef struct test_logcollector_s {
    logreader *log_reader;
    EVP_MD_CTX *context;
    os_file_status_t *status;
    OSHashNode *node;
} test_logcollector_t;

extern w_macos_log_vault_t macos_log_vault;
extern w_macos_log_procceses_t * macos_processes;
static wfd_t * stream_backup;
static wfd_t * show_backup;

// Aux functions
void set_gs_journald_ofe(bool exist, bool ofe, uint64_t timestamp);

/* setup/teardown */

static int setup_group(void **state) {
    test_mode = 1;
    macos_log_vault.is_valid_data = true;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

void free_os_file_status_t_struct(os_file_status_t *data) {
    EVP_MD_CTX_free(data->context);
    os_free(data);
}

static int setup_local_hashmap(void **state) {
    if (setup_hashmap(state) != 0) {
        return 1;
    }
    __real_OSHash_SetFreeDataPointer(mock_hashmap, (void (*)(void *))free_os_file_status_t_struct);
    files_status = mock_hashmap;
    return 0;
}

static int teardown_local_hashmap(void **state) {
    if (teardown_hashmap(state) != 0) {
        return 1;
    }
    return 0;
}

static int setup_log_context(void **state) {
    if (setup_local_hashmap(state) != 0) {
        return 1;
    }

    test_logcollector_t *test_struct = calloc(1, sizeof(test_logcollector_t));
    if (test_struct == NULL) {
        return 1;
    }

    test_struct->log_reader = calloc(1, sizeof(logreader));
    test_struct->context = EVP_MD_CTX_new();
    test_struct->status = calloc(1, sizeof(os_file_status_t));
    test_struct->node = calloc(1, sizeof(OSHashNode));

    if (test_struct->log_reader == NULL || test_struct->context == NULL || test_struct->status == NULL ||
        test_struct->node == NULL) {
        return 1;
    }

    test_struct->log_reader->fp = (FILE *) 1;
    *state = test_struct;
    return 0;
}

static int teardown_log_context(void **state) {
    if (teardown_local_hashmap(state) != 0) {
        return 1;
    }
    test_logcollector_t * test_struct = *state;

    expect_any(__wrap_fclose, _File);
    will_return_always(__wrap_fclose, 0);
    Free_Logreader(test_struct->log_reader);

    free(test_struct->log_reader);
    EVP_MD_CTX_free(test_struct->context);
    free(test_struct->status);
    free(test_struct->node);
    free(test_struct);

    return 0;
}

static int setup_process(void **state) {
    w_macos_log_procceses_t * local_macos_processes = calloc(1, sizeof(w_macos_log_procceses_t));
    os_calloc(1, sizeof(wfd_t), local_macos_processes->show.wfd);
    os_calloc(1, sizeof(wfd_t), local_macos_processes->stream.wfd);
    stream_backup = local_macos_processes->stream.wfd;
    show_backup = local_macos_processes->show.wfd;
    *state = local_macos_processes;

    return 0;
}

static int teardown_process(void **state) {
    w_macos_log_procceses_t * local_macos_processes = *state;

    os_free(stream_backup);
    os_free(show_backup);
    os_free(local_macos_processes);

    return 0;
}

static int setup_regex(void **state) {
    logreader *regex_config = calloc(1, sizeof(logreader));
    regex_config->regex_ignore = NULL;
    regex_config->regex_restrict = NULL;

    regex_config->regex_ignore = OSList_Create();
    if (regex_config->regex_ignore == NULL) {
        merror(MEM_ERROR, errno, strerror(errno));
        return -1;
    }
    OSList_SetFreeDataPointer(regex_config->regex_ignore, (void (*)(void *))w_free_expression);

    regex_config->regex_restrict = OSList_Create();
    if (regex_config->regex_restrict == NULL) {
        merror(MEM_ERROR, errno, strerror(errno));
        return -1;
    }
    OSList_SetFreeDataPointer(regex_config->regex_restrict, (void (*)(void *))w_free_expression);

    *state = regex_config;

    return 0;
}

static int teardown_regex(void **state) {
    logreader *regex_config = *state;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    if (regex_config->regex_ignore) {
        OSList_Destroy(regex_config->regex_ignore);
        regex_config->regex_ignore = NULL;
    }
    if (regex_config->regex_restrict) {
        OSList_Destroy(regex_config->regex_restrict);
        regex_config->regex_restrict = NULL;
    }

    os_free(regex_config);

    return 0;
}

/* wraps */

/* tests */

/* w_get_hash_context */

void test_w_get_hash_context_NULL_file_exist(void ** state) {
    EVP_MD_CTX *context = NULL;
    int64_t position = 10;
    test_logcollector_t *test_struct = *state;

    logreader *lf = test_struct->log_reader;

    lf->file = strdup("/test_path");

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, lf->file);
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_string(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fname, lf->file);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, mode, OS_BINARY);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, nbytes, position);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fd_check, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, 0);

    bool ret = w_get_hash_context(lf, &context, position);

    assert_true(ret);
}

void test_w_get_hash_context_NULL_file_not_exist(void ** state) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t position = 10;
    test_logcollector_t *test_struct = *state;
    logreader *lf = test_struct->log_reader;

    lf->file = strdup("/test_path");

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, lf->file);
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_string(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fname, lf->file);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, mode, OS_BINARY);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, nbytes, position);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fd_check, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, -1);

    bool ret = w_get_hash_context (lf, &context, position);
    EVP_MD_CTX_free(context);
    assert_false(ret);
}

void test_w_get_hash_context_done(void ** state) {
    int64_t position = 10;
    test_logcollector_t *test_struct = *state;

    logreader *lf = test_struct->log_reader;
    EVP_MD_CTX *context = test_struct->context;
    os_file_status_t *data = test_struct->status;

    lf->file = strdup("/test_path");

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, lf->file);
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_string(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fname, lf->file);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, mode, OS_BINARY);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, nbytes, position);
    expect_value(__wrap_OS_SHA1_File_Nbytes_with_fp_check, fd_check, 0);
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes_with_fp_check, -1);

    bool ret = w_get_hash_context (lf, &context, position);

    assert_false(ret);
}

/* w_update_file_status */
void test_w_update_file_status_fail_update_add_table_hash(void ** state) {
    char * path = "test/test.log";
    long pos = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, path);
    will_return(__wrap_OSHash_Add_ex, 0);

    int retval = w_update_file_status(path, pos, context);

    assert_int_equal(retval,-1);
}

void test_w_update_file_status_update_fail_add_OK(void ** state) {

    char * path = "test/test.log";
    long pos = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, path);
    will_return(__wrap_OSHash_Add_ex, 2);

    int retval = w_update_file_status(path, pos, context);

    assert_int_equal(retval,0);

}

void test_w_update_file_status_update_OK(void ** state) {
    char * path = "test/test.log";

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    os_file_status_t * data;
    os_malloc(sizeof(os_file_status_t), data);
    data->context = EVP_MD_CTX_new();

    __real_OSHash_Add_ex(mock_hashmap, path, data);

    long pos = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 1);

    int retval = w_update_file_status(path, pos, context);

    assert_int_equal(retval,0);;
}

/* w_set_to_pos */

void test_w_set_to_pos_localfile_NULL(void ** state) {
    logreader *lf = NULL;
    long pos = 0;
    int mode = OS_BINARY;

    int retval = w_set_to_pos(lf, pos, mode);

    assert_int_equal(retval, -1);

}

void test_w_set_to_pos_fseek_error(void ** state) {
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
    logreader *lf = NULL;
    os_calloc(1, sizeof(logreader), lf);
    lf->fp = (FILE*)1;
    os_strdup("test", lf->file);
    long pos = 0;
    int mode = OS_BINARY;
    fpos_t position_stack = {.__pos = 1};
    test_position = &position_stack;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    expect_value(__wrap_w_ftell, x, 1);
    will_return(__wrap_w_ftell, 1);

    ssize_t retval = w_set_to_pos(lf, pos, mode);

    assert_int_equal(retval, 1);

    os_free(lf->file);
    os_free(lf);
}

/* w_save_files_status_to_cJSON */

void test_w_save_files_status_to_cJSON_begin_NULL(void ** state) {
    OSHashNode *hash_node = NULL;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    char * ret = w_save_files_status_to_cJSON();
    assert_null(ret);
}

void test_w_save_files_status_to_cJSON_OK(void ** state) {
    test_logcollector_t *test_data = *state;

    os_file_status_t * data = test_data->status;
    OSHashNode *hash_node = test_data->node;

    strcpy(data->hash,"test1234");
    data->offset = 5;

    hash_node->key = "test";
    hash_node->data = data;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_PrintUnformatted, "test_1234");

    expect_function_call(__wrap_cJSON_Delete);

    char * ret = w_save_files_status_to_cJSON();

    assert_string_equal(ret, "test_1234");
}

void test_w_save_files_status_to_cJSON_macos_invalid_vault(void ** state) {
    test_mode = 1;

    OSHashNode *hash_node = NULL;

    strcpy(macos_log_vault.timestamp,"any timestamp");
    macos_log_vault.settings = "my settings";

    expect_function_call(__wrap_pthread_rwlock_rdlock);

    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);

    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    char * ret = w_save_files_status_to_cJSON();
    assert_null(ret);

}

void test_w_save_files_status_to_cJSON_macos_valid_vault(void ** state) {
    test_mode = 1;

    OSHashNode *hash_node = NULL;
    w_macos_log_procceses_t * bak_macos_processes = macos_processes;
    macos_processes = (w_macos_log_procceses_t *) 1;

    strcpy(macos_log_vault.timestamp,"2021-04-27 08:07:20-0700");
    macos_log_vault.settings = "/usr/bin/log stream --style syslog";

    expect_function_call(__wrap_pthread_rwlock_rdlock);

    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);

    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_CreateString, string, "2021-04-27 08:07:20-0700");
    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_CreateString, string, "/usr/bin/log stream --style syslog");
    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    will_return(__wrap_cJSON_PrintUnformatted, "test_1234");

    expect_function_call(__wrap_cJSON_Delete);

    char * ret = w_save_files_status_to_cJSON();

    assert_string_equal(ret, "test_1234");
    macos_processes = bak_macos_processes;

}

void test_w_save_files_status_to_cJSON_journal_valid(void ** state) {
    test_mode = 1;

    OSHashNode * hash_node = NULL;

    strcpy(macos_log_vault.timestamp, "any timestamp");
    macos_log_vault.settings = "my settings";

    expect_function_call(__wrap_pthread_rwlock_rdlock);

    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);

    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    // Set journald
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "timestamp");
    expect_string(__wrap_cJSON_AddStringToObject, string, "123456");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 2);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 3);
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    will_return(__wrap_cJSON_PrintUnformatted, "test_1234");
    expect_function_call(__wrap_cJSON_Delete);

    set_gs_journald_ofe(true, false, 123456);

    assert_non_null(w_save_files_status_to_cJSON());

    set_gs_journald_ofe(false, true, 0);
}

void test_w_save_files_status_invalid_vault(void ** state) {

    test_mode = 1;
    bool back_valid_json = macos_log_vault.is_valid_data;
    macos_log_vault.is_valid_data = false;

    OSHashNode *hash_node = NULL;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    char * ret = w_save_files_status_to_cJSON();
    assert_null(ret);
    assert_false(macos_log_vault.is_valid_data);
    macos_log_vault.is_valid_data = back_valid_json;

}

void test_w_save_files_status_to_cJSON_data(void ** state) {
    test_mode = 1;

    w_macos_log_procceses_t * bak_macos_processes = macos_processes;
    macos_processes = (w_macos_log_procceses_t *) 1;
    os_file_status_t * data;
    os_calloc(1, sizeof(os_file_status_t), data);
    strcpy(data->hash,"test1234");
    data->offset = 5;

    OSHashNode *hash_node = NULL;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = data;

    strcpy(macos_log_vault.timestamp,"2021-04-27 08:07:20-0700");
    macos_log_vault.settings = "/usr/bin/log stream --style syslog";

    expect_function_call(__wrap_pthread_rwlock_rdlock);

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

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_CreateString, string, "2021-04-27 08:07:20-0700");
    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_CreateString, string, "/usr/bin/log stream --style syslog");
    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    will_return(__wrap_cJSON_PrintUnformatted, "test_1234");

    expect_function_call(__wrap_cJSON_Delete);

    char * ret = w_save_files_status_to_cJSON();

    assert_string_equal(ret, "test_1234");
    macos_processes = bak_macos_processes;
    os_free(data);
    os_free(hash_node);

}

/* w_save_file_status */

void test_w_save_file_status_str_NULL(void ** state) {
    OSHashNode *hash_node = NULL;
    strcpy(macos_log_vault.timestamp,"any timestamp");
    macos_log_vault.settings = "my settings";

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_value(__wrap_OSHash_Begin, self, files_status);
    will_return(__wrap_OSHash_Begin, hash_node);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    w_save_file_status();

}


void test_w_save_file_status_wfopen_error(void ** state) {
    test_logcollector_t *test_data = *state;

    os_file_status_t * data = test_data->status;
    OSHashNode *hash_node = test_data->node;

    strcpy(data->hash,"test1234");
    data->offset = 5;

    hash_node->key = "test";
    hash_node->data = data;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_PrintUnformatted, "test_1234");

    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_wfopen, path, "queue/logcollector/file_status.json");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, 0);

    expect_string(__wrap__merror_exit, formatted_msg, "(1103): Could not open file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");
    expect_assert_failure(w_save_file_status());
}

void test_w_save_file_status_fwrite_error(void ** state) {
    test_logcollector_t *test_data = *state;

    os_file_status_t * data = test_data->status;
    OSHashNode *hash_node = test_data->node;

    strcpy(data->hash,"test1234");
    data->offset = 5;

    hash_node->key = "test";
    hash_node->data = data;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_PrintUnformatted, strdup("test_1234"));

    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_wfopen, path, "queue/logcollector/file_status.json");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, "test");

    will_return(__wrap_fwrite, 0);

    expect_string(__wrap__merror, formatted_msg, "(1110): Could not write file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");

    expect_function_call(__wrap_clearerr);
    expect_string(__wrap_clearerr, __stream, "test");

    expect_value(__wrap_fclose, _File, "test");
    will_return(__wrap_fclose, 1);

    w_save_file_status();
}

void test_w_save_file_status_OK(void ** state) {
    test_logcollector_t *test_data = *state;

    os_file_status_t * data = test_data->status;
    OSHashNode *hash_node = test_data->node;

    strcpy(data->hash,"test1234");
    data->offset = 5;

    hash_node->key = "test";
    hash_node->data = data;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    will_return(__wrap_cJSON_PrintUnformatted, strdup("test_1234"));

    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_wfopen, path, "queue/logcollector/file_status.json");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, "test");

    will_return(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, "test");
    will_return(__wrap_fclose, 1);

    w_save_file_status();
}

/* w_load_files_status */

void test_w_load_files_status_empty_array(void ** state) {
    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";


    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);
    // >> w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    
        // >> w_journald_set_status_from_JSON// << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // << w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_path_NULL(void ** state) {
    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_path_str_NULL(void ** state) {
    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 1);

    will_return(__wrap_cJSON_GetArrayItem, NULL);

    //Path
    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_no_file(void ** state) {
    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_hash_NULL(void ** state) {
    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_hash_str_NULL(void ** state) {
    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_offset_NULL(void ** state) {
    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_offset_str_NULL(void ** state) {
    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);
}

void test_w_load_files_status_invalid_offset(void ** state) {
    cJSON *global_json = (cJSON*)1;

    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_update_add_fail(void ** state) {
    char * file = "test";

    cJSON *global_json = (cJSON*)1;

    int mode = OS_BINARY;
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetStringValue, "32bb98743e298dee0a654a654765c765d765ae80");

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);
}

void test_w_load_files_status_update_hash_fail (void ** state) {
    char * file = "test";

    cJSON *global_json = (cJSON*)1;

    int mode = OS_BINARY;
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetStringValue, "32bb98743e298dee0a654a654765c765d765ae80");

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
    char * file = "test";

    cJSON *global_json = (cJSON*)1;

    int mode = OS_BINARY;
    struct stat stat_buf = { .st_mode = 0040000 };
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

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

    will_return(__wrap_cJSON_GetStringValue, "32bb98743e298dee0a654a654765c765d765ae80");

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON
    w_load_files_status(global_json);

}

void test_w_load_files_status_OK(void ** state) {
    char * file = "test";
    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    os_file_status_t * data;
    os_malloc(sizeof(os_file_status_t), data);
    data->context = EVP_MD_CTX_new();

    __real_OSHash_Add_ex(mock_hashmap, file, data);
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

    will_return(__wrap_cJSON_GetStringValue, "32bb98743e298dee0a654a654765c765d765ae80");

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

}

void test_w_load_files_status_valid_timestamp_only(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);

    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "2021-04-27 08:07:20-0700");

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

    assert_string_equal(macos_log_vault.settings, "my settings");
    assert_string_equal(macos_log_vault.timestamp, "hi 123");
}

void test_w_load_files_status_valid_settings_only(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);

    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "/usr/bin/log stream --style syslog");

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON

    w_load_files_status(global_json);

    assert_string_equal(macos_log_vault.settings, "my settings");
    assert_string_equal(macos_log_vault.timestamp, "hi 123");

}

void test_w_load_files_status_valid_vault(void ** state) {
    test_mode = 1;

    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    os_strdup("my settings", macos_log_vault.settings);
    macos_log_vault.is_valid_data = false;

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);

    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "2021-04-27 08:07:20-0700");

    will_return(__wrap_cJSON_GetObjectItem, 1);

    will_return(__wrap_cJSON_GetStringValue, "/usr/bin/log stream --style syslog");

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    // << w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // >> w_journald_set_status_from_JSON
    
    w_load_files_status(global_json);

    assert_string_equal(macos_log_vault.timestamp, "2021-04-27 08:07:20-0700");
    assert_string_equal(macos_log_vault.settings, "/usr/bin/log stream --style syslog");
    assert_true(macos_log_vault.is_valid_data);

    os_free(macos_log_vault.settings);
}

// Related only to journal
void test_w_load_files_status_jorunal_no_journal_obj(void ** state) {
    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";


    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);
    // >> w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // << w_macos_set_status_from_JSON

    // >> w_journald_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // << w_journald_set_status_from_JSON

    w_load_files_status(global_json);
}
void test_w_load_files_status_jorunal_no_journal_timestmap(void ** state) {
    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";


    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);
    // >> w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // << w_macos_set_status_from_JSON

    // >> w_journald_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, 0x1);
    will_return(__wrap_cJSON_GetObjectItem, 0x0);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // << w_journald_set_status_from_JSON

    w_load_files_status(global_json);
}
void test_w_load_files_status_jorunal_invalid_timestamp(void ** state) {
    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";


    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);
    // >> w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // << w_macos_set_status_from_JSON

    // >> w_journald_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "invalid timestamp");
    // << w_journald_set_status_from_JSON

    w_load_files_status(global_json);
}
void test_w_load_files_status_jorunal_success(void ** state) {
    cJSON *global_json = (cJSON*)1;
    strcpy(macos_log_vault.timestamp,"hi 123");
    macos_log_vault.settings = "my settings";


    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetArraySize, 0);
    // >> w_macos_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    // << w_macos_set_status_from_JSON

    // >> w_journald_set_status_from_JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "123456");
    expect_string(__wrap__mdebug2, formatted_msg, "(9009): Setting last read timestamp to '123456'");
    // << w_journald_set_status_from_JSON

    w_load_files_status(global_json);
}

/* w_initialize_file_status */

void test_w_initialize_file_status_OSHash_Create_fail(void ** state) {
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(1296): Unable to create a 'file_status' hash table");

    expect_assert_failure(w_initialize_file_status());
}

void test_w_initialize_file_status_OSHash_setSize_fail(void ** state) {
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(1297): Unable to set size of 'file_status' hash table");

    expect_assert_failure(w_initialize_file_status());

}

void test_w_initialize_file_status_fopen_fail(void ** state) {
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, 1);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap_wfopen, path, LOCALFILE_STATUS);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file 'queue/logcollector/file_status.json' due to [(0)-(Success)].");

    w_initialize_file_status();
}

void test_w_initialize_file_status_fread_fail(void ** state) {
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, 1);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap_wfopen, path, LOCALFILE_STATUS);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, "test");

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
    int mode = OS_BINARY;
    char * file = "test";
    struct stat stat_buf = { .st_mode = 0040000 };

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);
    os_file_status_t * data;
    os_malloc(sizeof(os_file_status_t), data);
    data->context = EVP_MD_CTX_new();

    __real_OSHash_Add_ex(mock_hashmap, file, data);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, 1);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap_wfopen, path, LOCALFILE_STATUS);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, "test");

    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 1);

    //w_load_files_status

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

    will_return(__wrap_cJSON_GetStringValue, "32bb98743e298dee0a654a654765c765d765ae80");

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

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, NULL);

    expect_function_call(__wrap_cJSON_Delete);

    expect_value(__wrap_fclose, _File, "test");
    will_return(__wrap_fclose, 1);

    w_initialize_file_status();
}

/* w_update_hash_node */

void test_w_update_hash_node_path_NULL(void ** state) {
    char * path = NULL;

    int ret = w_update_hash_node(path, 0);

    assert_int_equal(ret, -1);

}

void test_w_update_hash_node_update_fail(void ** state) {
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
    int mode = OS_BINARY;
    char * path = "test";

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);
    os_file_status_t * data;
    os_malloc(sizeof(os_file_status_t), data);
    data->context = EVP_MD_CTX_new();

    __real_OSHash_Add_ex(mock_hashmap, path, data);

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
    logreader lf = {0};
    int ret = w_set_to_last_line_read(&lf);
    assert_int_equal(ret, 0);

}

void test_w_set_to_last_line_read_OSHash_Get_ex_fail(void ** state) {
    fpos_t position_stack = {.__pos = 1};
    logreader log_reader = {.fp = (FILE *)1, .file = "test"};

    test_position = &position_stack;

    expect_function_call(__wrap_pthread_rwlock_wrlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);
    os_file_status_t * data;
    os_malloc(sizeof(os_file_status_t), data);
    data->context = EVP_MD_CTX_new();

    __real_OSHash_Add_ex(mock_hashmap, log_reader.file, data);

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, NULL);

    //w_set_pos
    long pos = 0;
    int mode = OS_BINARY;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    expect_value(__wrap_w_ftell, x, 1);
    will_return(__wrap_w_ftell, 1);

    expect_value(__wrap_w_ftell, x, 1);
    will_return(__wrap_w_ftell, 1);


    //w_update_hash_node
    expect_string(__wrap_OS_SHA1_File_Nbytes, fname, log_reader.file);
    expect_value(__wrap_OS_SHA1_File_Nbytes, mode, mode);
    expect_value(__wrap_OS_SHA1_File_Nbytes, nbytes, 1);
    will_return(__wrap_OS_SHA1_File_Nbytes, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File_Nbytes, 1);

    will_return(__wrap_OSHash_Update_ex, 1);

    int ret = w_set_to_last_line_read(&log_reader);

    assert_int_equal(ret, 0);
}

void test_w_set_to_last_line_read_fstat_fail(void ** state) {
    os_file_status_t *data = *state;

    logreader log_reader = {.fp = (FILE *)1, .file = "test"};

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, 1);

    expect_value(__wrap_fileno, __stream, log_reader.fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fstat, __fd, 1);
    will_return(__wrap_fstat, 0040000);
    will_return(__wrap_fstat, 0);
    will_return(__wrap_fstat, -1);

    expect_string(__wrap__merror, formatted_msg, "(1118): Could not retrieve information of file 'test' due to [(0)-(Success)].");


    int ret = w_set_to_last_line_read(&log_reader);

    assert_int_equal(ret, -1);
}

void test_w_set_to_last_line_read_OS_SHA1_File_Nbytes_fail(void ** state) {
    int mode = OS_BINARY;

    os_file_status_t data = {0};
    fpos_t position_stack = {.__pos = 1};
    logreader log_reader = {.fp = (FILE *)1, .file= "test"};
    test_position = &position_stack;

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, log_reader.fp);
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
    int ret = w_set_to_last_line_read(&log_reader);

    assert_int_equal(ret, -1);
}

void test_w_set_to_last_line_read_diferent_file(void ** state) {
    int mode = OS_BINARY;
    os_file_status_t data = {.hash = "1234", .offset = 1};
    logreader log_reader = {.fp = (FILE *)1, .file= "test"};

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, log_reader.fp);
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
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, -1);

    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file 'test' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = w_set_to_last_line_read(&log_reader);

    assert_int_equal(ret, -1);
}

void test_w_set_to_last_line_read_same_file(void ** state) {
    int mode = OS_BINARY;

    os_file_status_t data = {.hash = "1234", .offset = 1};
    logreader log_reader = {.fp = (FILE *)1, .file= "test", .diff_max_size = 0};

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, log_reader.fp);
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
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 1);
    will_return(__wrap_w_fseek, -1);

    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file 'test' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = w_set_to_last_line_read(&log_reader);

    assert_int_equal(ret, -1);
}

void test_w_set_to_last_line_read_same_file_rotate(void ** state) {
    int mode = OS_BINARY;
    logreader log_reader = {.fp = (FILE *)1, .file= "test", .diff_max_size = 0};
    os_file_status_t data = {.hash = "1234", .offset = 1};

    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, log_reader.fp);
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

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, -1);

    expect_string(__wrap__merror, formatted_msg, "(1116): Could not set position in file 'test' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = w_set_to_last_line_read(&log_reader);

    assert_int_equal(ret, -1);
}

void test_w_set_to_last_line_read_update_hash_node_error(void ** state) {
    int mode = OS_BINARY;
    logreader log_reader = {.fp = (FILE *)1, .file= "test", .diff_max_size = 0};
    os_file_status_t data = {.hash = "1234", .offset = 1};


    expect_any(__wrap_OSHash_Get_ex, self);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, &data);

    expect_value(__wrap_fileno, __stream, log_reader.fp);
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

    will_return(__wrap_OSHash_Update_ex, 0);

    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, log_reader.file);
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "(1299): Failure to update 'test' to 'file_status' hash table");

    int ret = w_set_to_last_line_read(&log_reader);

    assert_int_equal(ret, 1);
}

/* _macos_release_log_show */

void test_w_macos_release_log_show_not_launched(void ** state) {
    macos_processes = *state;
    macos_processes->show.wfd = NULL;

    w_macos_release_log_show();

}

void test_w_macos_release_log_show_launched_and_running(void ** state) {

    macos_processes = *state;
    macos_processes->show.wfd->pid = 10;

    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log show` resources.");
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_show();

    assert_null(macos_processes->show.wfd);

}

void test_w_macos_release_log_show_launched_and_running_with_child(void ** state) {

    macos_processes = *state;
    macos_processes->show.wfd->pid = 10;
    macos_processes->show.child = 11;

    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log show` resources.");
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 11);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_show();

    assert_null(macos_processes->show.wfd);

}

void test_w_macos_release_log_show_launched_and_not_running(void ** state) {

    macos_processes = *state;
    macos_processes->show.wfd->pid = 0;
    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log show` resources.");
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_show();

    assert_null(macos_processes->show.wfd);

}

/* w_macos_release_log_stream */

void test_w_macos_release_log_stream_not_launched(void ** state) {

    macos_processes = *state;
    macos_processes->stream.wfd = NULL;

    w_macos_release_log_stream();

}

void test_w_macos_release_log_stream_launched_and_running(void ** state) {

    macos_processes = *state;
    macos_processes->stream.wfd->pid = 10;
    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log stream` resources.");
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_stream();

    assert_null(macos_processes->stream.wfd);

}

void test_w_macos_release_log_stream_launched_and_running_with_child(void ** state) {

    macos_processes = *state;
    macos_processes->stream.wfd->pid = 10;
    macos_processes->stream.child = 11;
    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log stream` resources.");
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 11);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_stream();

    assert_null(macos_processes->stream.wfd);

}

void test_w_macos_release_log_stream_launched_and_not_running(void ** state) {

    macos_processes = *state;
    macos_processes->stream.wfd->pid = 0;
    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log stream` resources.");
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_stream();

    assert_null(macos_processes->stream.wfd);

}

/* w_macos_release_log_execution */

void test_w_macos_release_log_execution_log_stream_and_show_not_launched(void ** state) {

    macos_processes = *state;
    macos_processes->show.wfd = NULL;
    macos_processes->stream.wfd = NULL;

    w_macos_release_log_execution();

}

void test_w_macos_release_log_execution_log_stream_and_show_launched_and_running(void ** state) {

    macos_processes = *state;
    macos_processes->show.wfd->pid =10;
    macos_processes->stream.wfd->pid = 11;

    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log show` resources.");
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log stream` resources.");
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 11);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_execution();

    assert_null(macos_processes->stream.wfd);
    assert_null(macos_processes->show.wfd);

}

void test_w_macos_release_log_execution_log_stream_launched_and_show_not_launched(void ** state) {

    macos_processes = *state;
    macos_processes->show.wfd = NULL;
    macos_processes->stream.wfd->pid = 10;

    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log stream` resources.");
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_execution();

    assert_null(macos_processes->stream.wfd);

}

void test_w_macos_release_log_execution_log_stream_not_launched_and_show_launched(void ** state) {

    macos_processes = *state;
    macos_processes->show.wfd->pid = 10;
    macos_processes->stream.wfd = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log show` resources.");
    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_release_log_execution();

    assert_null(macos_processes->show.wfd);

}

void check_ignore_and_restrict_null_config(void ** state) {
    logreader *regex_config = *state;

    int ret = check_ignore_and_restrict(NULL, NULL, "testing log line");
    assert_false(ret);
}

void check_ignore_and_restrict_not_ignored(void ** state) {
    logreader *regex_config = *state;
    w_expression_t * expression_ignore;
    char *str_test = "testing log not match";

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    w_calloc_expression_t(&expression_ignore, EXP_TYPE_PCRE2);
    w_expression_compile(expression_ignore, "ignore.*", 0);
    OSList_InsertData(regex_config->regex_ignore, NULL, expression_ignore);

    will_return(wrap_pcre2_match_data_create_from_pattern, 1);
    will_return(wrap_pcre2_match, 0);

    int ret = check_ignore_and_restrict(regex_config->regex_ignore, NULL, str_test);

    assert_false(ret);
}

void check_ignore_and_restrict_ignored(void ** state) {
    logreader *regex_config = *state;
    w_expression_t * expression_ignore;
    char *str_test = "testing log with ignore word";
    char *aux[2];
    aux[0] = str_test;
    aux[1] = str_test+1;
    char log_str[PATH_MAX + 1] = {0};

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    w_calloc_expression_t(&expression_ignore, EXP_TYPE_PCRE2);
    w_expression_compile(expression_ignore, "ignore.*", 0);
    OSList_InsertData(regex_config->regex_ignore, NULL, expression_ignore);

    will_return(wrap_pcre2_match_data_create_from_pattern, 1);
    will_return(wrap_pcre2_match, 1);
    will_return(wrap_pcre2_get_ovector_pointer, aux);

    snprintf(log_str, PATH_MAX, LF_MATCH_REGEX, "testing log with ignore word", "ignore", "ignore.*");
    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    int ret = check_ignore_and_restrict(regex_config->regex_ignore, NULL, str_test);

    assert_true(ret);
}

void check_ignore_and_restrict_not_restricted(void ** state) {
    logreader *regex_config = *state;
    w_expression_t * expression_restrict;
    char *str_test = "testing log with restrict word";
    char *aux[2];
    aux[0] = str_test;
    aux[1] = str_test+1;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    w_calloc_expression_t(&expression_restrict, EXP_TYPE_PCRE2);
    w_expression_compile(expression_restrict, "restrict.*", 0);
    OSList_InsertData(regex_config->regex_restrict, NULL, expression_restrict);

    will_return(wrap_pcre2_match_data_create_from_pattern, 1);
    will_return(wrap_pcre2_match, 1);
    will_return(wrap_pcre2_get_ovector_pointer, aux);

    int ret = check_ignore_and_restrict(NULL, regex_config->regex_restrict, str_test);

    assert_false(ret);
}

void check_ignore_and_restrict_restricted(void ** state) {
    logreader *regex_config = *state;
    w_expression_t * expression_restrict;
    char *str_test = "testing log not match";
    char log_str[PATH_MAX + 1] = {0};

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    w_calloc_expression_t(&expression_restrict, EXP_TYPE_PCRE2);
    w_expression_compile(expression_restrict, "restrict.*", 0);
    OSList_InsertData(regex_config->regex_restrict, NULL, expression_restrict);

    will_return(wrap_pcre2_match_data_create_from_pattern, 1);
    will_return(wrap_pcre2_match, 0);

    snprintf(log_str, PATH_MAX, LF_MATCH_REGEX, "testing log not match", "restrict", "restrict.*");
    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    int ret = check_ignore_and_restrict(NULL, regex_config->regex_restrict, str_test);

    assert_true(ret);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_get_hash_context
        cmocka_unit_test_setup_teardown(test_w_get_hash_context_NULL_file_exist, setup_log_context, teardown_log_context),
        cmocka_unit_test_setup_teardown(test_w_get_hash_context_NULL_file_not_exist, setup_log_context, teardown_log_context),
        cmocka_unit_test_setup_teardown(test_w_get_hash_context_done, setup_log_context, teardown_log_context),

        // Test w_update_file_status
        cmocka_unit_test_setup_teardown(test_w_update_file_status_fail_update_add_table_hash, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_update_file_status_update_fail_add_OK, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_update_file_status_update_OK, setup_local_hashmap, teardown_local_hashmap),

        // Test w_set_to_pos
        cmocka_unit_test_setup_teardown(test_w_set_to_pos_localfile_NULL, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_set_to_pos_fseek_error, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_set_to_pos_OK, setup_local_hashmap, teardown_local_hashmap),

        // Test w_save_files_status_to_cJSON
        // Related only to files
        cmocka_unit_test_setup_teardown(test_w_save_files_status_to_cJSON_begin_NULL, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_save_files_status_to_cJSON_OK, setup_log_context, teardown_log_context),
        // Related only to macos
        cmocka_unit_test(test_w_save_files_status_to_cJSON_macos_invalid_vault),
        cmocka_unit_test(test_w_save_files_status_to_cJSON_macos_valid_vault),
        // Related only to journal
        cmocka_unit_test(test_w_save_files_status_to_cJSON_journal_valid),
        // Related to files and macos
        cmocka_unit_test(test_w_save_files_status_to_cJSON_data),

        // Test w_save_file_status
        cmocka_unit_test_setup_teardown(test_w_save_file_status_str_NULL, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_save_file_status_wfopen_error, setup_log_context, teardown_log_context),
        cmocka_unit_test_setup_teardown(test_w_save_file_status_fwrite_error, setup_log_context, teardown_log_context),
        cmocka_unit_test_setup_teardown(test_w_save_file_status_OK, setup_log_context, teardown_log_context),

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
        cmocka_unit_test_setup_teardown(test_w_load_files_status_update_add_fail, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_load_files_status_update_hash_fail, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_load_files_status_update_fail, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_load_files_status_OK, setup_local_hashmap, teardown_local_hashmap),
        // Related only to macos
        cmocka_unit_test(test_w_load_files_status_valid_timestamp_only),
        cmocka_unit_test(test_w_load_files_status_valid_settings_only),
        cmocka_unit_test(test_w_load_files_status_valid_vault),
        cmocka_unit_test(test_w_save_files_status_invalid_vault),
        // Related only to journal
        cmocka_unit_test(test_w_load_files_status_jorunal_no_journal_obj),
        cmocka_unit_test(test_w_load_files_status_jorunal_no_journal_timestmap),
        cmocka_unit_test(test_w_load_files_status_jorunal_invalid_timestamp),
        cmocka_unit_test(test_w_load_files_status_jorunal_success),
        

        // Test w_initialize_file_status
        cmocka_unit_test(test_w_initialize_file_status_OSHash_Create_fail),
        cmocka_unit_test(test_w_initialize_file_status_OSHash_setSize_fail),
        cmocka_unit_test(test_w_initialize_file_status_fopen_fail),
        cmocka_unit_test(test_w_initialize_file_status_fread_fail),
        cmocka_unit_test_setup_teardown(test_w_initialize_file_status_OK, setup_local_hashmap, teardown_local_hashmap),

        // Test w_update_hash_node
        cmocka_unit_test(test_w_update_hash_node_path_NULL),
        cmocka_unit_test(test_w_update_hash_node_sha_fail),
        cmocka_unit_test_setup_teardown(test_w_update_hash_node_update_fail, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_update_hash_node_add_fail, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_update_hash_node_OK, setup_local_hashmap, teardown_local_hashmap),

        // Test w_set_to_last_line_read
        cmocka_unit_test(test_w_set_to_last_line_read_null_reader),
        cmocka_unit_test_setup_teardown(test_w_set_to_last_line_read_OSHash_Get_ex_fail, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test(test_w_set_to_last_line_read_fstat_fail),
        cmocka_unit_test_setup_teardown(test_w_set_to_last_line_read_OS_SHA1_File_Nbytes_fail, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_set_to_last_line_read_diferent_file, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_set_to_last_line_read_same_file, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_set_to_last_line_read_same_file_rotate, setup_local_hashmap, teardown_local_hashmap),
        cmocka_unit_test_setup_teardown(test_w_set_to_last_line_read_update_hash_node_error, setup_local_hashmap, teardown_local_hashmap),

        // Test w_macos_release_log_show
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_show_not_launched, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_show_launched_and_running, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_show_launched_and_running_with_child, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_show_launched_and_not_running, setup_process, teardown_process),


        // Test w_macos_release_log_stream
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_stream_not_launched, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_stream_launched_and_running, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_stream_launched_and_running_with_child, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_stream_launched_and_not_running, setup_process, teardown_process),

        // Test w_macos_release_log_execution
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_execution_log_stream_and_show_not_launched, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_execution_log_stream_and_show_launched_and_running, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_execution_log_stream_launched_and_show_not_launched, setup_process, teardown_process),
        cmocka_unit_test_setup_teardown(test_w_macos_release_log_execution_log_stream_not_launched_and_show_launched, setup_process, teardown_process),

        // Test w_macos_release_log_execution
        cmocka_unit_test_setup_teardown(check_ignore_and_restrict_null_config, setup_regex, teardown_regex),
        cmocka_unit_test_setup_teardown(check_ignore_and_restrict_not_ignored, setup_regex, teardown_regex),
        cmocka_unit_test_setup_teardown(check_ignore_and_restrict_ignored, setup_regex, teardown_regex),
        cmocka_unit_test_setup_teardown(check_ignore_and_restrict_not_restricted, setup_regex, teardown_regex),
        cmocka_unit_test_setup_teardown(check_ignore_and_restrict_restricted, setup_regex, teardown_regex)

    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
