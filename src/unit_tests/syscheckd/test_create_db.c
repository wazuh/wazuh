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
#include <string.h>

#include "../wrappers/common.h"
#include "../wrappers/posix/dirent_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/wazuh/config/syscheck_config_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/fs_op_wrappers.h"
#include "../wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "../wrappers/wazuh/syscheckd/fim_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_check_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_realtime_wrappers.h"
#include "../wrappers/wazuh/syscheckd/fim_diff_changes_wrappers.h"
#include "../wrappers/wazuh/syscheckd/registry.h"
#include "../wrappers/wazuh/os_crypto/md5_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

#include "syscheck.h"
#include "../../config/syscheck-config.h"
#include "db/include/db.h"

#include "test_fim.h"

fim_state_db _files_db_state = FIM_STATE_DB_NORMAL;

void update_wildcards_config();
void fim_process_wildcard_removed(directory_t *configuration);
void transaction_callback(ReturnTypeCallback resultType, const cJSON* result_json, void* user_data);
void fim_event_callback(void* data, void * ctx);
cJSON * fim_calculate_dbsync_difference(const fim_file_data *data, const cJSON* changed_data, cJSON* old_attributes,
                                        cJSON* changed_attributes);
void create_windows_who_data_events(void * data, void * ctx);
void fim_db_remove_entry(void * data, void * ctx);
void process_delete_event(void * data, void * ctx);
void fim_db_process_missing_entry(void * data, void * ctx);
void dbsync_attributes_json(const cJSON *dbsync_event, const directory_t *configuration, cJSON *attributes);

/* auxiliary structs */
typedef struct __fim_data_s {
    event_data_t *evt_data;
    whodata_evt *w_evt;
    fim_entry *fentry;
    fim_file_data *new_data;
    fim_file_data *old_data;
    fim_file_data *local_data; // Used on certain tests, not affected by group setup/teardown
    struct dirent *entry;       // Used on fim_directory tests, not affected by group setup/teardown
    cJSON *json;
    OSList *list;
    rb_tree *tree;
} fim_data_t;

typedef struct _txn_data_s {
    fim_txn_context_t *txn_context;
    char *diff;
    cJSON *dbsync_event;
} txn_data_t;

typedef struct _json_struct_s {
    cJSON *json1;
    cJSON *json2;
} json_struct_t;

const struct stat DEFAULT_STATBUF = { .st_mode = S_IFREG | 00444,
                                      .st_size = 1000,
                                      .st_uid = 0,
                                      .st_gid = 0,
                                      .st_ino = 1234,
                                      .st_dev = 2345,
                                      .st_mtime = 3456 };

static OSList *removed_entries;

fim_file_data DEFAULT_FILE_DATA = {
    // Checksum attributes
    .size = 0,
    .attributes = NULL,
    .uid = "1000",
    .gid = "1000",
    .user_name = "root",
    .group_name = "root",
    .mtime = 123456789,
    .inode = 1,
    .hash_md5 = "0123456789abcdef0123456789abcdef",
    .hash_sha1 = "0123456789abcdef0123456789abcdef01234567",
    .hash_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    #ifdef TEST_WINAGENT
    .perm = "{\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]},\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"synchronize\",\"read_data\",\"read_ea\",\"execute\",\"read_attributes\"]},\"S-1-5-11\":{\"name\":\"Authenticated Users\",\"allowed\":[\"delete\",\"read_control\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]}}",
    #else
    .perm = "rw-rw-r--",
    #endif
    // Options
    .mode = FIM_REALTIME,
    .last_event = 0,
    .dev = 100,
    .scanned = 0,
    .options = (CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_INODE | CHECK_MD5SUM |
                CHECK_SHA1SUM | CHECK_SHA256SUM),
    .checksum = "0123456789abcdef0123456789abcdef01234567",
};

/* redefinitons/wrapping */

#ifdef TEST_WINAGENT
void __wrap_decode_win_attributes(char *str, unsigned int attrs) {
    check_expected(str);
    check_expected(attrs);
}
#endif

static int setup_fim_data(void **state) {
    fim_data_t *fim_data = calloc(1, sizeof(fim_data_t));

    test_mode = 0;

    if(fim_data == NULL)
        return -1;

    if (fim_data->evt_data = calloc(1, sizeof(event_data_t)), fim_data->evt_data == NULL)
        return -1;

    if(fim_data->w_evt = calloc(1, sizeof(whodata_evt)), fim_data->w_evt == NULL)
        return -1;

    if(fim_data->new_data = calloc(1, sizeof(fim_file_data)), fim_data->new_data == NULL)
        return -1;

    if(fim_data->old_data = calloc(1, sizeof(fim_file_data)), fim_data->old_data == NULL)
        return -1;

    // Setup mock whodata event
    fim_data->w_evt->user_id = strdup("100");
    fim_data->w_evt->user_name = strdup("test");
    fim_data->w_evt->process_name = strdup("test_proc");
    fim_data->w_evt->path = strdup("./test/test.file");
#ifndef TEST_WINAGENT
    fim_data->w_evt->group_id = strdup("1000");
    fim_data->w_evt->group_name = strdup("testing");
    fim_data->w_evt->audit_uid = strdup("99");
    fim_data->w_evt->audit_name = strdup("audit_user");
    fim_data->w_evt->effective_uid = strdup("999");
    fim_data->w_evt->effective_name = strdup("effective_user");
    fim_data->w_evt->inode = strdup("606060");
    fim_data->w_evt->dev = strdup("12345678");
    fim_data->w_evt->parent_name = strdup("parent_name");
    fim_data->w_evt->parent_cwd = strdup("parent_cwd");
    fim_data->w_evt->ppid = 1000;
    fim_data->w_evt->cwd = strdup("process_cwd");
#endif
    fim_data->w_evt->process_id = 1001;

    // Setup mock old fim_entry
    fim_data->old_data->size = 1500;
    fim_data->old_data->perm = strdup("0664");
#ifdef TEST_WINAGENT
    fim_data->old_data->perm_json = cJSON_CreateObject();
#endif
    fim_data->old_data->attributes = strdup("r--r--r--");
    fim_data->old_data->uid = strdup("100");
    fim_data->old_data->gid = strdup("1000");
    fim_data->old_data->user_name = strdup("test");
    fim_data->old_data->group_name = strdup("testing");
    fim_data->old_data->mtime = 1570184223;
    fim_data->old_data->inode = 606060;
    strcpy(fim_data->old_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->old_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->old_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->old_data->mode = FIM_REALTIME;
    fim_data->old_data->last_event = 1570184220;
    fim_data->old_data->dev = 12345678;
    fim_data->old_data->scanned = 123456;
    fim_data->old_data->options = 511;
    strcpy(fim_data->old_data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    // Setup mock new fim_entry
    fim_data->new_data->size = 1501;
    fim_data->new_data->perm = strdup("0666");
#ifdef TEST_WINAGENT
    fim_data->new_data->perm_json = create_win_permissions_object();
#endif
    fim_data->new_data->attributes = strdup("rw-rw-rw-");
    fim_data->new_data->uid = strdup("101");
    fim_data->new_data->gid = strdup("1001");
    fim_data->new_data->user_name = strdup("test1");
    fim_data->new_data->group_name = strdup("testing1");
    fim_data->new_data->mtime = 1570184224;
    fim_data->new_data->inode = 1152921500312810880;
    strcpy(fim_data->new_data->hash_md5, "3691689a513ace7e508297b583d7550d");
    strcpy(fim_data->new_data->hash_sha1, "07f05add1049244e7e75ad0f54f24d8094cd8f8b");
    strcpy(fim_data->new_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e9959643c6262667b61fbe57694df224d40");
    fim_data->new_data->mode = FIM_REALTIME;
    fim_data->new_data->last_event = 1570184221;
    fim_data->new_data->dev = 12345678;
    fim_data->new_data->scanned = 123456;
    fim_data->new_data->options = 511;
    strcpy(fim_data->new_data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    fim_data->json = NULL;

    *state = fim_data;

    return 0;
}

static int teardown_fim_data(void **state) {
    fim_data_t *fim_data = *state;

    free(fim_data->evt_data);
    free_whodata_event(fim_data->w_evt);
    free_file_data(fim_data->new_data);
    free_file_data(fim_data->old_data);
    free(fim_data);

    return 0;
}

static int setup_group(void **state) {
    if(setup_fim_data(state) != 0)
        return -1;

    test_mode = 0;
    expect_any_always(__wrap__mdebug1, formatted_msg);

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    // Read and setup global values.
    Read_Syscheck_Config("test_syscheck.conf");

    syscheck.rt_delay = 1;
    syscheck.max_depth = 256;
    syscheck.file_max_size = 1024;

    test_mode = 1;

    removed_entries = OSList_Create();
    if (removed_entries == NULL) {
        merror(MEM_ERROR, errno, strerror(errno));
        return -1;
    }
    OSList_SetFreeDataPointer(removed_entries, (void (*)(void *))free_directory);

#ifdef TEST_WINAGENT
    char *path = "C:\\a\\random\\path";
#else
    char *path = "/a/random/path";
#endif
    directory_t *directory0 = fim_create_directory(path, WHODATA_ACTIVE, NULL, 512, NULL, 1024, 1);

    OSList_InsertData(removed_entries, NULL, directory0);

    return 0;
}

static int setup_wildcards(void **state) {
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    // Wildcards list
    syscheck.wildcards = OSList_Create();
    if (syscheck.wildcards == NULL) {
        return -1;
    }
    OSList_SetFreeDataPointer(syscheck.wildcards, (void (*)(void *))free_directory);

#ifndef TEST_WINAGENT
    expect_string(__wrap_realpath, path, "/testdir?");
    will_return(__wrap_realpath, NULL);
    expect_string(__wrap_realpath, path, "/*/path");
    will_return(__wrap_realpath, NULL);

    char buffer1[20] = "/testdir?";
    char buffer2[20] = "/*/path";
    int options = WHODATA_ACTIVE | CHECK_FOLLOW;
#else
    char buffer1[20] = "c:\\testdir?";
    char buffer2[20] = "c:\\*\\path";
    int options = WHODATA_ACTIVE;
#endif

    directory_t *wildcard0 = fim_create_directory(buffer1, options, NULL, 512,
                                                  NULL, -1, 1);

    directory_t *wildcard1 = fim_create_directory(buffer2, options, NULL, 512,
                                                  NULL, -1, 1);

    OSList_InsertData(syscheck.wildcards, NULL, wildcard0);
    OSList_InsertData(syscheck.wildcards, NULL, wildcard1);

    // Directories list
    syscheck.directories = OSList_Create();
    if (syscheck.directories == NULL) {
        return -1;
    }

    return 0;
}

static int setup_root_group(void **state) {
    if(setup_fim_data(state) != 0)
        return -1;

    test_mode = 0;
    expect_any_always(__wrap__mdebug1, formatted_msg);

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    // Read and setup global values.
    Read_Syscheck_Config("test_syscheck_top_level.conf");

    syscheck.rt_delay = 1;
    syscheck.max_depth = 256;
    syscheck.file_max_size = 1024;

    test_mode = 1;

    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    if(teardown_fim_data(state) != 0)
        return -1;

    Free_Syscheck(&syscheck);

    syscheck.audit_key = NULL;

#ifdef TEST_WINAGENT
    syscheck.key_ignore = NULL;
    syscheck.key_ignore_regex = NULL;
#endif

    return 0;
}

static int teardown_wildcards(void **state) {
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    if (syscheck.wildcards) {
        OSList_SetFreeDataPointer(syscheck.wildcards, (void (*)(void *))free_directory);
        OSList_Destroy(syscheck.wildcards);
        syscheck.wildcards = NULL;
    }

    if (syscheck.directories) {
        OSList_SetFreeDataPointer(syscheck.directories, (void (*)(void *))free_directory);
        OSList_Destroy(syscheck.directories);
        syscheck.directories = NULL;
    }

    return 0;
}

static int teardown_delete_json(void **state) {
    fim_data_t *fim_data = *state;
    cJSON_Delete(fim_data->json);
    return 0;
}

static int setup_fim_entry(void **state) {
    fim_data_t *fim_data = *state;

    if(fim_data->fentry = calloc(1, sizeof(fim_entry)), fim_data->fentry == NULL)
        return -1;

    fim_data->fentry->type = FIM_TYPE_FILE;

    if(fim_data->local_data = calloc(1, sizeof(fim_file_data)), fim_data->local_data == NULL)
        return -1;

    fim_data->fentry->file_entry.path = NULL;

    fim_data->fentry->file_entry.data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    return 0;
}

static int teardown_fim_entry(void **state) {
    fim_data_t *fim_data = *state;
    if(fim_data->fentry != NULL) {
        if (fim_data->fentry->file_entry.path != NULL) {
                free(fim_data->fentry->file_entry.path);
        }
        free(fim_data->fentry);
    }
    if (fim_data != NULL) {
        free(fim_data->local_data->perm);
        free(fim_data->local_data->uid);
        free(fim_data->local_data->gid);
        free(fim_data->local_data->attributes);
        free(fim_data->local_data->user_name);
        free(fim_data->local_data->group_name);
        free(fim_data->local_data);
    }
    return 0;
}

static int teardown_local_data(void **state) {
    fim_data_t *fim_data = *state;

    free_file_data(fim_data->local_data);
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

static int setup_file_limit(void **state) {
    syscheck.file_limit_enabled = false;
    syscheck.file_entry_limit = 0;
#ifdef TEST_WINAGENT
    syscheck.registry_limit_enabled = false;
    syscheck.db_entry_registry_limit = 0;
#endif
    return 0;
}

static int teardown_file_limit(void **state) {
    syscheck.file_limit_enabled = true;
    syscheck.file_entry_limit = 50000;
#ifdef TEST_WINAGENT
    syscheck.registry_limit_enabled = true;
    syscheck.db_entry_registry_limit = 100000;
#endif
    return 0;
}

static int setup_fim_double_scan(void **state) {
    activate_full_db = true;
    struct dirent *dirent_st = calloc(1, sizeof(struct dirent));
    syscheck.database = calloc (1, sizeof(fdb_t));

    if (!dirent_st || !syscheck.database ) {
        return -1;
    }

    strcpy(dirent_st->d_name, "test_file");

#ifndef TEST_WINAGENT
    dirent_st->d_type = DT_REG;
    dirent_st->d_ino = 1;
#else
    dirent_st->d_ino = 0;
    dirent_st->d_reclen = 0;
    dirent_st->d_namlen = 9;
#endif
    *state = dirent_st;

    return 0;
}

static int teardown_fim_double_scan(void **state) {
    struct dirent *sd = state[0];
    free(sd);
    free(syscheck.database);
    syscheck.database = NULL;
    sd = NULL;
    activate_full_db = false;

#ifdef TEST_WINAGENT
    char *file = state[1];
    free(file);
#endif

    return 0;
}

static int setup_fim_not_double_scan(void **state) {
    syscheck.database = calloc (1, sizeof(fdb_t));

    if(!syscheck.database ) {
        return -1;
    }
    syscheck.database->full = true;
    return 0;
}

static int teardown_fim_not_double_scan(void **state) {
    free(syscheck.database);
    syscheck.database = NULL;
    return 0;
}

#ifndef TEST_WINAGENT
static int setup_fim_scan_realtime(void **state) {

    syscheck.database = calloc (1, sizeof(fdb_t));

    if (!syscheck.database) {
        return -1;
    }

    syscheck.database->full = true;
    return 0;
}

static int teardown_fim_scan_realtime(void **state) {
    os_free(syscheck.database);

    syscheck.realtime = NULL; // Used with local variables in some tests

    return 0;
}

#endif

static int setup_transaction_callback(void **state) {
    txn_data_t *txn_data = calloc(1, sizeof(txn_data_t));

    if (txn_data == NULL) {
        return 1;
    }

    txn_data->txn_context = calloc(1, sizeof(fim_txn_context_t));
    if (txn_data->txn_context == NULL) {
        return 1;
    }
    txn_data->txn_context->evt_data = calloc(1, sizeof(event_data_t));
    txn_data->txn_context->evt_data->report_event = true;
    txn_data->txn_context->evt_data->mode = FIM_SCHEDULED;
    txn_data->txn_context->evt_data->type = FIM_DELETE;

    *state = txn_data;
    return 0;
}

static int teardown_transaction_callback(void **state) {
    txn_data_t *txn_data = (txn_data_t *) *state;
    cJSON_Delete (txn_data->dbsync_event);

    if (txn_data->diff != NULL) {
        free(txn_data->diff);
    }

    if (txn_data->txn_context != NULL) {
        if (txn_data->txn_context->evt_data != NULL) {
            free(txn_data->txn_context->evt_data);
        }
        free(txn_data->txn_context);
    }

    free(txn_data);
    return 0;
}

static int setup_json_event_attributes(void **state) {
    json_struct_t *data = calloc(1, sizeof(json_struct_t));
    if (data == NULL) {
        return 1;
    }

    *state = data;
    return 0;
}

static int teardown_json_event_attributes(void **state) {
    json_struct_t *data = *state;

    cJSON_Delete(data->json1);
    cJSON_Delete(data->json2);

    free(data);

    return 0;
}

/* Auxiliar functions */
void expect_get_data (char *user, char *group, char *file_path, int calculate_checksums) {
#ifndef TEST_WINAGENT
    expect_get_user(0, user);
    expect_get_group(0, group);
#else
    cJSON *perms = cJSON_CreateObject();

    expect_get_file_user(file_path, "0", user);
    expect_w_get_file_permissions(file_path, perms, 0);

    expect_value(__wrap_decode_win_acl_json, perms, perms);

    expect_string(__wrap_get_UTC_modification_time, file_path, file_path);
    will_return(__wrap_get_UTC_modification_time, 123456);
#endif
    if (calculate_checksums) {
        expect_OS_MD5_SHA1_SHA256_File_call(file_path,
                                            syscheck.prefilter_cmd,
                                            "d41d8cd98f00b204e9800998ecf8427e",
                                            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                            OS_BINARY,
                                            0x400,
                                            0);
    }
}

/* tests */
static void test_fim_json_event(void **state) {
    fim_data_t *fim_data = *state;
    fim_entry entry = { .file_entry.path = "test.file", .file_entry.data = fim_data->new_data };
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true, .type = FIM_MODIFICATION };
    directory_t configuration = { .tag = "tag1,tag2" };

    fim_data->json = fim_json_event(&entry, fim_data->old_data, &configuration, &evt_data, NULL);

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "event");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *path = cJSON_GetObjectItem(data, "path");
    assert_string_equal(cJSON_GetStringValue(path), "test.file");
    cJSON *mode = cJSON_GetObjectItem(data, "mode");
    assert_string_equal(cJSON_GetStringValue(mode), "realtime");
    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    assert_string_equal(cJSON_GetStringValue(data_type), "modified");
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184221);
    cJSON *tags = cJSON_GetObjectItem(data, "tags");
    assert_string_equal(cJSON_GetStringValue(tags), "tag1,tag2");
#ifndef TEST_WINAGENT
    cJSON *hard_links = cJSON_GetObjectItem(data, "hard_links");
    assert_null(hard_links);
#endif
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    assert_non_null(changed_attributes);
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);

#ifdef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 10);
#else
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 11);
#endif
    assert_int_equal(cJSON_GetArraySize(attributes), 13);
    assert_int_equal(cJSON_GetArraySize(old_attributes), 13);

}


static void test_fim_json_event_whodata(void **state) {
    fim_data_t *fim_data = *state;
    fim_entry entry = { .file_entry.path = "test.file", .file_entry.data = fim_data->new_data };
    event_data_t evt_data = {
        .mode = FIM_WHODATA, .w_evt = fim_data->w_evt, .report_event = true, .type = FIM_MODIFICATION
    };
    directory_t configuration = { .tag = "tag1,tag2" };

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1))->options |= CHECK_SEECHANGES;

    fim_data->json = fim_json_event(&entry, fim_data->old_data, &configuration, &evt_data, "diff");

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1))->options &= ~CHECK_SEECHANGES;

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
#ifndef TEST_WINAGENT
    cJSON *hard_links = cJSON_GetObjectItem(data, "hard_links");
    assert_null(hard_links);
#endif
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    assert_non_null(audit);
#ifdef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(audit), 4);
#else
    assert_int_equal(cJSON_GetArraySize(audit), 14);
#endif
    cJSON *diff = cJSON_GetObjectItem(data, "content_changes");
    assert_string_equal(cJSON_GetStringValue(diff), "diff");
}


static void test_fim_json_event_no_changes(void **state) {
    fim_data_t *fim_data = *state;
    fim_entry entry = { .file_entry.path = "test.file", .file_entry.data = fim_data->new_data };
    event_data_t evt_data = {
        .mode = FIM_WHODATA, .w_evt = fim_data->w_evt, .report_event = true, .type = FIM_MODIFICATION
    };
    directory_t configuration = { .tag = "tag1,tag2" };

    fim_data->json = fim_json_event(&entry, fim_data->new_data, &configuration, &evt_data, NULL);

    assert_null(fim_data->json);
}

static void test_fim_json_event_hardlink_one_path(void **state) {
    fim_data_t *fim_data = *state;
    fim_entry entry = { .file_entry.path = "test.file", .file_entry.data = fim_data->new_data };
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true, .type = FIM_MODIFICATION };
    directory_t configuration = { .tag = NULL };

    fim_data->json = fim_json_event(&entry, fim_data->old_data, &configuration, &evt_data, NULL);

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "event");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *path = cJSON_GetObjectItem(data, "path");
    assert_string_equal(cJSON_GetStringValue(path), "test.file");
    cJSON *mode = cJSON_GetObjectItem(data, "mode");
    assert_string_equal(cJSON_GetStringValue(mode), "realtime");
    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    assert_string_equal(cJSON_GetStringValue(data_type), "modified");
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184221);
    cJSON *tags = cJSON_GetObjectItem(data, "tags");
    assert_null(tags);
#ifndef TEST_WINAGENT
    cJSON *hard_links = cJSON_GetObjectItem(data, "hard_links");
    assert_null(hard_links);
#endif
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    assert_non_null(changed_attributes);
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);

#ifndef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 11);
#else
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 10);
#endif
    assert_int_equal(cJSON_GetArraySize(attributes), 13);
    assert_int_equal(cJSON_GetArraySize(old_attributes), 13);
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
#ifndef TEST_WINAGENT
    assert_string_equal(cJSON_GetStringValue(perm), "0664");
#else
    assert_non_null(perm);
#endif
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

static void test_fim_attributes_json_without_options(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->old_data->options = 0;

    fim_data->json = fim_attributes_json(fim_data->old_data);

    fim_data->old_data->options = 511;

    assert_non_null(fim_data->json);
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 4);

    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "file");
    cJSON *user_name = cJSON_GetObjectItem(fim_data->json, "user_name");
    assert_string_equal(cJSON_GetStringValue(user_name), "test");
    cJSON *group_name = cJSON_GetObjectItem(fim_data->json, "group_name");
    assert_string_equal(cJSON_GetStringValue(group_name), "testing");
    cJSON *checksum = cJSON_GetObjectItem(fim_data->json, "checksum");
    assert_string_equal(cJSON_GetStringValue(checksum), "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}

static void test_fim_json_compare_attrs(void **state) {
    fim_data_t *fim_data = *state;
    int i = 0;

    fim_data->json = fim_json_compare_attrs(
        fim_data->old_data,
        fim_data->new_data
    );

    assert_non_null(fim_data->json);
#ifdef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 10);
#else
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 11);
#endif

    cJSON *size = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(size), "size");
    cJSON *permission = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(permission), "permission");
    cJSON *uid = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(uid), "uid");
    cJSON *user_name = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(user_name), "user_name");
    cJSON *gid = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(gid), "gid");
    cJSON *group_name = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(group_name), "group_name");
    cJSON *mtime = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(mtime), "mtime");
#ifndef TEST_WINAGENT
    cJSON *inode = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(inode), "inode");
#endif
    cJSON *md5 = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(md5), "md5");
    cJSON *sha1 = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(sha1), "sha1");
    cJSON *sha256 = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(sha256), "sha256");

}

static void test_fim_json_compare_attrs_without_options(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->old_data->options = 0;

    fim_data->json = fim_json_compare_attrs(
        fim_data->old_data,
        fim_data->new_data
    );

    fim_data->old_data->options = 511;

    assert_non_null(fim_data->json);
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 0);

}


static void test_fim_audit_json(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_audit_json(fim_data->w_evt);

    assert_non_null(fim_data->json);
#ifdef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 4);
#else
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 14);
#endif

    cJSON *user_id = cJSON_GetObjectItem(fim_data->json, "user_id");
    assert_string_equal(cJSON_GetStringValue(user_id), "100");
    cJSON *user_name = cJSON_GetObjectItem(fim_data->json, "user_name");
    assert_string_equal(cJSON_GetStringValue(user_name), "test");
    cJSON *process_name = cJSON_GetObjectItem(fim_data->json, "process_name");
    assert_string_equal(cJSON_GetStringValue(process_name), "test_proc");
    cJSON *process_id = cJSON_GetObjectItem(fim_data->json, "process_id");
    assert_non_null(process_id);
    assert_int_equal(process_id->valueint, 1001);

#ifndef TEST_WINAGENT
    cJSON *cwd = cJSON_GetObjectItem(fim_data->json, "cwd");
    assert_string_equal(cJSON_GetStringValue(cwd), "process_cwd");
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
    cJSON *parent_cwd = cJSON_GetObjectItem(fim_data->json, "parent_cwd");
    assert_string_equal(cJSON_GetStringValue(parent_cwd), "parent_cwd");
    cJSON *parent_name = cJSON_GetObjectItem(fim_data->json, "parent_name");
    assert_string_equal(cJSON_GetStringValue(parent_name), "parent_name");
#endif
}

#ifndef TEST_WINAGENT
static void test_fim_check_ignore_strncasecmp(void **state) {
    int ret;
    char debug_msg[OS_MAXSTR];

    snprintf(debug_msg, OS_MAXSTR, FIM_IGNORE_ENTRY, "/EtC/dumPDateS", "/etc/dumpdates");

    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    ret = fim_check_ignore("/EtC/dumPDateS", FIM_REGULAR);

    assert_int_equal(ret, 1);
}
#else
static void test_fim_check_ignore_strncasecmp(void **state) {
    int ret;
    char *path = "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\DeskTop.ini";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    snprintf(debug_msg, OS_MAXSTR, FIM_IGNORE_ENTRY, expanded_path, syscheck.ignore[0]);

    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);


    ret = fim_check_ignore(expanded_path, FIM_REGULAR);

    assert_int_equal(ret, 1);
}
#endif

static void test_fim_check_ignore_regex_file(void **state) {
    int ret;
    char debug_msg[OS_MAXSTR];


#ifndef TEST_WINAGENT
    snprintf(debug_msg, OS_MAXSTR, FIM_IGNORE_SREGEX, "/test/files/test.swp", ".log$|.swp$");
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
#else
    snprintf(debug_msg, OS_MAXSTR, FIM_IGNORE_SREGEX, "/test/files/test.swp", ".log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$|.swp$");
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
#endif

    ret = fim_check_ignore("/test/files/test.swp", FIM_REGULAR);

    assert_int_equal(ret, 1);
}

static void test_fim_check_ignore_regex_directory(void **state) {
    int ret;
    char debug_msg[OS_MAXSTR];


#ifndef TEST_WINAGENT
    snprintf(debug_msg, OS_MAXSTR, FIM_IGNORE_SREGEX, "/test/files", ".log$|.swp$");
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
#else
    snprintf(debug_msg, OS_MAXSTR, FIM_IGNORE_SREGEX, "/test/files", ".log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$|.swp$");
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
#endif

    ret = fim_check_ignore("/test/files", FIM_DIRECTORY);

    assert_int_equal(ret, 0);
}


static void test_fim_check_ignore_failure(void **state) {
   int ret;

    ret = fim_check_ignore("/test/files/test.sp", FIM_REGULAR);

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

    expect_string(__wrap__mdebug2, formatted_msg, "(6203): Ignoring entry 'my_test_' due to restriction 'test$'");

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
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
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
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(type->valuestring, "scan_end");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184220);
}


static void test_fim_get_checksum(void **state) {
    fim_entry entry = {.file_entry.path = "/media/test", .file_entry.data=&DEFAULT_FILE_DATA};

    fim_get_checksum(entry.file_entry.data);
#ifdef TEST_WINAGENT
    assert_string_equal(entry.file_entry.data->checksum, "6ec831114b5d930f19a90d7c34996e0fce4e7b84");
#else
    assert_string_equal(entry.file_entry.data->checksum, "98e039efc1b8490965e7e1247a9dc31cf7379051");
#endif
}


static void test_fim_get_checksum_wrong_size(void **state) {
    fim_data_t *fim_data = *state;
    fim_data->local_data = calloc(1, sizeof(fim_file_data));

    fim_data->local_data->size = -1;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    fim_get_checksum(fim_data->local_data);

    assert_string_equal(fim_data->local_data->checksum, "0a0070d140761418be81531ad48f5909f410e161");
}

static void test_fim_check_depth_success(void **state) {
#ifndef TEST_WINAGENT
    char * path = "/usr/bin/folder1/folder2/folder3/file";
    directory_t configuration = { .path = "/usr/bin", .recursion_level = 4 };

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#else

    char *aux_path = "c:\\windows\\System32\\wbem\\folder1\\folder2\\folder3\\path.exe";
    directory_t configuration = { .path = "c:\\windows\\System32\\wbem", .recursion_level = 4 };
    char path[OS_MAXSTR];

    if(!ExpandEnvironmentStrings(aux_path, path, OS_MAXSTR))
        fail();
#endif
    int ret;

    ret = fim_check_depth(path, &configuration);

    assert_int_equal(ret, 3);
}


static void test_fim_check_depth_failure_strlen(void **state) {
    char * path = "fl/fd";
    directory_t configuration = { .path = "/usr/bin", .recursion_level = 4 };
    int ret;

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    ret = fim_check_depth(path, &configuration);

    assert_int_equal(ret, -1);

}

static void test_fim_check_depth_failure_null_directory(void **state) {
    char * path = "/usr/bin";
    directory_t configuration = { .path = "/usr/bin", .recursion_level = 6 };
    int ret;

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    ret = fim_check_depth(path, &configuration);

    assert_int_equal(ret, -1);

}

static void test_fim_configuration_directory_no_path(void **state) {
    directory_t *ret;

    ret = fim_configuration_directory(NULL);

    assert_null(ret);
}


#ifndef TEST_WINAGENT
static void test_fim_configuration_directory_file(void **state) {
    directory_t *ret;

    const char * path = "/media";

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    ret = fim_configuration_directory(path);

    assert_non_null(ret);
    assert_ptr_equal(ret, ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3)));
}
#else
static void test_fim_configuration_directory_file(void **state) {
    char *aux_path = "%WINDIR%\\System32\\drivers\\etc";
    char path[OS_MAXSTR];
    directory_t *ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    if(!ExpandEnvironmentStrings(aux_path, path, OS_MAXSTR))
        fail();

    str_lowercase(path);

    ret = fim_configuration_directory(path);

    assert_ptr_equal(ret, ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3)));
}
#endif


static void test_fim_configuration_directory_not_found(void **state) {
    const char *path = "/invalid";
    directory_t *ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    ret = fim_configuration_directory(path);

    assert_null(ret);
}

static void test_init_fim_data_entry(void **state) {
    fim_file_data entry;
    init_fim_data_entry(&entry);

    assert_int_equal(entry.size, 0);
    assert_null(entry.perm);
    assert_null(entry.attributes);
    assert_null(entry.uid);
    assert_null(entry.gid);
    assert_null(entry.user_name);
    assert_null(entry.group_name);
    assert_int_equal(entry.mtime, 0);
    assert_int_equal(entry.inode, 0);
    assert_int_equal(entry.hash_md5[0], 0);
    assert_int_equal(entry.hash_sha1[0], 0);
    assert_int_equal(entry.hash_sha256[0], 0);
}

static void test_fim_file_add(void **state) {
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true, .statbuf = DEFAULT_STATBUF };
    directory_t configuration = { .options = CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MD5SUM |
                                             CHECK_SHA1SUM | CHECK_MTIME | CHECK_SHA256SUM | CHECK_SEECHANGES };
#ifdef TEST_WINAGENT
    char file_path[OS_SIZE_256] = "c:\\windows\\system32\\cmd.exe";
#else
    char file_path[OS_SIZE_256] = "/bin/ls";
#endif

    expect_get_data(strdup("user"), strdup("group"), file_path, 1);

    will_return(__wrap_fim_db_file_update, FIMDB_OK);

    fim_file(file_path, &configuration, &evt_data, NULL, NULL);
}

static void test_fim_file_modify_transaction(void **state) {
    fim_data_t *fim_data = *state;
    event_data_t evt_data = { .mode = FIM_SCHEDULED, .w_evt = NULL, .report_event = true, .statbuf = DEFAULT_STATBUF };
    directory_t configuration = { .options = CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MD5SUM |
                                             CHECK_SHA1SUM | CHECK_SHA256SUM };
    TXN_HANDLE mock_handle = (TXN_HANDLE)1;

    fim_txn_context_t mock_context = {0};

#ifdef TEST_WINAGENT
    char file_path[OS_SIZE_256] = "c:\\windows\\system32\\cmd.exe";
    cJSON *permissions = create_win_permissions_object();
#else
    char file_path[OS_SIZE_256] = "/bin/ls";
#endif

    fim_data->fentry->file_entry.path = strdup("file");
    fim_data->fentry->file_entry.data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    // Inside fim_get_data
#ifndef TEST_WINAGENT
    expect_get_user(0, strdup("user"));

    expect_get_group(0, strdup("group"));
#else

    expect_get_file_user(file_path, "0", strdup("user"));
    expect_w_get_file_permissions(file_path, permissions, 0);

    expect_value(__wrap_decode_win_acl_json, perms, permissions);
#endif

    expect_OS_MD5_SHA1_SHA256_File_call(file_path, syscheck.prefilter_cmd, "d41d8cd98f00b204e9800998ecf8427e",
                                        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", OS_BINARY,
                                        0x400, 0);

    will_return(__wrap_fim_db_transaction_sync_row, FIMDB_OK);

    fim_file(file_path, &configuration, &evt_data, mock_handle, &mock_context);
}

static void test_fim_file_modify(void **state) {
    fim_data_t *fim_data = *state;
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true, .statbuf = DEFAULT_STATBUF };
    directory_t configuration = { .options = CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MD5SUM |
                                             CHECK_SHA1SUM | CHECK_SHA256SUM };
#ifdef TEST_WINAGENT
    char file_path[OS_SIZE_256] = "c:\\windows\\system32\\cmd.exe";
    cJSON *permissions = create_win_permissions_object();
#else
    char file_path[OS_SIZE_256] = "/bin/ls";
#endif

    fim_data->fentry->file_entry.path = strdup("file");
    fim_data->fentry->file_entry.data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    // Inside fim_get_data
#ifndef TEST_WINAGENT
    expect_get_user(0, strdup("user"));

    expect_get_group(0, strdup("group"));
#else

    expect_get_file_user(file_path, "0", strdup("user"));
    expect_w_get_file_permissions(file_path, permissions, 0);

    expect_value(__wrap_decode_win_acl_json, perms, permissions);
#endif

    expect_OS_MD5_SHA1_SHA256_File_call(file_path, syscheck.prefilter_cmd, "d41d8cd98f00b204e9800998ecf8427e",
                                        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", OS_BINARY,
                                        0x400, 0);

    will_return(__wrap_fim_db_file_update, FIMDB_OK);

    fim_file(file_path, &configuration, &evt_data, NULL, NULL);
}

static void test_fim_file_no_attributes(void **state) {
    char buffer1[OS_SIZE_256];
    char buffer2[OS_SIZE_256];
    event_data_t evt_data = { .mode = FIM_SCHEDULED, .w_evt = NULL, .report_event = true, .statbuf = DEFAULT_STATBUF };
    directory_t configuration = { .options = CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MD5SUM |
                                             CHECK_SHA1SUM | CHECK_SHA256SUM };
#ifdef TEST_WINAGENT
    char file_path[] = "c:\\windows\\system32\\cmd.exe";
    cJSON *permissions = create_win_permissions_object();
#else
    char file_path[] = "/bin/ls";
#endif

    // Inside fim_get_data
#ifndef TEST_WINAGENT
    expect_get_user(0, strdup("user"));
    expect_get_group(0, strdup("group"));
#else
    expect_get_file_user(file_path, "0", strdup("user"));

    expect_w_get_file_permissions(file_path, permissions, 0);

    expect_value(__wrap_decode_win_acl_json, perms, permissions);
#endif

    expect_OS_MD5_SHA1_SHA256_File_call(file_path,
                                        syscheck.prefilter_cmd,
                                        "d41d8cd98f00b204e9800998ecf8427e",
                                        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                        OS_BINARY,
                                        0x400,
                                        -1);

    snprintf(buffer1, OS_SIZE_256, FIM_HASHES_FAIL, file_path);
    snprintf(buffer2, OS_SIZE_256, FIM_GET_ATTRIBUTES, file_path);

    expect_string(__wrap__mdebug1, formatted_msg, buffer1);
    expect_string(__wrap__mdebug1, formatted_msg, buffer2);


    fim_file(file_path, &configuration, &evt_data, NULL, NULL);
}

static void test_fim_file_error_on_insert(void **state) {
    fim_data_t *fim_data = *state;
    event_data_t evt_data = { .mode = FIM_SCHEDULED, .w_evt = NULL, .report_event = true, .statbuf = DEFAULT_STATBUF };
    directory_t configuration = { .options = CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MD5SUM |
                                             CHECK_SHA1SUM | CHECK_SHA256SUM };
#ifdef TEST_WINAGENT
    char file_path[OS_SIZE_256] = "c:\\windows\\system32\\cmd.exe";
    cJSON *permissions = create_win_permissions_object();
#else
    char file_path[OS_SIZE_256] = "/bin/ls";
#endif

    fim_data->fentry->file_entry.path = strdup(file_path);
    fim_data->fentry->file_entry.data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    // Inside fim_get_data
#ifndef TEST_WINAGENT
    expect_get_user(0, strdup("user"));
    expect_get_group(0, strdup("group"));
#else
    expect_get_file_user(file_path, "0", strdup("user"));
    expect_w_get_file_permissions(file_path, permissions, 0);

    expect_value(__wrap_decode_win_acl_json, perms, permissions);
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, file_path);
#ifndef TEST_WINAGENT
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, syscheck.prefilter_cmd);
#else
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, syscheck.prefilter_cmd);
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    will_return(__wrap_fim_db_file_update, FIMDB_OK);

    fim_file(file_path, &configuration, &evt_data, NULL, NULL);
}

static void test_fim_checker_scheduled_configuration_directory_error(void **state) {
    char * path = "/not/found/test.file";
    event_data_t evt_data = { .mode = FIM_SCHEDULED, .w_evt = NULL, .report_event = true };
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/not/found/test.file'");

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_not_scheduled_configuration_directory_error(void **state) {
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    const char *path = "/not/found/test.file";

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/not/found/test.file'");

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

#ifndef TEST_WINAGENT
static void test_fim_checker_over_max_recursion_level(void **state) {
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    const char *path = "/media/a/test.file";

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3))->recursion_level = 0;

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6217): Maximum level of recursion reached. Depth:1 recursion_level:0 '/media/a/test.file'");

    fim_checker(path, &evt_data, NULL, NULL, NULL);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3))->recursion_level = 50;
}

static void test_fim_checker_deleted_file(void **state) {
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    struct stat statbuf = DEFAULT_STATBUF;
    const char *path = "/media/test.file";

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "(6222): Stat() function failed on: '/media/test.file' due to [(1)-(Operation not permitted)]");

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, -1);

    errno = 1;

    fim_checker(path, &evt_data, NULL, NULL, NULL);

    errno = 0;
}

static void test_fim_checker_deleted_file_enoent(void **state) {
    fim_data_t *fim_data = *state;
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    struct stat statbuf = DEFAULT_STATBUF;
    const char *path = "/media/test.file";

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3))->options |= CHECK_SEECHANGES;

    fim_data->fentry->file_entry.path = strdup("/media/test.file");
    fim_data->fentry->file_entry.data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, -1);
    errno = ENOENT;

    expect_fim_db_get_path("/media/test.file", FIMDB_ERR);
    expect_fim_diff_process_delete_file(path, 0);

    fim_checker(path, &evt_data, NULL, NULL, NULL);

    errno = 0;
    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3))->options &= ~CHECK_SEECHANGES;
}

static void test_fim_checker_no_file_system(void **state) {
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    struct stat statbuf = DEFAULT_STATBUF;
    const char *path = "/media/test.file";
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/test.file");
    will_return(__wrap_HasFilesystem, -1);

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_regular(void **state) {
    const char *path = "/media/test.file";
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    struct stat statbuf = { .st_mode = S_IFREG,
                            .st_dev = 1,
                            .st_ino = 999,
                            .st_uid = 0,
                            .st_gid = 0,
                            .st_mtime = 1433395216,
                            .st_size = 1500 };

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, path);
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));
    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("group"));
    will_return(__wrap_fim_db_file_update, FIMDB_OK);

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_regular_warning(void **state) {
    const char *path = "/media/test.file";
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    struct stat statbuf = { .st_mode = S_IFREG,
                            .st_dev = 1,
                            .st_ino = 999,
                            .st_uid = 0,
                            .st_gid = 0,
                            .st_mtime = 1433395216,
                            .st_size = 1500 };

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/test.file");
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("group"));
    will_return(__wrap_fim_db_file_update, FIMDB_OK);

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_regular_ignore(void **state) {
    struct stat statbuf = DEFAULT_STATBUF;
    event_data_t evt_data = { .mode = FIM_WHODATA, .w_evt = NULL, .report_event = true };
    const char *path = "/etc/mtab";
    char debug_msg[OS_MAXSTR];

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, path);
    will_return(__wrap_HasFilesystem, 0);

    snprintf(debug_msg, OS_MAXSTR, FIM_IGNORE_ENTRY, path, path);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_regular_restrict(void **state) {
    struct stat statbuf = DEFAULT_STATBUF;
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    const char *path = "/media/test";

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, path);
    will_return(__wrap_HasFilesystem, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6203): Ignoring entry '/media/test' due to restriction 'file$'");

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_directory(void **state) {
    fim_data_t *fim_data = *state;
    struct stat directory_stat = DEFAULT_STATBUF;
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    const char *path = "/media/";

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    directory_stat.st_mode = S_IFDIR;

    expect_string(__wrap_lstat, filename, "/media/");
    will_return(__wrap_lstat, &directory_stat);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_lstat, filename, "/media/test");
    will_return(__wrap_lstat, &directory_stat);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/");
    expect_string(__wrap_HasFilesystem, path, "/media/test");
    will_return_always(__wrap_HasFilesystem, 0);

    expect_string(__wrap_fim_add_inotify_watch, dir, "/media/test");
    will_return(__wrap_fim_add_inotify_watch, 0);
    expect_string(__wrap_fim_add_inotify_watch, dir, "/media/");
    will_return(__wrap_fim_add_inotify_watch, 0);

    strcpy(fim_data->entry->d_name, "test");

    will_return_always(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_readdir, NULL);

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_directory_on_max_recursion_level(void **state) {
    fim_data_t *fim_data = *state;
    struct stat statbuf = DEFAULT_STATBUF;
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    const char *path = "/media";

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    statbuf.st_mode = S_IFDIR;

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3))->recursion_level = 0;

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, path);
    will_return(__wrap_HasFilesystem, 0);

    expect_string(__wrap_fim_add_inotify_watch, dir, path);
    will_return(__wrap_fim_add_inotify_watch, 0);

    will_return(__wrap_opendir, 1);
    strcpy(fim_data->entry->d_name, "test");
    will_return(__wrap_readdir, fim_data->entry);

    expect_string(__wrap_lstat, filename, "/media/test");
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/test");
    will_return(__wrap_HasFilesystem, 0);

    will_return(__wrap_readdir, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6347): Directory '/media/test' is already on the max recursion_level (0), it will not be scanned.");

    fim_checker(path, &evt_data, NULL, NULL, NULL);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3))->recursion_level = 50;
}

static void test_fim_checker_root_ignore_file_under_recursion_level(void **state) {
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    const char *path = "/media/test.file";

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6217): Maximum level of recursion reached. Depth:1 recursion_level:0 '/media/test.file'");

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_root_file_within_recursion_level(void **state) {
    struct stat statbuf = DEFAULT_STATBUF;
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    const char *path = "/test.file";

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    statbuf.st_size = 0;

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &statbuf);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, path);
    will_return(__wrap_HasFilesystem, 0);
    // Inside fim_file
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("group"));
    will_return(__wrap_fim_db_file_update, FIMDB_OK);

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_scan_db_full_double_scan(void **state) {
    struct stat directory_buf = { .st_mode = S_IFDIR };
    directory_t *dir_it;
    OSListNode *node_it;
    TXN_HANDLE mock_handle = NULL;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    will_return(__wrap_fim_db_transaction_start, &mock_handle);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    // First scan
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        expect_string(__wrap_lstat, filename, dir_it->path);
        will_return(__wrap_lstat, &directory_buf);
        will_return(__wrap_lstat, 0);

        expect_string(__wrap_HasFilesystem, path, dir_it->path);
        will_return(__wrap_HasFilesystem, 0);

        if (FIM_MODE(dir_it->options) == FIM_REALTIME) {
            expect_string(__wrap_fim_add_inotify_watch, dir, dir_it->path);
            will_return(__wrap_fim_add_inotify_watch, 0);
        }

        expect_string(__wrap_realtime_adddir, dir, dir_it->path);
        will_return(__wrap_realtime_adddir, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }

    expect_wrapper_fim_db_get_count_file_entry(50000);
    expect_function_call_any(__wrap_fim_db_transaction_deleted_rows);

    // Second scan
    will_return(__wrap_fim_db_transaction_start, &mock_handle);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        expect_string(__wrap_lstat, filename, dir_it->path);
        will_return(__wrap_lstat, &directory_buf);
        will_return(__wrap_lstat, 0);

        expect_string(__wrap_HasFilesystem, path, dir_it->path);
        will_return(__wrap_HasFilesystem, 0);

        if (FIM_MODE(dir_it->options) == FIM_REALTIME) {
            expect_string(__wrap_fim_add_inotify_watch, dir, dir_it->path);
            will_return(__wrap_fim_add_inotify_watch, 0);
        }

        expect_string(__wrap_realtime_adddir, dir, dir_it->path);
        will_return(__wrap_realtime_adddir, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }
    expect_wrapper_fim_db_get_count_file_entry(50000);

    // fim_check_db_state
    expect_string(__wrap__mwarn, formatted_msg, "(6926): File database is 100% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    // fim_send_scan_info
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}


static void test_fim_scan_db_full_not_double_scan(void **state) {
    struct stat directory_buf = { .st_mode = S_IFDIR };
    directory_t *dir_it;
    OSListNode *node_it;
    TXN_HANDLE mock_handle = NULL;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    will_return(__wrap_fim_db_transaction_start, &mock_handle);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    // First scan
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        expect_string(__wrap_lstat, filename, dir_it->path);
        will_return(__wrap_lstat, &directory_buf);
        will_return(__wrap_lstat, 0);

        expect_string(__wrap_HasFilesystem, path, dir_it->path);
        will_return(__wrap_HasFilesystem, 0);

        if (FIM_MODE(dir_it->options) == FIM_REALTIME) {
            expect_string(__wrap_fim_add_inotify_watch, dir, dir_it->path);
            will_return(__wrap_fim_add_inotify_watch, 0);
        }

        expect_string(__wrap_realtime_adddir, dir, dir_it->path);
        will_return(__wrap_realtime_adddir, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }

    expect_wrapper_fim_db_get_count_file_entry(25000);
    expect_function_call_any(__wrap_fim_db_transaction_deleted_rows);
    expect_wrapper_fim_db_get_count_file_entry(25000);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

static void test_fim_scan_realtime_enabled(void **state) {
    OSHashNode empty_table = { .key = NULL }, *table = &empty_table;
    OSHash dirtb = { .elements = 10, .table = &table, .rows = 0 }; // this hash is not reallistic but works for testing
    rtfim realtime = { .queue_overflow = true, .dirtb = &dirtb };
    struct stat directory_buf = { .st_mode = S_IFDIR };
    directory_t *dir_it;
    OSListNode *node_it;
    TXN_HANDLE mock_handle = NULL;
    char debug_buffer[OS_SIZE_128] = {0};
    int rt_folder = 0;
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    will_return(__wrap_fim_db_transaction_start, &mock_handle);

    syscheck.realtime = &realtime;

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    // First scan
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        expect_string(__wrap_lstat, filename, dir_it->path);
        will_return(__wrap_lstat, &directory_buf);
        will_return(__wrap_lstat, 0);

        expect_string(__wrap_HasFilesystem, path, dir_it->path);
        will_return(__wrap_HasFilesystem, 0);

        if (FIM_MODE(dir_it->options) == FIM_REALTIME) {
            rt_folder++;
            expect_string(__wrap_fim_add_inotify_watch, dir, dir_it->path);
            will_return(__wrap_fim_add_inotify_watch, 0);
        }

        expect_string(__wrap_realtime_adddir, dir, dir_it->path);
        will_return(__wrap_realtime_adddir, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }

    // fim_scan
    expect_wrapper_fim_db_get_count_file_entry(25000);

    expect_function_call_any(__wrap_fim_db_transaction_deleted_rows);

    // fim_check_db_state
    expect_wrapper_fim_db_get_count_file_entry(50000);
    expect_function_call(__wrap_realtime_sanitize_watch_map);

    // fim_check_db_state
    snprintf(debug_buffer, OS_SIZE_128, FIM_NUM_WATCHES, dirtb.elements);
    expect_string(__wrap__mdebug2, formatted_msg, debug_buffer);

    expect_string(__wrap__mwarn, formatted_msg, "(6926): File database is 100% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();

    assert_int_equal(syscheck.realtime->queue_overflow, false);
}

static void test_fim_scan_no_limit(void **state) {
    struct stat directory_buf = { .st_mode = S_IFDIR };
    directory_t *dir_it;
    OSListNode *node_it;
    TXN_HANDLE mock_handle = NULL;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    will_return(__wrap_fim_db_transaction_start, &mock_handle);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    // First scan
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        expect_string(__wrap_lstat, filename, dir_it->path);
        will_return(__wrap_lstat, &directory_buf);
        will_return(__wrap_lstat, 0);

        expect_string(__wrap_HasFilesystem, path, dir_it->path);
        will_return(__wrap_HasFilesystem, 0);

        if (FIM_MODE(dir_it->options) == FIM_REALTIME) {
            expect_string(__wrap_fim_add_inotify_watch, dir, dir_it->path);
            will_return(__wrap_fim_add_inotify_watch, 0);
        }

        expect_string(__wrap_realtime_adddir, dir, dir_it->path);
        will_return(__wrap_realtime_adddir, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }
    expect_function_call_any(__wrap_fim_db_transaction_deleted_rows);

    // In fim_scan
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

#else
static void test_fim_checker_over_max_recursion_level(void **state) {
    event_data_t evt_data = { .mode = FIM_REALTIME, .report_event = true, .w_evt = NULL };
    char *path = "%WINDIR%\\System32\\drivers\\etc\\random\\test.exe";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 2))->recursion_level = 0;
    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    snprintf(debug_msg, OS_MAXSTR,
        "(6217): Maximum level of recursion reached. Depth:1 recursion_level:0 '%s'", expanded_path);

    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    fim_checker(expanded_path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_deleted_file(void **state) {
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    struct stat stat_s = { .st_mode = S_IFREG };
    char *path = "%WINDIR%\\System32\\drivers\\etc\\test.exe";
    char expanded_path[OS_MAXSTR];
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__mdebug1, formatted_msg, "(6222): Stat() function failed on: 'c:\\windows\\system32\\drivers\\etc\\test.exe' due to [(1)-(Operation not permitted)]");

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(wrap__stat64, __file, expanded_path);
    will_return(wrap__stat64, &stat_s);
    will_return(wrap__stat64, -1);

    errno = 1;

    fim_checker(expanded_path, &evt_data, NULL, NULL, NULL);

    errno = 0;
}

static void test_fim_checker_deleted_file_enoent(void **state) {
    fim_data_t *fim_data = *state;
    struct stat stat_s = { .st_mode = S_IFREG };
    char *path = "%WINDIR%\\System32\\drivers\\etc\\test.exe";
    char expanded_path[OS_MAXSTR];
    event_data_t evt_data = { .mode = FIM_REALTIME, .report_event = true };

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3))->options |= CHECK_SEECHANGES;

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    fim_data->fentry->file_entry.path = strdup(expanded_path);
    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    expect_string(wrap__stat64, __file, expanded_path);
    will_return(wrap__stat64, &stat_s);
    will_return(wrap__stat64, -1);

    errno = ENOENT;

    expect_string(__wrap_fim_db_get_path, file_path, expanded_path);
    will_return(__wrap_fim_db_get_path, FIMDB_ERR);

    expect_fim_diff_process_delete_file(expanded_path, 0);

    fim_checker(expanded_path, &evt_data, NULL, NULL, NULL);

    errno = 0;
    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3))->options &= ~CHECK_SEECHANGES;
}

static void test_fim_checker_fim_regular(void **state) {
    fim_data_t *fim_data = *state;
    struct stat stat_s = { .st_mode = S_IFREG };
    char *path = "%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    char expanded_path[OS_SIZE_128];
    event_data_t evt_data = { .mode = FIM_WHODATA, .w_evt = fim_data->w_evt, .report_event = true };
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    if (!ExpandEnvironmentStrings(path, expanded_path, OS_SIZE_128)) {
        fail();
    }

    expect_string(wrap__stat64, __file, expanded_path);
    will_return(wrap__stat64, &stat_s);
    will_return(wrap__stat64, 0);

    str_lowercase(expanded_path);

    expect_string(__wrap_HasFilesystem, path, expanded_path);

    will_return(__wrap_HasFilesystem, 0);
    // Inside fim_file
    expect_get_data(strdup("user"), "group", expanded_path, 0);
    will_return(__wrap_fim_db_file_update, FIMDB_OK);
    expect_string(__wrap_w_get_file_attrs, file_path, expanded_path);
    will_return(__wrap_w_get_file_attrs, 123456);
    fim_checker(expanded_path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_regular_ignore(void **state) {
    struct stat stat_s = { .st_mode = S_IFREG };
    char *path = "%WINDIR%\\System32\\drivers\\etc\\ignored.file";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(wrap__stat64, __file, expanded_path);
    will_return(wrap__stat64, &stat_s);
    will_return(wrap__stat64, 0);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    will_return(__wrap_HasFilesystem, 0);

    snprintf(debug_msg, OS_MAXSTR, FIM_IGNORE_ENTRY, expanded_path, expanded_path);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    fim_checker(expanded_path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_regular_restrict(void **state) {
    struct stat stat_s = { .st_mode = S_IFREG };
    char * path = "%WINDIR%\\System32\\wbem\\restricted.exe";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];
    event_data_t evt_data = { .mode = FIM_REALTIME, .report_event = true };
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(wrap__stat64, __file, expanded_path);
    will_return(wrap__stat64, &stat_s);
    will_return(wrap__stat64, 0);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    will_return(__wrap_HasFilesystem, 0);

    snprintf(debug_msg, OS_MAXSTR, "(6203): Ignoring entry '%s' due to restriction 'wmic.exe$'", expanded_path);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    fim_checker(expanded_path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_regular_warning(void **state) {
    struct stat stat_s = { .st_mode = S_IFREG };
    char *path = "%WINDIR%\\System32\\drivers\\etc\\test.exe";
    char expanded_path[OS_MAXSTR];
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(wrap__stat64, __file, expanded_path);
    will_return(wrap__stat64, &stat_s);
    will_return(wrap__stat64, 0);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_get_data(strdup("user"), "group", expanded_path, 0);

    expect_string(__wrap_w_get_file_attrs, file_path, expanded_path);
    will_return(__wrap_w_get_file_attrs, 123456);

    will_return(__wrap_fim_db_file_update, FIMDB_OK);

    fim_checker(expanded_path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_fim_directory(void **state) {
    fim_data_t *fim_data = *state;
    struct stat stat_s = { .st_mode = S_IFDIR };
    char * path = "%WINDIR%\\System32\\drivers\\etc";
    char skip_directory_message[OS_MAXSTR];
    char expanded_path[OS_MAXSTR];
    char expanded_path_test[OS_MAXSTR];
    event_data_t evt_data = { .mode = FIM_REALTIME, .report_event = true };
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    snprintf(expanded_path_test, OS_MAXSTR, "%s\\test", expanded_path);

    expect_string(wrap__stat64, __file, expanded_path);
    expect_string(wrap__stat64, __file, expanded_path_test);
    will_return(wrap__stat64, &stat_s);
    will_return(wrap__stat64, 0);
    will_return(wrap__stat64, &stat_s);
    will_return(wrap__stat64, 0);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    expect_string(__wrap_HasFilesystem, path, expanded_path_test);
    will_return_always(__wrap_HasFilesystem, 0);

    strcpy(fim_data->entry->d_name, "test");

    will_return_always(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);


    snprintf(skip_directory_message, OS_MAXSTR,
        "(6347): Directory '%s' is already on the max recursion_level (0), it will not be scanned.", expanded_path_test);
    expect_string(__wrap__mdebug2, formatted_msg, skip_directory_message);

    fim_checker(expanded_path, &evt_data, NULL, NULL, NULL);
}


static void test_fim_checker_root_ignore_file_under_recursion_level(void **state) {
    char * path = "c:\\windows\\test.file";
    event_data_t evt_data = { .mode = FIM_REALTIME, .report_event = true };
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6217): Maximum level of recursion reached. Depth:1 recursion_level:0 'c:\\windows\\test.file'");

    fim_checker(path, &evt_data, NULL, NULL, NULL);
}

static void test_fim_checker_root_file_within_recursion_level(void **state) {
    char * path = "c:\\test.file";
    struct stat statbuf = DEFAULT_STATBUF;
    event_data_t evt_data = { .mode = FIM_REALTIME, .report_event = true, .w_evt = NULL };

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    TXN_HANDLE txn_handle = (TXN_HANDLE) 1;
    fim_txn_context_t mock_context = {0};
    statbuf.st_size = 0;

    // Inside fim_file
    expect_get_data(strdup("user"), "", path, 0);

    expect_string(__wrap_w_get_file_attrs, file_path, "c:\\test.file");
    will_return(__wrap_w_get_file_attrs, 123456);

    expect_string(wrap__stat64, __file, "c:\\test.file");
    will_return(wrap__stat64, &statbuf);
    will_return(wrap__stat64, 0);

    expect_string(__wrap_HasFilesystem, path, "c:\\test.file");
    will_return(__wrap_HasFilesystem, 0);

    will_return(__wrap_fim_db_transaction_sync_row, 0);
    fim_checker(path, &evt_data, NULL, &txn_handle, &mock_context);
}

static void test_fim_scan_db_full_double_scan(void **state) {
    char test_file_path[OS_SIZE_256];
    struct stat directory_stat = { .st_mode = S_IFDIR };
    TXN_HANDLE mock_handle;
    char expanded_dirs[10][OS_SIZE_1024];
    char directories[6][OS_SIZE_256] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%",
        "%WINDIR%\\System32",
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
    };
    int i;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    will_return(__wrap_fim_db_transaction_start, mock_handle);
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    for(i = 0; i < 6; i++) {
        if(!ExpandEnvironmentStrings(directories[i], expanded_dirs[i], OS_SIZE_1024)) {
            fail();
        }
        str_lowercase(expanded_dirs[i]);

        expect_string(wrap__stat64, __file, expanded_dirs[i]);
        will_return(wrap__stat64, &directory_stat);
        will_return(wrap__stat64, 0);

        expect_string(__wrap_HasFilesystem, path, expanded_dirs[i]);
        will_return(__wrap_HasFilesystem, 0);

        will_return(__wrap_readdir, NULL);
        will_return(__wrap_opendir, 1);
    }
    expect_string_count(__wrap_realtime_adddir, dir, "c:\\windows\\system32\\windowspowershell\\v1.0",1);
    will_return_maybe(__wrap_realtime_adddir, 0);

    will_return(__wrap_fim_db_get_count_file_entry, 1);
    will_return(__wrap_fim_db_get_count_file_entry, 1);
    will_return(__wrap_fim_db_get_count_registry_data, 1);
    will_return(__wrap_fim_db_get_count_registry_key, 1);

    snprintf(test_file_path, 160, "%s\\test_file", expanded_dirs[0]);

    expect_function_call(__wrap_fim_db_transaction_deleted_rows);
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);
    fim_scan();
}

static void test_fim_scan_db_full_not_double_scan(void **state) {
    char expanded_dirs[10][OS_SIZE_1024];
    char directories[6][OS_SIZE_256] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%",
        "%WINDIR%\\System32",
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
    };
    int i;
    struct stat buf = { .st_mode = S_IFDIR };
    TXN_HANDLE mock_handle;
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    will_return(__wrap_fim_db_transaction_start, &mock_handle);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    for(i = 0; i < 6; i++) {
        if(!ExpandEnvironmentStrings(directories[i], expanded_dirs[i], OS_SIZE_1024)) {
            fail();
        }
        str_lowercase(expanded_dirs[i]);

        expect_string(wrap__stat64, __file, expanded_dirs[i]);
        will_return(wrap__stat64, &buf);
        will_return(wrap__stat64, 0);
        expect_string(__wrap_HasFilesystem, path, expanded_dirs[i]);
        will_return(__wrap_HasFilesystem, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }

    expect_string_count(__wrap_realtime_adddir, dir, "c:\\windows\\system32\\windowspowershell\\v1.0",1);
    will_return_maybe(__wrap_realtime_adddir, 0);

    will_return(__wrap_fim_db_get_count_file_entry, 1);
    will_return(__wrap_fim_db_get_count_file_entry, 1);
    will_return(__wrap_fim_db_get_count_registry_data, 1);
    will_return(__wrap_fim_db_get_count_registry_key, 1);

    expect_function_call(__wrap_fim_db_transaction_deleted_rows);
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

static void test_fim_scan_no_limit(void **state) {
    char expanded_dirs[10][OS_SIZE_1024];
    char directories[6][OS_SIZE_256] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%",
        "%WINDIR%\\System32",
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
    };
    int i;
    struct stat buf = { .st_mode = S_IFDIR };
    TXN_HANDLE mock_handle;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    will_return(__wrap_fim_db_transaction_start, &mock_handle);
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    for(i = 0; i < 6; i++) {
        if(!ExpandEnvironmentStrings(directories[i], expanded_dirs[i], OS_SIZE_1024)) {
            fail();
        }
        str_lowercase(expanded_dirs[i]);

        expect_string(wrap__stat64, __file, expanded_dirs[i]);
        will_return(wrap__stat64, &buf);
        will_return(wrap__stat64, 0);
        expect_string(__wrap_HasFilesystem, path, expanded_dirs[i]);
        will_return(__wrap_HasFilesystem, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }
    expect_string_count(__wrap_realtime_adddir, dir, "c:\\windows\\system32\\windowspowershell\\v1.0",1);
    will_return_maybe(__wrap_realtime_adddir, 0);

    expect_function_call(__wrap_fim_db_transaction_deleted_rows);
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

#endif

static void test_fim_checker_unsupported_path(void **state) {
    const char * PATH = "Unsupported\xFF\x02";
    expect_string(__wrap__mwarn, formatted_msg, "(6955): Ignoring file 'Unsupported\xFF\x02' due to unsupported name (non-UTF8).");

    fim_checker(PATH, NULL, NULL, NULL, NULL);
}

/* fim_check_db_state */
static void test_fim_check_db_state_normal_to_empty(void **state) {

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state(syscheck.file_entry_limit, 0, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_empty(void **state) {
    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state(syscheck.file_entry_limit, 0, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_full(void **state) {
    expect_string(__wrap__mwarn, formatted_msg, "(6926): File database is 100% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state(syscheck.file_entry_limit, 50000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_empty(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6036): The file database status returns to normal.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":0,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state(syscheck.file_entry_limit, 0, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_90_percentage(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6040): File database is 90% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":46000,\"alert_type\":\"90_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state(syscheck.file_entry_limit, 46000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_empty(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6036): The file database status returns to normal.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":0,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 0, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_80_percentage(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6038): File database is 80% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":41000,\"alert_type\":\"80_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state(syscheck.file_entry_limit, 41000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_empty(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6036): The file database status returns to normal.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":0,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 0, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_normal(void **state) {
    assert_int_equal(_files_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state(syscheck.file_entry_limit, 10000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_normal_to_normal(void **state) {
    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state(syscheck.file_entry_limit, 20000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_normal_to_full(void **state) {
    expect_string(__wrap__mwarn, formatted_msg, "(6926): File database is 100% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state(syscheck.file_entry_limit, 50000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_normal(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6036): The file database status returns to normal.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":10000,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state(syscheck.file_entry_limit, 10000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_normal_to_90_percentage(void **state) {

    expect_string(__wrap__minfo, formatted_msg, "(6040): File database is 90% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":46000,\"alert_type\":\"90_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state(syscheck.file_entry_limit, 46000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_normal(void **state) {

    expect_string(__wrap__minfo, formatted_msg, "(6036): The file database status returns to normal.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":10000,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 10000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_normal_to_80_percentage(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6038): File database is 80% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":41000,\"alert_type\":\"80_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state(syscheck.file_entry_limit, 41000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_80_percentage(void **state) {
    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 42000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_full(void **state) {
    expect_string(__wrap__mwarn, formatted_msg, "(6926): File database is 100% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 50000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_80_percentage(void **state) {

    expect_string(__wrap__minfo, formatted_msg, "(6038): File database is 80% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":41000,\"alert_type\":\"80_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state(syscheck.file_entry_limit, 41000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_90_percentage(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6040): File database is 90% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":46000,\"alert_type\":\"90_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 46000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_90_percentage(void **state) {
    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 48000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_full(void **state) {
    expect_string(__wrap__mwarn, formatted_msg, "(6926): File database is 100% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 50000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_full(void **state) {
    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state(syscheck.file_entry_limit, 60000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_90_percentage(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6040): File database is 90% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":46000,\"alert_type\":\"90_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state(syscheck.file_entry_limit, 46000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_80_percentage(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6038): File database is 80% full.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":41000,\"alert_type\":\"80_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 41000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_normal(void **state) {
    expect_string(__wrap__minfo, formatted_msg, "(6036): The file database status returns to normal.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"fim_db_table\":\"file_entry\",\"file_limit\":50000,\"file_count\":10000,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_files_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state(syscheck.file_entry_limit, 10000, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_nodes_count_database_error(void **state) {
    expect_string(__wrap__mwarn, formatted_msg, "(6948): Unable to get the number of entries in database.");

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state(syscheck.file_entry_limit, -1, &_files_db_state, FIMDB_FILE_TABLE_NAME);

    assert_int_equal(_files_db_state, FIM_STATE_DB_NORMAL);
}

/* fim_directory */
static void test_fim_directory(void **state) {
    fim_data_t *fim_data = *state;
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true, .type = FIM_MODIFICATION };
    int ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    strcpy(fim_data->entry->d_name, "test");

    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);

#ifndef TEST_WINAGENT
    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'test/test'");
#else
    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'test\\test'");
#endif

    ret = fim_directory("test", &evt_data, NULL, NULL, NULL);

    assert_int_equal(ret, 0);
}

static void test_fim_directory_ignore(void **state) {
    fim_data_t *fim_data = *state;
    event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true, .type = FIM_MODIFICATION };
    int ret;

    strcpy(fim_data->entry->d_name, ".");

    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);

    ret = fim_directory(".", &evt_data, NULL, NULL, NULL);

    assert_int_equal(ret, 0);
}

static void test_fim_directory_nodir(void **state) {
    int ret;

    expect_string(__wrap__merror, formatted_msg, "(1105): Attempted to use null string.");

    ret = fim_directory(NULL, NULL, NULL, NULL, NULL);

    assert_int_equal(ret, OS_INVALID);
}

static void test_fim_directory_opendir_error(void **state) {
    int ret;

    will_return(__wrap_opendir, 0);

    expect_string(__wrap__mwarn, formatted_msg, "(6922): Cannot open 'test': Permission denied");

    errno = EACCES;

    ret = fim_directory("test", NULL, NULL, NULL, NULL);

    errno = 0;

    assert_int_equal(ret, OS_INVALID);
}

/* fim_get_data */
static void test_fim_get_data(void **state) {
    fim_data_t *fim_data = *state;
    directory_t configuration = { .options = CHECK_SIZE | CHECK_PERM | CHECK_MTIME | CHECK_OWNER | CHECK_GROUP |
                                             CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM };
    struct stat statbuf = { .st_mode = S_IFREG | 00444,
                            .st_size = 1000,
                            .st_uid = 0,
                            .st_gid = 0,
                            .st_ino = 1234,
                            .st_dev = 2345,
                            .st_mtime = 3456 };

    expect_get_data(strdup("user"), strdup("group"), "test", 1);
    fim_data->local_data = fim_get_data("test", &configuration, &statbuf);

#ifndef TEST_WINAGENT
    assert_string_equal(fim_data->local_data->perm, "r--r--r--");
#else
    assert_string_equal(fim_data->local_data->perm, "{}");
    assert_non_null(fim_data->local_data->perm_json);
#endif
    assert_string_equal(fim_data->local_data->hash_md5, "d41d8cd98f00b204e9800998ecf8427e");
    assert_string_equal(fim_data->local_data->hash_sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_string_equal(fim_data->local_data->hash_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_fim_get_data_no_hashes(void **state) {
    fim_data_t *fim_data = *state;
    directory_t configuration = { .options = CHECK_SIZE | CHECK_PERM | CHECK_MTIME | CHECK_OWNER | CHECK_GROUP };
    struct stat statbuf = { .st_mode = S_IFREG | 00444,
                            .st_size = 1000,
                            .st_uid = 0,
                            .st_gid = 0,
                            .st_ino = 1234,
                            .st_dev = 2345,
                            .st_mtime = 3456 };

    expect_get_data(strdup("user"), strdup("group"), "test", 0);

    fim_data->local_data = fim_get_data("test", &configuration, &statbuf);

#ifndef TEST_WINAGENT
    assert_string_equal(fim_data->local_data->perm, "r--r--r--");
#else
    assert_string_equal(fim_data->local_data->perm, "{}");
    assert_non_null(fim_data->local_data->perm_json);
#endif
    assert_string_equal(fim_data->local_data->hash_md5, "");
    assert_string_equal(fim_data->local_data->hash_sha1, "");
    assert_string_equal(fim_data->local_data->hash_sha256, "");
}

static void test_fim_get_data_hash_error(void **state) {
    fim_data_t *fim_data = *state;
    directory_t configuration = { .options = CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM | CHECK_MTIME |
                          CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP };
    struct stat statbuf = { .st_mode = S_IFREG | 00444,
                            .st_size = 1000,
                            .st_uid = 0,
                            .st_gid = 0,
                            .st_ino = 1234,
                            .st_dev = 2345,
                            .st_mtime = 3456 };

    expect_get_data(strdup("user"), strdup("group"), "test", 0);

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "test");
#ifndef TEST_WINAGENT
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, syscheck.prefilter_cmd);
#else
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, syscheck.prefilter_cmd);
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "(6324): Couldn't generate hashes for 'test'");

    fim_data->local_data = fim_get_data("test", &configuration, &statbuf);

    assert_null(fim_data->local_data);
}

#ifdef TEST_WINAGENT
static void test_fim_get_data_fail_to_get_file_premissions(void **state) {
    fim_data_t *fim_data = *state;
    directory_t configuration = { .options = CHECK_SIZE | CHECK_PERM | CHECK_MTIME | CHECK_OWNER | CHECK_GROUP |
                                             CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM };
    struct stat statbuf = DEFAULT_STATBUF;

    expect_string(__wrap__mdebug1, formatted_msg, "(6325): It was not possible to extract the permissions of 'test'. Error: 5");

    expect_string(__wrap_w_get_file_permissions, file_path, "test");
    will_return(__wrap_w_get_file_permissions, NULL);
    will_return(__wrap_w_get_file_permissions, ERROR_ACCESS_DENIED);


    fim_data->local_data = fim_get_data("test", &configuration, &statbuf);

    assert_null(fim_data->local_data);
}
#endif

static void test_fim_realtime_event_file_exists(void **state) {
    struct stat buf = { .st_mode = 0 };

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

#ifndef TEST_WINAGENT
    expect_string(__wrap_lstat, filename, "/test");
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, 0);
#else
    expect_string(wrap__stat64, __file, "/test");
    will_return(wrap__stat64, &buf);
    will_return(wrap__stat64, 0);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/test'");

    fim_realtime_event("/test");
}

static void test_fim_realtime_event_file_missing(void **state) {

    struct stat stat_buf = { .st_mode = 0 };
    char mdebug_msg[70];

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

#ifdef TEST_WINAGENT
    char *path = "C:\\a\\random\\path";
#else
    char *path = "/a/random/path";
#endif
    char buff[OS_SIZE_128] = {0};
    snprintf(buff, OS_SIZE_128, "%s%c%%", path, PATH_SEP);
    sprintf(mdebug_msg, FIM_CONFIGURATION_NOTFOUND, "file", path);
#ifndef TEST_WINAGENT
    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, &stat_buf);
    will_return(__wrap_lstat, -1);
#else
    expect_string(wrap__stat64, __file, path);
    will_return(wrap__stat64, &stat_buf);
    will_return(wrap__stat64, -1);
#endif
    errno = ENOENT;

    expect_string(__wrap__mdebug2, formatted_msg, mdebug_msg);

    fim_realtime_event(path);
    errno = 0;
}

static void test_fim_whodata_event_file_exists(void **state) {

    fim_data_t *fim_data = *state;
    struct stat buf = { .st_mode = 0 };

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

#ifndef TEST_WINAGENT
    expect_string(__wrap_lstat, filename, fim_data->w_evt->path);
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, 0);
#else
    expect_string(wrap__stat64, __file, fim_data->w_evt->path);
    will_return(wrap__stat64, &buf);
    will_return(wrap__stat64, 0);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'./test/test.file'");

    fim_whodata_event(fim_data->w_evt);
}

static void test_fim_whodata_event_file_missing(void **state) {
    fim_data_t *fim_data = *state;
    struct stat buf = { .st_mode = 0 };

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#ifndef TEST_WINAGENT
    expect_string(__wrap_lstat, filename, fim_data->w_evt->path);
    will_return(__wrap_lstat, &buf);
    will_return(__wrap_lstat, -1);
#else
    expect_string(wrap__stat64, __file, fim_data->w_evt->path);
    will_return(wrap__stat64, &buf);
    will_return(wrap__stat64, -1);
#endif
    errno = ENOENT;

#ifndef TEST_WINAGENT
    expect_fim_db_file_inode_search(606060, 12345678, FIMDB_OK);
#endif
    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'./test/test.file'");
    fim_whodata_event(fim_data->w_evt);
    errno = 0;
}

/* fim_process_missing_entry */

static void test_fim_process_missing_entry_null_configuration(void **state) {
#ifdef TEST_WINAGENT
    char *path = "C:\\a\\random\\path";
#else
    char *path = "/a/random/path";
#endif

    char buff[OS_SIZE_128] = {0};
    snprintf(buff, OS_SIZE_128, "%s%c%%", path, PATH_SEP);
    char debug_msg[70];
    sprintf(debug_msg,"(6319): No configuration found for (file):'%s'", path);

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    fim_process_missing_entry(path, FIM_REALTIME, NULL);
}

static void test_fim_process_missing_entry_data_exists(void **state) {
    fim_data_t *fim_data = (fim_data_t*) *state;
    free(fim_data->w_evt->path);
#ifdef TEST_WINAGENT
    char *aux_path = "%WINDIR%\\SysNative\\drivers\\etc";
    char path[OS_MAXSTR];

    if(!ExpandEnvironmentStrings(aux_path, path, OS_MAXSTR))
        fail();

    str_lowercase(path);
    fim_data->w_evt->path = strdup(path);
#else
    fim_data->w_evt->path = strdup("/media/test.txt");
#endif

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_string(__wrap_fim_db_get_path, file_path, fim_data->w_evt->path);
    will_return(__wrap_fim_db_get_path, FIMDB_OK);

    fim_process_missing_entry(fim_data->w_evt->path, FIM_WHODATA, fim_data->w_evt);
}

void test_fim_process_missing_entry_whodata_disabled(void **state){
    fim_data_t *fim_data = (fim_data_t*) *state;
    free(fim_data->w_evt->path);
#ifdef TEST_WINAGENT
    char *aux_path = "%WINDIR%\\SysNative\\drivers\\etc";
    char path[OS_MAXSTR];

    if(!ExpandEnvironmentStrings(aux_path, path, OS_MAXSTR))
        fail();

    str_lowercase(path);
    fim_data->w_evt->path = strdup(path);
#else
    fim_data->w_evt->path = strdup("/media/test.txt");
#endif

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_string(__wrap_fim_db_get_path, file_path, fim_data->w_evt->path);
    will_return(__wrap_fim_db_get_path, FIMDB_ERR);

    fim_process_missing_entry(fim_data->w_evt->path, FIM_WHODATA, fim_data->w_evt);
}

void test_fim_process_missing_entry(void **state){
    fim_data_t *fim_data = (fim_data_t*) *state;
    free(fim_data->w_evt->path);
#ifdef TEST_WINAGENT
    char *aux_path = "%WINDIR%\\SysNative\\drivers\\etc";
    char path[OS_MAXSTR];

    if(!ExpandEnvironmentStrings(aux_path, path, OS_MAXSTR))
        fail();

    str_lowercase(path);
    fim_data->w_evt->path = strdup(path);
#else
    fim_data->w_evt->path = strdup("/etc/test.txt");
#endif

    char pattern[PATH_MAX] = {0};
    snprintf(pattern, PATH_MAX, "%s%c%%", fim_data->w_evt->path, PATH_SEP);

#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_string(__wrap_fim_db_get_path, file_path, fim_data->w_evt->path);
    will_return(__wrap_fim_db_get_path, FIMDB_ERR);
    expect_string(__wrap_fim_db_file_pattern_search, pattern, pattern);
    will_return(__wrap_fim_db_file_pattern_search, FIMDB_OK);

    fim_process_missing_entry(fim_data->w_evt->path, FIM_SCHEDULED, fim_data->w_evt);
}

static void test_fim_process_wildcard_removed_no_data(void **state) {

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    directory_t *directory0 = OSList_GetFirstNode(removed_entries)->data;

    char buff[OS_SIZE_128] = {0};
    snprintf(buff, OS_SIZE_128, "%s%c%%", directory0->path, PATH_SEP);
    expect_string(__wrap_fim_db_file_pattern_search, pattern, buff);
    will_return(__wrap_fim_db_file_pattern_search, FIMDB_OK);

    expect_string(__wrap_fim_db_get_path, file_path, directory0->path);
    will_return(__wrap_fim_db_get_path, NULL);


    fim_process_wildcard_removed(directory0);
}

static void test_fim_process_wildcard_removed_failure(void **state) {
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->elements = 1;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    directory_t *directory0 = OSList_GetFirstNode(removed_entries)->data;

    char buff[OS_SIZE_128] = {0};

    snprintf(buff, OS_SIZE_128, "%s%c%%", directory0->path, PATH_SEP);
    expect_string(__wrap_fim_db_file_pattern_search, pattern, buff);
    will_return(__wrap_fim_db_file_pattern_search, FIMDB_OK);
    expect_string(__wrap_fim_db_get_path, file_path, directory0->path);
    will_return(__wrap_fim_db_get_path, NULL);

    fim_process_wildcard_removed(directory0);

    free(file);
}

static void test_fim_process_wildcard_removed_data_exists(void **state) {

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    fim_data_t *fim_data = *state;
    directory_t *directory0 = OSList_GetFirstNode(removed_entries)->data;

    fim_data->fentry->file_entry.path = strdup("file");
    fim_data->fentry->file_entry.data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");
    char pattern[100];
    snprintf(pattern, PATH_MAX, "%s%c%%", directory0->path, PATH_SEP);
    expect_string(__wrap_fim_db_file_pattern_search, pattern, pattern);
    will_return(__wrap_fim_db_file_pattern_search, FIMDB_OK);
    expect_string(__wrap_fim_db_get_path, file_path, directory0->path);
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

    fim_process_wildcard_removed(directory0);
}

void test_fim_diff_folder_size(void **state) {
    (void) state;
    char *diff_local;

    diff_local = (char *)calloc(strlen(DIFF_DIR) + strlen("/local") + 1, sizeof(char));

    snprintf(diff_local, strlen(DIFF_DIR) + strlen("/local") + 1, "%s/local", DIFF_DIR);

    expect_string(__wrap_IsDir, file, diff_local);
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, diff_local);
    will_return(__wrap_DirSize, 20 * 1024);

    fim_diff_folder_size();

    assert_int_equal(syscheck.diff_folder_size, 20);

    if (diff_local) {
        free(diff_local);
    }
}

static void test_update_wildcards_config() {
    char **paths;
#ifndef TEST_WINAGENT
    char wildcard1[20] = "/testdir?";
    char wildcard2[20] = "/*/path";
    char resolvedpath1[20] = "/testdir1";
    char resolvedpath2[20] = "/testdir2";
#else
    char wildcard1[20] = "c:\\testdir?";
    char wildcard2[20] = "c:\\*\\path";
    char resolvedpath1[20] = "c:\\testdir1";
    char resolvedpath2[20] = "c:\\testdir2";
#endif
    os_calloc(3, sizeof(char *), paths);
    os_strdup(resolvedpath1, paths[0]);
    os_strdup(resolvedpath2, paths[1]);

    expect_string(__wrap__mdebug2, formatted_msg, FIM_WILDCARDS_UPDATE_START);
    expect_string(__wrap__mdebug2, formatted_msg, FIM_WILDCARDS_UPDATE_FINALIZE);

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap_expand_wildcards, path, wildcard1);
    will_return(__wrap_expand_wildcards, paths);
    expect_string(__wrap_expand_wildcards, path, wildcard2);
    will_return(__wrap_expand_wildcards, NULL);

#ifndef WIN32
    expect_string_count(__wrap_realpath, path, wildcard1, 2);
    will_return_count(__wrap_realpath, NULL, 2);
#endif

    update_wildcards_config();

    // Filled config
    directory_t *directory0 = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 0);
    assert_string_equal(directory0->path, resolvedpath1);
    directory_t *directory1 = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);
    assert_string_equal(directory1->path, resolvedpath2);
}

static void test_update_wildcards_config_remove_config() {
#ifndef TEST_WINAGENT
    char wildcard1[20] = "/testdir?";
    char wildcard2[20] = "/*/path";
    char resolvedpath1[20] = "/testdir1";
    char resolvedpath2[20] = "/testdir2";
    char pattern1[20] = "/testdir1/%";
    char pattern2[20] = "/testdir2/%";
#else
    char wildcard1[20] = "c:\\testdir?";
    char wildcard2[20] = "c:\\*\\path";
    char resolvedpath1[20] = "c:\\testdir1";
    char resolvedpath2[20] = "c:\\testdir2";
    char pattern1[20] = "c:\\testdir1\\%";
    char pattern2[20] = "c:\\testdir2\\%";
#endif

    char error_msg[OS_MAXSTR];
    char error_msg2[OS_MAXSTR];

    snprintf(error_msg, OS_MAXSTR, FIM_WILDCARDS_REMOVE_DIRECTORY, resolvedpath1);
    snprintf(error_msg2, OS_MAXSTR, FIM_WILDCARDS_REMOVE_DIRECTORY, resolvedpath2);

    expect_string(__wrap__mdebug2, formatted_msg, FIM_WILDCARDS_UPDATE_START);
    expect_string(__wrap__mdebug2, formatted_msg, error_msg2);
    expect_string(__wrap__mdebug2, formatted_msg, error_msg);
    expect_string(__wrap__mdebug2, formatted_msg, FIM_WILDCARDS_UPDATE_FINALIZE);

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_expand_wildcards, path, wildcard1);
    will_return(__wrap_expand_wildcards, NULL);
    expect_string(__wrap_expand_wildcards, path, wildcard2);
    will_return(__wrap_expand_wildcards, NULL);
#ifndef TEST_WINAGENT
    expect_string(__wrap_remove_audit_rule_syscheck, path, resolvedpath1);
    expect_string(__wrap_remove_audit_rule_syscheck, path, resolvedpath2);

#endif

    // Remove configuration loop
    expect_string(__wrap_fim_db_get_path, file_path, resolvedpath2);
    will_return(__wrap_fim_db_get_path, NULL);

    expect_string(__wrap_fim_db_get_path, file_path, resolvedpath1);
    will_return(__wrap_fim_db_get_path, NULL);

    expect_string(__wrap_fim_db_file_pattern_search, pattern, pattern2);
    will_return(__wrap_fim_db_file_pattern_search, 0);

    expect_string(__wrap_fim_db_file_pattern_search, pattern, pattern1);
    will_return(__wrap_fim_db_file_pattern_search, 0);
    update_wildcards_config();

    // Empty config
    directory_t *directory0 = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 0);
    assert_null(directory0);
}

static void test_update_wildcards_config_list_null() {
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    if (syscheck.wildcards) {
        OSList_Destroy(syscheck.wildcards);
        syscheck.wildcards = NULL;
    }
    update_wildcards_config();
}

static void test_transaction_callback_add(void **state) {
    txn_data_t *data = (txn_data_t *) *state;
#ifndef TEST_WINAGENT
    char *path = "/etc/a_test_file.txt";
#else
    char *path = "c:\\windows\\a_test_file.txt";
#endif

    fim_txn_context_t *txn_context = data->txn_context;
    fim_entry entry = {.type = FIM_TYPE_FILE, .file_entry.path = path, .file_entry.data=&DEFAULT_FILE_DATA};
    cJSON *result = cJSON_Parse("[{\"attributes\":\"\",\"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\",\"dev\":64768,\"gid\":0,\"group_name\":\"root\",\"hash_md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"hash_sha1\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"hash_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"inode\":801978,\"last_event\":0,\"mode\":0,\"mtime\":1645001030,\"options\":139775,\"path\":\"/etc/a_test_file.txt\",\"perm\":\"rw-r--r--\",\"scanned\":1,\"size\":0,\"uid\":0,\"user_name\":\"root\"}]");

    txn_context->latest_entry = &entry;
    data->dbsync_event = result;

#ifndef TEST_WINAGENT // The order of the functions is different between windows an linux
    // These functions are called every time transaction_callback calls fim_configuration_directory
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_function_call(__wrap_send_syscheck_msg);

    transaction_callback(INSERTED, result, txn_context);
    assert_int_equal(txn_context->evt_data->type, FIM_ADD);

    data->txn_context->latest_entry = NULL;
}

static void test_transaction_callback_modify(void **state) {
    txn_data_t *data = (txn_data_t *) *state;
#ifndef TEST_WINAGENT
    char *path = "/etc/a_test_file.txt";
#else
    char *path = "c:\\windows\\a_test_file.txt";
#endif
    fim_txn_context_t *txn_context = data->txn_context;
    fim_entry entry = {.type = FIM_TYPE_FILE, .file_entry.path = path, .file_entry.data=&DEFAULT_FILE_DATA};
    txn_context->latest_entry = &entry;

    cJSON *result = cJSON_Parse("[{\"new\":{\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\",\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"mtime\":1645001693,\"path\":\"/etc/a_test_file.txt\",\"size\":11},\"old\":{\"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\",\"hash_md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"hash_sha1\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"hash_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"mtime\":1645001030,\"path\":\"/etc/a_test_file.txt\",\"size\":0}}]");
    data->dbsync_event = result;

    // These functions are called every time transaction_callback calls fim_configuration_directory
#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_function_call(__wrap_send_syscheck_msg);

    transaction_callback(MODIFIED, result, txn_context);
    assert_int_equal(txn_context->evt_data->type, FIM_MODIFICATION);

    data->txn_context->latest_entry = NULL;
}

static void test_transaction_callback_modify_empty_changed_attributes(void **state) {
    txn_data_t *data = (txn_data_t *) *state;
#ifndef TEST_WINAGENT
    char *path = "/etc/a_test_file.txt";
#else
    char *path = "c:\\windows\\a_test_file.txt";
#endif
    fim_txn_context_t *txn_context = data->txn_context;
    fim_entry entry = {.type = FIM_TYPE_FILE, .file_entry.path = path, .file_entry.data=&DEFAULT_FILE_DATA};
    txn_context->latest_entry = &entry;

    cJSON *result = cJSON_Parse("{\"new\":{\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\",\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"mtime\":1645001693,\"path\":\"/etc/a_test_file.txt\",\"size\":11},\"old\":{\"path\":\"/etc/a_test_file.txt\"}}");
    data->dbsync_event = result;

    // These functions are called every time transaction_callback calls fim_configuration_directory
#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

#ifndef TEST_WINAGENT
    expect_string(__wrap__mdebug2, formatted_msg, "(6954): Entry '/etc/a_test_file.txt' does not have any modified fields. No event will be generated.");
#else
    expect_string(__wrap__mdebug2, formatted_msg, "(6954): Entry 'c:\\windows\\a_test_file.txt' does not have any modified fields. No event will be generated.");
#endif
    transaction_callback(MODIFIED, result, txn_context);
    assert_int_equal(txn_context->evt_data->type, FIM_MODIFICATION);

    data->txn_context->latest_entry = NULL;
}

static void test_transaction_callback_modify_report_changes(void **state) {
    txn_data_t *data = (txn_data_t *) *state;
#ifndef TEST_WINAGENT
    char *path = "/etc/a_test_file.txt";
#else
    char *path = "c:\\windows\\a_test_file.txt";
#endif
    fim_txn_context_t *txn_context = data->txn_context;
    fim_entry entry = {.type = FIM_TYPE_FILE, .file_entry.path = path, .file_entry.data=&DEFAULT_FILE_DATA};
    txn_context->latest_entry = &entry;


    cJSON *result = cJSON_Parse("[{\"new\":{\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\",\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"mtime\":1645001693,\"path\":\"/etc/a_test_file.txt\",\"size\":11},\"old\":{\"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\",\"hash_md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"hash_sha1\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"hash_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"mtime\":1645001030,\"path\":\"/etc/a_test_file.txt\",\"size\":0}}]");
    data->dbsync_event = result;

    // These functions are called every time transaction_callback calls fim_configuration_directory
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1))->options |= CHECK_SEECHANGES;

    expect_fim_file_diff(entry.file_entry.path, strdup("diff"));

    expect_function_call(__wrap_send_syscheck_msg);

    transaction_callback(MODIFIED, result, txn_context);
    assert_int_equal(txn_context->evt_data->type, FIM_MODIFICATION);

    data->txn_context->latest_entry = NULL;

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1))->options &= ~CHECK_SEECHANGES;
}

static void test_transaction_callback_delete(void **state) {
    txn_data_t *data = (txn_data_t *) *state;
#ifndef TEST_WINAGENT
    cJSON *result = cJSON_Parse("{\"path\":\"/etc/a_test_file.txt\",\"size\":11,\"last_event\":123456789,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":801978,\"mtime\":1645001693,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\"}");
#else
    cJSON *result = cJSON_Parse("{\"path\":\"c:\\\\windows\\\\a_test_file.txt\",\"size\":11,\"last_event\":123456789,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":801978,\"mtime\":1645001693,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\"}");
#endif

    fim_txn_context_t *txn_context = data->txn_context;
    data->dbsync_event = result;

    // These functions are called every time transaction_callback calls fim_configuration_directory
#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_function_call(__wrap_send_syscheck_msg);

    transaction_callback(DELETED, result, txn_context);
    assert_int_equal(txn_context->evt_data->type, FIM_DELETE);
}

static void test_transaction_callback_delete_report_changes(void **state) {
    txn_data_t *data = (txn_data_t *) *state;

    fim_txn_context_t *txn_context = data->txn_context;
#ifndef TEST_WINAGENT
    const char* path = "/etc/a_test_file.txt";
    cJSON *result = cJSON_Parse("{\"path\":\"/etc/a_test_file.txt\",\"size\":11,\"last_event\":123456789,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":801978,\"mtime\":1645001693,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\"}");
#else
    const char *path = "c:\\windows\\a_test_file.txt";
    cJSON *result = cJSON_Parse("{\"path\":\"c:\\\\windows\\\\a_test_file.txt\",\"size\":11,\"last_event\":123456789,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":801978,\"mtime\":1645001693,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\"}");
#endif
    data->dbsync_event = result;

    // These functions are called every time transaction_callback calls fim_configuration_directory
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1))->options |= CHECK_SEECHANGES;


    expect_fim_diff_process_delete_file(path, 0);

    expect_function_call(__wrap_send_syscheck_msg);

    transaction_callback(DELETED, result, txn_context);
    assert_int_equal(txn_context->evt_data->type, FIM_DELETE);

    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1))->options &= ~CHECK_SEECHANGES;
}

static void test_transaction_callback_delete_full_db(void **state) {
    txn_data_t *data = (txn_data_t *) *state;
#ifndef TEST_WINAGENT
    cJSON *result = cJSON_Parse("{\"path\":\"/etc/a_test_file.txt\",\"size\":11,\"last_event\":123456789,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":801978,\"mtime\":1645001693,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\"}");
#else
    cJSON *result = cJSON_Parse("{\"path\":\"c:\\\\windows\\\\a_test_file.txt\",\"size\":11,\"last_event\":123456789,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":801978,\"mtime\":1645001693,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\"}");
#endif

    fim_txn_context_t *txn_context = data->txn_context;
    data->dbsync_event = result;

    // These functions are called every time transaction_callback calls fim_configuration_directory
#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    expect_function_call(__wrap_send_syscheck_msg);

    transaction_callback(DELETED, result, txn_context);
    assert_int_equal(txn_context->evt_data->type, FIM_DELETE);
}

static void test_transaction_callback_full_db(void **state) {
    txn_data_t *data = (txn_data_t *) *state;
#ifndef TEST_WINAGENT
    char* path = "/etc/a_test_file.txt";
    cJSON *result = cJSON_Parse("{\"path\":\"/etc/a_test_file.txt\",\"size\":11,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":801978,\"mtime\":1645001693,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\"}");
#else
    char *path = "c:\\windows\\a_test_file.txt";
    cJSON *result = cJSON_Parse("{\"path\":\"c:\\\\windows\\\\a_test_file.txt\",\"size\":11,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":801978,\"mtime\":1645001693,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"cfdd740677ed8b250e93081e72b4d97b1c846fdc\"}");
#endif
    char debug_msg[OS_SIZE_128] = {0};

    fim_txn_context_t *txn_context = data->txn_context;
    fim_entry entry = {.type = FIM_TYPE_FILE, .file_entry.path = path, .file_entry.data=&DEFAULT_FILE_DATA};

    txn_context->latest_entry = &entry;
    data->dbsync_event = result;

    // These functions are called every time transaction_callback calls fim_configuration_directory
#ifndef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
#else
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    snprintf(debug_msg, OS_SIZE_128, "Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", path);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    transaction_callback(MAX_ROWS, result, txn_context);
}

static void test_fim_event_callback(void **state) {
    whodata_evt w_event = {.user_name = "audit_user_name" };
    event_data_t evt_data = { .report_event = true, .w_evt = &w_event };
    directory_t configuration = { .options = -1, .tag = "tag_name" };
    create_json_event_ctx callback_ctx = { .event = &evt_data, .config = &configuration };

    cJSON* json_event = cJSON_CreateObject();
    cJSON* data = cJSON_CreateObject();

    cJSON_AddStringToObject(data, "path", "/path/to/file");
    cJSON_AddItemToObject(json_event, "data", data);

    expect_fim_file_diff("/path/to/file", strdup("diff"));

    expect_function_call(__wrap_send_syscheck_msg);

    fim_event_callback(json_event, &callback_ctx);
#ifndef TEST_WINAGENT
    char* test_event = "{\"data\":{\"path\":\"/path/to/file\",\"audit\":{\"user_name\":\"audit_user_name\",\"process_id\":0,\"ppid\":0},\"tags\":\"tag_name\"}}";
#else
    char* test_event = "{\"data\":{\"path\":\"/path/to/file\",\"audit\":{\"user_name\":\"audit_user_name\",\"process_id\":0},\"tags\":\"tag_name\"}}";
#endif
    char* string_event = cJSON_PrintUnformatted(json_event);
    assert_string_equal(string_event, test_event);

    os_free(string_event);
    cJSON_Delete(json_event);
}

static void test_fim_event_callback_empty_changed_attributes(void **state) {
    whodata_evt w_event = {.user_name = "audit_user_name" };
    event_data_t evt_data = { .report_event = true, .w_evt = &w_event };
    directory_t configuration = { .options = -1, .tag = "tag_name" };
    create_json_event_ctx callback_ctx = { .event = &evt_data, .config = &configuration };

    cJSON* json_event = cJSON_CreateObject();
    cJSON* data = cJSON_CreateObject();

    cJSON_AddStringToObject(data, "path", "/path/to/file");
    cJSON_AddArrayToObject(data, "changed_attributes");
    cJSON_AddItemToObject(json_event, "data", data);

    expect_string(__wrap__mdebug2, formatted_msg, "(6954): Entry '/path/to/file' does not have any modified fields. No event will be generated.");

    fim_event_callback(json_event, &callback_ctx);

    char* test_event = "{\"data\":{\"path\":\"/path/to/file\",\"changed_attributes\":[]}}";
    char* string_event = cJSON_PrintUnformatted(json_event);
    assert_string_equal(string_event, test_event);

    os_free(string_event);
    cJSON_Delete(json_event);
}

void test_fim_calculate_dbsync_difference_no_attributes(void **state){

    cJSON* output = fim_calculate_dbsync_difference(NULL,
                                        NULL,
                                        NULL,
                                        NULL);
    assert_null(output);
}

/* fim_calculate_dbsync_difference */
void test_fim_calculate_dbsync_difference(void **state){

    #ifndef TEST_WINAGENT
        char* changed_data = "{\"size\":0, \"perm\":\"rw-rw-r--\", \"attributes\":\"NULL\", \"uid\":\"1000\", \"gid\":\"1000\", \
        \"user_name\":\"root\", \"group_name\":\"root\", \"mtime\":123456789, \"inode\":1, \"hash_md5\":\"0123456789abcdef0123456789abcdef\", \
        \"hash_sha1\":\"0123456789abcdef0123456789abcdef01234567\", \"hash_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \
        \"checksum\":\"0123456789abcdef0123456789abcdef01234567\" }";
    #else
        DEFAULT_FILE_DATA.options |= CHECK_ATTRS;
        char* changed_data = "{\"size\":0, \"perm\":\"{\\\"S-1-5-32-544\\\":{\\\"name\\\":\\\"Administrators\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"synchronize\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\",\\\"read_attributes\\\",\\\"write_attributes\\\"]},\\\"S-1-5-18\\\":{\\\"name\\\":\\\"SYSTEM\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"synchronize\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\",\\\"read_attributes\\\",\\\"write_attributes\\\"]},\\\"S-1-5-32-545\\\":{\\\"name\\\":\\\"Users\\\",\\\"allowed\\\":[\\\"read_control\\\",\\\"synchronize\\\",\\\"read_data\\\",\\\"read_ea\\\",\\\"execute\\\",\\\"read_attributes\\\"]},\\\"S-1-5-11\\\":{\\\"name\\\":\\\"Authenticated Users\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"synchronize\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\",\\\"read_attributes\\\",\\\"write_attributes\\\"]}}\", \"attributes\":\"NULL\", \"uid\":\"1000\", \"gid\":\"1000\", \
        \"user_name\":\"root\", \"group_name\":\"root\", \"mtime\":123456789, \"inode\":1, \"hash_md5\":\"0123456789abcdef0123456789abcdef\", \
        \"hash_sha1\":\"0123456789abcdef0123456789abcdef01234567\", \"hash_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \
        \"checksum\":\"0123456789abcdef0123456789abcdef01234567\" }";
    #endif

    cJSON* changed_data_json = cJSON_Parse(changed_data);
    cJSON* old_attributes = cJSON_CreateObject();
    cJSON* changed_attributes = cJSON_CreateArray();

    fim_calculate_dbsync_difference(&DEFAULT_FILE_DATA,
                                        changed_data_json,
                                        old_attributes,
                                        changed_attributes);

    #ifdef TEST_WINAGENT
        DEFAULT_FILE_DATA.options &= ~CHECK_ATTRS;
    #endif

    assert_int_equal(cJSON_GetObjectItem(old_attributes, "size")->valueint, 0);
    #ifdef TEST_WINAGENT
    assert_string_equal(cJSON_PrintUnformatted(cJSON_GetObjectItem(old_attributes, "perm")), "{\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]},\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"synchronize\",\"read_data\",\"read_ea\",\"execute\",\"read_attributes\"]},\"S-1-5-11\":{\"name\":\"Authenticated Users\",\"allowed\":[\"delete\",\"read_control\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]}}");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "attributes")->valuestring, "NULL");
    #else
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "perm")->valuestring, "rw-rw-r--");
    #endif

    assert_string_equal(cJSON_GetObjectItem(old_attributes, "uid")->valuestring, "1000");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "gid")->valuestring, "1000");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "user_name")->valuestring, "root");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "group_name")->valuestring, "root");
    assert_int_equal(cJSON_GetObjectItem(old_attributes, "mtime")->valueint, 123456789);
    assert_int_equal(cJSON_GetObjectItem(old_attributes, "inode")->valueint, 1);
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "hash_md5")->valuestring, "0123456789abcdef0123456789abcdef");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "hash_sha1")->valuestring, "0123456789abcdef0123456789abcdef01234567");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "hash_sha256")->valuestring, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "checksum")->valuestring, "0123456789abcdef0123456789abcdef01234567");
    cJSON_Delete(changed_data_json);
    cJSON_Delete(old_attributes);
    cJSON_Delete(changed_attributes);

}

void test_fim_calculate_dbsync_difference_no_changed_data(void **state){

    cJSON* changed_data_json = NULL;
    cJSON* old_attributes = cJSON_CreateObject();
    cJSON* changed_attributes = cJSON_CreateArray();

#ifdef TEST_WINAGENT
    DEFAULT_FILE_DATA.attributes = "NULL";
    DEFAULT_FILE_DATA.options |= CHECK_ATTRS;
#endif

    fim_calculate_dbsync_difference(&DEFAULT_FILE_DATA,
                                        changed_data_json,
                                        old_attributes,
                                        changed_attributes);
#ifdef TEST_WINAGENT
    DEFAULT_FILE_DATA.options &= ~CHECK_ATTRS;
#endif
    assert_int_equal(cJSON_GetObjectItem(old_attributes, "size")->valueint, 0);
#ifndef TEST_WINAGENT
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "perm")->valuestring, "rw-rw-r--");
#else
    assert_string_equal(cJSON_PrintUnformatted(cJSON_GetObjectItem(old_attributes, "perm")), "{\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]},\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"synchronize\",\"read_data\",\"read_ea\",\"execute\",\"read_attributes\"]},\"S-1-5-11\":{\"name\":\"Authenticated Users\",\"allowed\":[\"delete\",\"read_control\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]}}");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "attributes")->valuestring, "NULL");
#endif

    assert_string_equal(cJSON_GetObjectItem(old_attributes, "uid")->valuestring, "1000");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "gid")->valuestring, "1000");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "user_name")->valuestring, "root");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "group_name")->valuestring, "root");
    assert_int_equal(cJSON_GetObjectItem(old_attributes, "mtime")->valueint, 123456789);
    assert_int_equal(cJSON_GetObjectItem(old_attributes, "inode")->valueint, 1);
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "hash_md5")->valuestring, "0123456789abcdef0123456789abcdef");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "hash_sha1")->valuestring, "0123456789abcdef0123456789abcdef01234567");
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "hash_sha256")->valuestring, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
#ifdef TEST_WINAGENT
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "checksum")->valuestring, "6ec831114b5d930f19a90d7c34996e0fce4e7b84");
#else
    assert_string_equal(cJSON_GetObjectItem(old_attributes, "checksum")->valuestring, "98e039efc1b8490965e7e1247a9dc31cf7379051");
#endif
    cJSON_Delete(old_attributes);
    cJSON_Delete(changed_attributes);
}

void test_process_delete_event(void **state){
    fim_data_t* entry = (fim_data_t*) *state;
    directory_t config;
    config.tag = "tag";
    event_data_t evt;
    evt.w_evt = NULL;
    evt.mode = FIM_SCHEDULED;
    evt.type = FIM_ADD;
    evt.report_event = 1;
    get_data_ctx ctx_data;
    ctx_data.config = &config;
    ctx_data.event = &evt;
    entry->fentry->file_entry.path = "path";
    expect_string(__wrap_fim_db_remove_path, path, entry->fentry->file_entry.path);
    will_return(__wrap_fim_db_remove_path, 0);

    expect_function_call(__wrap_send_syscheck_msg);

    process_delete_event(entry->fentry, &ctx_data);
    entry->fentry->file_entry.path = NULL;
}

void test_create_windows_who_data_events(void **state){
    fim_data_t* fim_data = (fim_data_t*) *state;
    char *path = fim_data->w_evt->path;

    #ifndef TEST_WINAGENT
        expect_function_call_any(__wrap_pthread_rwlock_wrlock);
        expect_function_call_any(__wrap_pthread_rwlock_unlock);
        expect_function_call_any(__wrap_pthread_mutex_lock);
        expect_function_call_any(__wrap_pthread_mutex_unlock);
        expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    #else
        expect_function_call_any(__wrap_pthread_rwlock_wrlock);
        expect_function_call_any(__wrap_pthread_rwlock_unlock);
        expect_function_call_any(__wrap_pthread_rwlock_rdlock);
        expect_function_call_any(__wrap_pthread_mutex_lock);
        expect_function_call_any(__wrap_pthread_mutex_unlock);
    #endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'./test/test.file'");
    create_windows_who_data_events(path, fim_data->w_evt);
}

void test_fim_db_remove_entry(void **state){
    fim_data_t* fim_data = (fim_data_t*) *state;
    char *path = fim_data->w_evt->path;
    directory_t config;
    config.options = CHECK_SEECHANGES;
    get_data_ctx get_data;
    get_data.config = &config;

    expect_string(__wrap_fim_db_get_path, file_path, path);
    will_return(__wrap_fim_db_get_path, FIMDB_OK);
    expect_string(__wrap_fim_diff_process_delete_file, filename, path);
    will_return(__wrap_fim_diff_process_delete_file, 0);
    fim_db_remove_entry(path, &get_data);
}

void test_fim_db_process_missing_entry(void **state){
    fim_data_t* fim_data = (fim_data_t*) *state;
    fim_data->fentry->file_entry.path = "mock_path";
    directory_t config;
    get_data_ctx get_data;
    get_data.config = &config;

    #ifndef TEST_WINAGENT
        expect_function_call_any(__wrap_pthread_rwlock_wrlock);
        expect_function_call_any(__wrap_pthread_rwlock_unlock);
        expect_function_call_any(__wrap_pthread_mutex_lock);
        expect_function_call_any(__wrap_pthread_mutex_unlock);
        expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    #else
        expect_function_call_any(__wrap_pthread_rwlock_wrlock);
        expect_function_call_any(__wrap_pthread_rwlock_unlock);
        expect_function_call_any(__wrap_pthread_rwlock_rdlock);
        expect_function_call_any(__wrap_pthread_mutex_lock);
        expect_function_call_any(__wrap_pthread_mutex_unlock);
    #endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'mock_path'");

    fim_db_process_missing_entry(fim_data->fentry, &get_data);
    fim_data->fentry->file_entry.path = NULL;
}

static void test_dbsync_attributes_json(void **state) {
    directory_t configuration = { .options = -1, .tag = "tag_name" };
    json_struct_t *data = *state;
#ifndef TEST_WINAGENT
    const char *result_str = "{\"type\":\"file\",\"size\":11,\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"group_name\":\"root\",\"inode\":271017,\"mtime\":1646124392,\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"checksum\":\"c0edc82c463da5f4ab8dd420a778a9688a923a72\"}";
    cJSON *dbsync_event = cJSON_Parse("{\"attributes\":\"\",\"checksum\":\"c0edc82c463da5f4ab8dd420a778a9688a923a72\",\"dev\":64768,\"gid\":\"0\",\"group_name\":\"root\",\"hash_md5\":\"d73b04b0e696b0945283defa3eee4538\",\"hash_sha1\":\"e7509a8c032f3bc2a8df1df476f8ef03436185fa\",\"hash_sha256\":\"8cd07f3a5ff98f2a78cfc366c13fb123eb8d29c1ca37c79df190425d5b9e424d\",\"inode\":271017,\"last_event\":1646124394,\"mode\":0,\"mtime\":1646124392,\"options\":131583,\"path\":\"/etc/testfile\",\"perm\":\"rw-r--r--\",\"scanned\":1,\"size\":11,\"uid\":\"0\",\"user_name\":\"root\"}");
#else
    cJSON *dbsync_event = cJSON_Parse("{\"size\":0, \"perm\":\"{\\\"S-1-5-32-544\\\":{\\\"name\\\":\\\"Administrators\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"synchronize\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\",\\\"read_attributes\\\",\\\"write_attributes\\\"]},\\\"S-1-5-18\\\":{\\\"name\\\":\\\"SYSTEM\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"synchronize\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\",\\\"read_attributes\\\",\\\"write_attributes\\\"]},\\\"S-1-5-32-545\\\":{\\\"name\\\":\\\"Users\\\",\\\"allowed\\\":[\\\"read_control\\\",\\\"synchronize\\\",\\\"read_data\\\",\\\"read_ea\\\",\\\"execute\\\",\\\"read_attributes\\\"]},\\\"S-1-5-11\\\":{\\\"name\\\":\\\"Authenticated Users\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"synchronize\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\",\\\"read_attributes\\\",\\\"write_attributes\\\"]}}\", \"attributes\":\"ARCHIVE\", \"uid\":\"0\", \"gid\":\"0\", \
        \"user_name\":\"Administrators\", \"group_name\":\"\", \"mtime\":1646145212, \"inode\":0, \"hash_md5\":\"d41d8cd98f00b204e9800998ecf8427e\", \
        \"hash_sha1\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\", \"hash_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\", \
        \"checksum\":\"ac962fef86e12e656b882fc88170fff24bf10a77\" }");

    char *result_str = "{\"type\":\"file\",\"size\":0,\"perm\":{\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]},\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"synchronize\",\"read_data\",\"read_ea\",\"execute\",\"read_attributes\"]},\"S-1-5-11\":{\"name\":\"Authenticated Users\",\"allowed\":[\"delete\",\"read_control\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"]}},\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"Administrators\",\"inode\":0,\"mtime\":1646145212,\"hash_md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"hash_sha1\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"hash_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"attributes\":\"ARCHIVE\",\"checksum\":\"ac962fef86e12e656b882fc88170fff24bf10a77\"}";
#endif
    cJSON *attributes = cJSON_CreateObject();

    data->json1 = dbsync_event;
    data->json2 = attributes;

    dbsync_attributes_json(dbsync_event, &configuration, attributes);
    char * json_attributes_str = cJSON_PrintUnformatted(attributes);

    assert_string_equal(json_attributes_str, result_str);
    free(json_attributes_str);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_json_event */
        cmocka_unit_test_teardown(test_fim_json_event, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_whodata, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_no_changes, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_hardlink_one_path, teardown_delete_json),

        /* fim_attributes_json */
        cmocka_unit_test_teardown(test_fim_attributes_json, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_attributes_json_without_options, teardown_delete_json),

        /* fim_json_compare_attrs */
        cmocka_unit_test_teardown(test_fim_json_compare_attrs, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_compare_attrs_without_options, teardown_delete_json),

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
        cmocka_unit_test(test_fim_get_checksum),
        cmocka_unit_test_teardown(test_fim_get_checksum_wrong_size, teardown_local_data),

        /* fim_check_depth */
        cmocka_unit_test(test_fim_check_depth_success),
        cmocka_unit_test(test_fim_check_depth_failure_strlen),
        cmocka_unit_test(test_fim_check_depth_failure_null_directory),

        /* fim_configuration_directory */
        cmocka_unit_test(test_fim_configuration_directory_no_path),
        cmocka_unit_test(test_fim_configuration_directory_file),
        cmocka_unit_test(test_fim_configuration_directory_not_found),

        /* init_fim_data_entry */
        cmocka_unit_test(test_init_fim_data_entry),

        /* fim_file */
        cmocka_unit_test(test_fim_file_add),
        cmocka_unit_test_setup_teardown(test_fim_file_modify, setup_fim_entry, teardown_fim_entry),
        cmocka_unit_test_setup_teardown(test_fim_file_modify_transaction, setup_fim_entry, teardown_fim_entry),

        cmocka_unit_test(test_fim_file_no_attributes),
        cmocka_unit_test_setup_teardown(test_fim_file_error_on_insert, setup_fim_entry, teardown_fim_entry),

        /* fim_scan */
        cmocka_unit_test_setup_teardown(test_fim_scan_db_full_double_scan, setup_fim_double_scan,
                                        teardown_fim_double_scan),
        cmocka_unit_test_setup_teardown(test_fim_scan_db_full_not_double_scan, setup_fim_not_double_scan,
                                        teardown_fim_not_double_scan),
        cmocka_unit_test_setup_teardown(test_fim_scan_no_limit, setup_file_limit, teardown_file_limit),

        /* fim_check_db_state */
        cmocka_unit_test(test_fim_check_db_state_normal_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_normal),
        cmocka_unit_test(test_fim_check_db_state_normal_to_normal),
        cmocka_unit_test(test_fim_check_db_state_normal_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_normal),
        cmocka_unit_test(test_fim_check_db_state_normal_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_normal),
        cmocka_unit_test(test_fim_check_db_state_normal_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_normal),
        cmocka_unit_test(test_fim_check_db_state_nodes_count_database_error),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_fim_scan_realtime_enabled, setup_fim_scan_realtime,
                                        teardown_fim_scan_realtime),
#endif
        /* fim_checker */
        cmocka_unit_test(test_fim_checker_scheduled_configuration_directory_error),
        cmocka_unit_test(test_fim_checker_not_scheduled_configuration_directory_error),
        cmocka_unit_test(test_fim_checker_over_max_recursion_level),
        cmocka_unit_test(test_fim_checker_deleted_file),
        cmocka_unit_test_setup_teardown(test_fim_checker_deleted_file_enoent, setup_fim_entry, teardown_fim_entry),
#ifndef TEST_WINAGENT
        cmocka_unit_test(test_fim_checker_no_file_system),
#endif
        cmocka_unit_test(test_fim_checker_fim_regular),
        cmocka_unit_test(test_fim_checker_fim_regular_warning),
        cmocka_unit_test(test_fim_checker_fim_regular_ignore),
        cmocka_unit_test(test_fim_checker_fim_regular_restrict),
        cmocka_unit_test_setup_teardown(test_fim_checker_fim_directory, setup_struct_dirent, teardown_struct_dirent),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_fim_checker_fim_directory_on_max_recursion_level, setup_struct_dirent, teardown_struct_dirent),
#endif
        cmocka_unit_test(test_fim_checker_unsupported_path),

        /* fim_directory */
        cmocka_unit_test_setup_teardown(test_fim_directory, setup_struct_dirent, teardown_struct_dirent),
        cmocka_unit_test_setup_teardown(test_fim_directory_ignore, setup_struct_dirent, teardown_struct_dirent),
        cmocka_unit_test(test_fim_directory_nodir),
        cmocka_unit_test(test_fim_directory_opendir_error),

        /* fim_get_data */
        cmocka_unit_test_teardown(test_fim_get_data, teardown_local_data),
        cmocka_unit_test_teardown(test_fim_get_data_no_hashes, teardown_local_data),
        cmocka_unit_test(test_fim_get_data_hash_error),
#ifdef TEST_WINAGENT
        cmocka_unit_test(test_fim_get_data_fail_to_get_file_premissions),
#endif

        /* fim_realtime_event */
        cmocka_unit_test(test_fim_realtime_event_file_exists),
        cmocka_unit_test(test_fim_realtime_event_file_missing),

        /* fim_whodata_event */
        cmocka_unit_test(test_fim_whodata_event_file_exists),
        cmocka_unit_test(test_fim_whodata_event_file_missing),

        /* fim_process_missing_entry */
        cmocka_unit_test(test_fim_process_missing_entry_null_configuration),
        cmocka_unit_test_setup_teardown(test_fim_process_missing_entry_data_exists, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_missing_entry_whodata_disabled, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_missing_entry, setup_fim_entry, teardown_fim_entry),

        /* fim_process_wildcard_removed */
        cmocka_unit_test(test_fim_process_wildcard_removed_no_data),
        cmocka_unit_test(test_fim_process_wildcard_removed_failure),
        cmocka_unit_test_setup_teardown(test_fim_process_wildcard_removed_data_exists, setup_fim_entry, teardown_fim_entry),

        /* fim_diff_folder_size */
        cmocka_unit_test(test_fim_diff_folder_size),

        /* transaction_callback */
        cmocka_unit_test_setup_teardown(test_transaction_callback_add, setup_transaction_callback, teardown_transaction_callback),
        cmocka_unit_test_setup_teardown(test_transaction_callback_modify, setup_transaction_callback, teardown_transaction_callback),
        cmocka_unit_test_setup_teardown(test_transaction_callback_modify_empty_changed_attributes, setup_transaction_callback, teardown_transaction_callback),
        cmocka_unit_test_setup_teardown(test_transaction_callback_modify_report_changes, setup_transaction_callback, teardown_transaction_callback),
        cmocka_unit_test_setup_teardown(test_transaction_callback_delete, setup_transaction_callback, teardown_transaction_callback),
        cmocka_unit_test_setup_teardown(test_transaction_callback_delete_report_changes, setup_transaction_callback, teardown_transaction_callback),
        cmocka_unit_test_setup_teardown (test_transaction_callback_delete_full_db, setup_transaction_callback, teardown_transaction_callback),
        cmocka_unit_test_setup_teardown(test_transaction_callback_full_db, setup_transaction_callback, teardown_transaction_callback),

        /* fim_event_callback */
        cmocka_unit_test(test_fim_event_callback),
        cmocka_unit_test(test_fim_event_callback_empty_changed_attributes),

        cmocka_unit_test(test_fim_calculate_dbsync_difference_no_attributes),
        cmocka_unit_test(test_fim_calculate_dbsync_difference),
        cmocka_unit_test(test_fim_calculate_dbsync_difference_no_changed_data),
        cmocka_unit_test_setup_teardown(test_create_windows_who_data_events, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_process_delete_event, setup_fim_entry, teardown_fim_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_entry, setup_fim_entry, teardown_fim_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_process_missing_entry, setup_fim_entry, teardown_fim_entry),

        /* dbsync_attributes_json */
        cmocka_unit_test_setup_teardown(test_dbsync_attributes_json, setup_json_event_attributes, teardown_json_event_attributes),
    };

    const struct CMUnitTest root_monitor_tests[] = {
        cmocka_unit_test(test_fim_checker_root_ignore_file_under_recursion_level),
        cmocka_unit_test(test_fim_checker_root_file_within_recursion_level),
    };
    const struct CMUnitTest wildcards_tests[] = {
        /* update_wildcards_config */
        cmocka_unit_test(test_update_wildcards_config),
        cmocka_unit_test(test_update_wildcards_config_remove_config),
        cmocka_unit_test(test_update_wildcards_config_list_null),
    };
    int retval;

    retval = cmocka_run_group_tests(tests, setup_group, teardown_group);
    retval += cmocka_run_group_tests(root_monitor_tests, setup_root_group, teardown_group);
    retval += cmocka_run_group_tests(wildcards_tests, setup_wildcards, teardown_wildcards);

    return retval;

}
