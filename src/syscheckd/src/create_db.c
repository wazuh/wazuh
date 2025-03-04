/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"
#include "syscheck_op.h"
#include "integrity_op.h"
#include "time_op.h"
#include "db/include/db.h"
#include "ebpf/include/ebpf_whodata.h"
#include "registry/registry.h"

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "../unit_tests/wrappers/windows/stat64_wrappers.h"
#endif
/* Remove static qualifier when unit testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);

#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

// Global variables
static int _base_line = 0;

static const char *FIM_EVENT_TYPE_ARRAY[] = {
    "added",
    "deleted",
    "modified"
};

static const char *FIM_EVENT_MODE[] = {
    "scheduled",
    "realtime",
    "whodata"
};

cJSON * fim_calculate_dbsync_difference(const fim_file_data *data,
                                        const cJSON* changed_data,
                                        cJSON* old_attributes,
                                        cJSON* changed_attributes) {

    if (old_attributes == NULL || changed_attributes == NULL || !cJSON_IsArray(changed_attributes)) {
        return NULL;
    }

    cJSON *aux = NULL;

    cJSON_AddStringToObject(old_attributes, "type", "file");

    if (data->options & CHECK_SIZE) {
        if (aux = cJSON_GetObjectItem(changed_data, "size"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "size", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("size"));
        } else {
            cJSON_AddNumberToObject(old_attributes, "size", data->size);
        }
    }

    if (data->options & CHECK_PERM) {
        if (aux = cJSON_GetObjectItem(changed_data, "perm"), aux != NULL) {
#ifndef WIN32
            cJSON_AddStringToObject(old_attributes, "perm", cJSON_GetStringValue(aux));
#else
            cJSON_AddItemToObject(old_attributes, "perm", cJSON_Parse(cJSON_GetStringValue(aux)));
#endif
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("permission"));

        } else {
#ifndef WIN32
            cJSON_AddStringToObject(old_attributes, "perm", data->perm);
#else
            cJSON_AddItemToObject(old_attributes, "perm", cJSON_Parse(data->perm));
#endif
        }
    }

    if (data->options & CHECK_OWNER) {
        if (aux = cJSON_GetObjectItem(changed_data, "uid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "uid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("uid"));

        } else {
            cJSON_AddStringToObject(old_attributes, "uid", data->uid);
        }
    }

    if (data->options & CHECK_GROUP) {
        if (aux = cJSON_GetObjectItem(changed_data, "gid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "gid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("gid"));

        } else {
            cJSON_AddStringToObject(old_attributes, "gid", data->gid);
        }
    }

    if (data->user_name) {
        if (aux = cJSON_GetObjectItem(changed_data, "user_name"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "user_name", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("user_name"));

        } else {
            cJSON_AddStringToObject(old_attributes, "user_name", data->user_name);
        }
    }

    if (data->group_name) {
        if (aux = cJSON_GetObjectItem(changed_data, "group_name"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "group_name", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("group_name"));

        } else {
            cJSON_AddStringToObject(old_attributes, "group_name", data->group_name);
        }
    }

    if (data->options & CHECK_INODE) {
        if (aux = cJSON_GetObjectItem(changed_data, "inode"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "inode", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("inode"));

        } else {
            cJSON_AddNumberToObject(old_attributes, "inode", data->inode);
        }
    }

    if (data->options & CHECK_MTIME) {
        if (aux = cJSON_GetObjectItem(changed_data, "mtime"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "mtime", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mtime"));

        } else {
            cJSON_AddNumberToObject(old_attributes, "mtime", data->mtime);
        }
    }

    if (data->options & CHECK_MD5SUM) {
        if (aux = cJSON_GetObjectItem(changed_data, "hash_md5"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "hash_md5", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("md5"));

        } else {
            cJSON_AddStringToObject(old_attributes, "hash_md5", data->hash_md5);
        }
    }

    if (data->options & CHECK_SHA1SUM) {
        if (aux = cJSON_GetObjectItem(changed_data, "hash_sha1"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "hash_sha1", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha1"));

        } else {
            cJSON_AddStringToObject(old_attributes, "hash_sha1", data->hash_sha1);
        }
    }

    if (data->options & CHECK_SHA256SUM) {
        if (aux = cJSON_GetObjectItem(changed_data, "hash_sha256"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "hash_sha256", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha256"));

        } else {
            cJSON_AddStringToObject(old_attributes, "hash_sha256", data->hash_sha256);
        }
    }

#ifdef WIN32
    if (data->options & CHECK_ATTRS) {
        if (aux = cJSON_GetObjectItem(changed_data, "attributes"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "attributes", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("attributes"));

        } else {
            cJSON_AddStringToObject(old_attributes, "attributes", data->attributes);
        }
    }
#endif

    if (*data->checksum) {
        if (aux = cJSON_GetObjectItem(changed_data, "checksum"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "checksum", cJSON_GetStringValue(aux));
        } else {
            cJSON_AddStringToObject(old_attributes, "checksum", data->checksum);
        }
    }

    return old_attributes;
}

/**
 * @brief Function to calculate the `attributes` field using the information returned by dbsync.
 *
 * @param dbsync_event Information returned by dbsync.
 * @param configuration Configuration of the specific entry.
 * @param attributes JSON where the information will be stored.
 */
static void dbsync_attributes_json(const cJSON *dbsync_event, const directory_t *configuration, cJSON *attributes) {
    if (attributes == NULL || dbsync_event == NULL || configuration == NULL) {
        return;
    }

    cJSON *aux = NULL;

    cJSON_AddStringToObject(attributes, "type", "file");

    if (configuration->options & CHECK_SIZE) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "size"), aux != NULL)
        cJSON_AddNumberToObject(attributes, "size", aux->valueint);
    }

    if (configuration->options & CHECK_PERM) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "perm"), aux != NULL) {
#ifndef WIN32
            cJSON_AddStringToObject(attributes, "perm", cJSON_GetStringValue(aux));
#else
            cJSON_AddItemToObject(attributes, "perm", cJSON_Parse(cJSON_GetStringValue(aux)));
#endif
        }
    }

    if (configuration->options & CHECK_OWNER) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "uid"), aux != NULL) {
            char *uid = cJSON_GetStringValue(aux);
            if (uid != NULL && *uid != '\0') {
                cJSON_AddStringToObject(attributes, "uid", uid);
            }
        }
    }

    if (configuration->options & CHECK_GROUP) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "gid"), aux != NULL) {
            char *gid = cJSON_GetStringValue(aux);
            if (gid != NULL && *gid != '\0') {
                cJSON_AddStringToObject(attributes, "gid", gid);
            }
        }
    }

    if (aux = cJSON_GetObjectItem(dbsync_event, "user_name"), aux != NULL) {
        char *user_name = cJSON_GetStringValue(aux);
        if (user_name != NULL && *user_name != '\0') {
            cJSON_AddStringToObject(attributes, "user_name", cJSON_GetStringValue(aux));
        }
    }

    if (aux = cJSON_GetObjectItem(dbsync_event, "group_name"), aux != NULL) {
        char *group_name = cJSON_GetStringValue(aux);
        if (group_name != NULL && *group_name != '\0') {
            cJSON_AddStringToObject(attributes, "group_name", cJSON_GetStringValue(aux));
        }
    }

    if (configuration->options & CHECK_INODE) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "inode"), aux != NULL) {
            cJSON_AddNumberToObject(attributes, "inode", aux->valueint);
        }
    }

    if (configuration->options & CHECK_MTIME) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "mtime"), aux != NULL) {
            cJSON_AddNumberToObject(attributes, "mtime", aux->valueint);
        }
    }

    if (configuration->options & CHECK_MD5SUM) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "hash_md5"), aux != NULL) {
            cJSON_AddStringToObject(attributes, "hash_md5", cJSON_GetStringValue(aux));
        }
    }

    if (configuration->options & CHECK_SHA1SUM) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "hash_sha1"), aux != NULL) {
            cJSON_AddStringToObject(attributes, "hash_sha1", cJSON_GetStringValue(aux));
        }
    }

    if (configuration->options & CHECK_SHA256SUM) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "hash_sha256"), aux != NULL) {
            cJSON_AddStringToObject(attributes, "hash_sha256", cJSON_GetStringValue(aux));
        }
    }

#ifdef WIN32
    if (configuration->options & CHECK_ATTRS) {
        if (aux = cJSON_GetObjectItem(dbsync_event, "attributes"), aux != NULL) {
            cJSON_AddStringToObject(attributes, "attributes", cJSON_GetStringValue(aux));
        }
    }
#endif

    if (aux = cJSON_GetObjectItem(dbsync_event, "checksum"), aux != NULL) {
        cJSON_AddStringToObject(attributes, "checksum", cJSON_GetStringValue(aux));
    }
}

static void transaction_callback(ReturnTypeCallback resultType, const cJSON* result_json, void* user_data) {
    char *path = NULL;
    char *diff = NULL;
    cJSON* json_event = NULL;
    cJSON* data = NULL;
    cJSON* old_attributes = NULL;
    cJSON* changed_attributes = NULL;
    cJSON* old_data = NULL;
    cJSON *attributes = NULL;
    cJSON* timestamp = NULL;
    directory_t *configuration = NULL;
    fim_txn_context_t *txn_context = (fim_txn_context_t *) user_data;

    // In case of deletions, latest_entry is NULL, so we need to get the path from the json event
    if (resultType == DELETED) {
        cJSON *path_cjson = cJSON_GetObjectItem(result_json, "path");
        if (path_cjson == NULL) {
            goto end;
        }
        path = cJSON_GetStringValue(path_cjson);
    } else if (txn_context->latest_entry != NULL) {
        path = txn_context->latest_entry->file_entry.path;
    } else {
        goto end;
    }

    if (configuration = fim_configuration_directory(path), configuration == NULL) {
        goto end;
    }

    if (configuration->options & CHECK_SEECHANGES && resultType != DELETED) {
        diff = fim_file_diff(path, configuration);
    }

    // Do not process if it's the first scan
    if (_base_line == 0) {
        goto end; // LCOV_EXCL_LINE
    }

    switch (resultType) {
        case INSERTED:
            txn_context->evt_data->type = FIM_ADD;
            break;

        case MODIFIED:
            txn_context->evt_data->type = FIM_MODIFICATION;
            break;

        case DELETED:
            if (configuration->options & CHECK_SEECHANGES) {
                fim_diff_process_delete_file(path);
            }

            txn_context->evt_data->type = FIM_DELETE;

            break;

        case MAX_ROWS:
            mdebug1("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", path);

        // Fallthrough
        default:
            goto end;
    }

    json_event = cJSON_CreateObject();
    data = cJSON_CreateObject();

    if (json_event == NULL || data == NULL) {
        goto end; // LCOV_EXCL_LINE
    }

    cJSON_AddStringToObject(json_event, "type", "event");
    cJSON_AddItemToObject(json_event, "data", data);

    cJSON_AddStringToObject(data, "path", path);
    cJSON_AddNumberToObject(data, "version", 2.0);
    cJSON_AddStringToObject(data, "mode", FIM_EVENT_MODE[txn_context->evt_data->mode]);
    cJSON_AddStringToObject(data, "type", FIM_EVENT_TYPE_ARRAY[txn_context->evt_data->type]);

    if(timestamp = cJSON_GetObjectItem(result_json, "last_event"), timestamp != NULL){
        cJSON_AddNumberToObject(data, "timestamp", timestamp->valueint);
    } else {
        cJSON_AddNumberToObject(data, "timestamp", txn_context->latest_entry->file_entry.data->last_event);
    }

    if (resultType == DELETED || txn_context->latest_entry == NULL) {
        // We need to add the `type` field to the attributes JSON. This avoid modifying the dbsync event.
        attributes = cJSON_CreateObject();
        dbsync_attributes_json(result_json, configuration, attributes);
        cJSON_AddItemToObject(data, "attributes", attributes);
    } else {
        cJSON_AddItemToObject(data, "attributes", fim_attributes_json(txn_context->latest_entry->file_entry.data));

        old_data = cJSON_GetObjectItem(result_json, "old");
        if (old_data) {
            old_attributes = cJSON_CreateObject();
            changed_attributes = cJSON_CreateArray();
            cJSON_AddItemToObject(data, "old_attributes", old_attributes);
            cJSON_AddItemToObject(data, "changed_attributes", changed_attributes);
            fim_calculate_dbsync_difference(txn_context->latest_entry->file_entry.data,
                                            old_data,
                                            old_attributes,
                                            changed_attributes);

            if (cJSON_GetArraySize(changed_attributes) == 0) {
                mdebug2(FIM_EMPTY_CHANGED_ATTRIBUTES, path);
                goto end;
            }
        }
    }

    if (diff != NULL && resultType == MODIFIED) {
        cJSON_AddStringToObject(data, "content_changes", diff);
    }

    if (configuration->tag != NULL) {
        cJSON_AddStringToObject(data, "tags", configuration->tag);
    }

    send_syscheck_msg(json_event);

end:
    os_free(diff);
    cJSON_Delete(json_event);
}

void process_delete_event(void * data, void * ctx)
{
    cJSON *json_event = NULL;
    fim_entry *new_entry = (fim_entry *)data;
    struct get_data_ctx *ctx_data = (struct get_data_ctx *)ctx;

    // Remove path from the DB.
    if (fim_db_remove_path(new_entry->file_entry.path) == FIMDB_ERR)
    {
        return;
    }

    if (ctx_data->event->report_event) {
        json_event = fim_json_event(new_entry, NULL, ctx_data->config, ctx_data->event, NULL);
    }

    if (json_event != NULL) {
        send_syscheck_msg(json_event);
    }

    cJSON_Delete(json_event);
}

int fim_generate_delete_event(const char *file_path,
                              const void *_evt_data,
                              const void *configuration) {
    const directory_t *original_configuration = (const directory_t *)configuration;
    get_data_ctx ctx = {
        .event = (event_data_t *)_evt_data,
        .config = original_configuration,
        .path = file_path
    };
    callback_context_t callback_data;
    callback_data.callback = process_delete_event;
    callback_data.context = &ctx;

    if (original_configuration->options & CHECK_SEECHANGES) {
        fim_diff_process_delete_file(file_path);
    }

    return fim_db_get_path(file_path, callback_data);
}

time_t fim_scan() {
    struct timespec start;
    struct timespec end;
    time_t end_of_scan;
    clock_t cputime_start;
    int nodes_count = 0;
    OSListNode *node_it;
    directory_t *dir_it;
    event_data_t evt_data = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
    fim_txn_context_t txn_ctx = { .evt_data = &evt_data, .latest_entry = NULL };

    static fim_state_db _files_db_state = FIM_STATE_DB_EMPTY;
#ifdef WIN32
    static fim_state_db _registry_key_state = FIM_STATE_DB_EMPTY;
    static fim_state_db _registry_value_state = FIM_STATE_DB_EMPTY;
#endif

#ifdef WIN32
    SafeWow64DisableWow64FsRedirection(NULL); //Disable virtual redirection to 64bits folder due this is a x86 process
#endif
    cputime_start = clock();
    gettime(&start);
    minfo(FIM_FREQUENCY_STARTED);
    fim_send_scan_info(FIM_SCAN_START);


    TXN_HANDLE db_transaction_handle = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE, transaction_callback, &txn_ctx);
    if (db_transaction_handle == NULL) {
        merror(FIM_ERROR_TRANSACTION, FIMDB_FILE_TXN_TABLE);
        return time(NULL);
    }
    fim_diff_folder_size();
    syscheck.disk_quota_full_msg = true;

    mdebug2(FIM_DIFF_FOLDER_SIZE, DIFF_DIR, syscheck.diff_folder_size);

    w_mutex_lock(&syscheck.fim_scan_mutex);

    update_wildcards_config();

    w_rwlock_rdlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        char *path = fim_get_real_path(dir_it);

        fim_checker(path, &evt_data, dir_it, db_transaction_handle, &txn_ctx);

#ifndef WIN32
        realtime_adddir(path, dir_it);
#elif defined WIN_WHODATA
        if (FIM_MODE(dir_it->options) == FIM_WHODATA) {
            realtime_adddir(path, dir_it);
        }
#endif
        os_free(path);
    }
    w_rwlock_unlock(&syscheck.directories_lock);

    w_mutex_unlock(&syscheck.fim_scan_mutex);

    if (syscheck.file_limit_enabled) {
        nodes_count = fim_db_get_count_file_entry();
    }

    fim_db_transaction_deleted_rows(db_transaction_handle, transaction_callback, &txn_ctx);
    db_transaction_handle = NULL;

    if (syscheck.file_limit_enabled && (nodes_count >= syscheck.file_entry_limit)) {
        w_mutex_lock(&syscheck.fim_scan_mutex);

        db_transaction_handle = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE, transaction_callback, &txn_ctx);

        w_rwlock_rdlock(&syscheck.directories_lock);
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            char *path;
            event_data_t evt_data = { .mode = FIM_SCHEDULED, .report_event = true, .w_evt = NULL };

            path = fim_get_real_path(dir_it);

            fim_checker(path, &evt_data, dir_it, db_transaction_handle, &txn_ctx);

            // Verify the directory is being monitored correctly
#ifndef WIN32
            realtime_adddir(path, dir_it);
#elif defined WIN_WHODATA
            if (FIM_MODE(dir_it->options) == FIM_WHODATA) {
                realtime_adddir(path, dir_it);
            }
#endif
            os_free(path);
        }
        w_rwlock_unlock(&syscheck.directories_lock);

        w_mutex_unlock(&syscheck.fim_scan_mutex);

        fim_db_transaction_deleted_rows(db_transaction_handle, transaction_callback, &txn_ctx);
        db_transaction_handle = NULL;
    }

#ifdef WIN32
    fim_registry_scan();
#endif

    gettime(&end);
    end_of_scan = time(NULL);

    if (syscheck.file_limit_enabled) {
        int files_count = fim_db_get_count_file_entry();
        fim_check_db_state(syscheck.file_entry_limit, files_count, &_files_db_state, FIMDB_FILE_TABLE_NAME);
    }

#ifdef WIN32
    if (syscheck.registry_limit_enabled) {
        fim_check_db_state(syscheck.db_entry_registry_limit,
                           fim_db_get_count_registry_key(),
                           &_registry_key_state,
                           FIMDB_REGISTRY_KEY_TABLENAME);
        fim_check_db_state(syscheck.db_entry_registry_limit,
                           fim_db_get_count_registry_data(),
                           &_registry_value_state,
                           FIMDB_REGISTRY_VALUE_TABLENAME);
    }
#endif

    if (_base_line == 0) {
        _base_line = 1;
    } else {
        // In the first scan, the fim initialization is different between Linux and Windows.
        // Realtime watches are set after the first scan in Windows.
        if (fim_realtime_get_queue_overflow()) {
            fim_realtime_set_queue_overflow(false);
            realtime_sanitize_watch_map();
        }
        fim_realtime_print_watches();
    }

    minfo(FIM_FREQUENCY_ENDED);
    fim_send_scan_info(FIM_SCAN_END);

    if (isDebug()) {
        fim_print_info(start, end, cputime_start); // LCOV_EXCL_LINE
    }
    audit_queue_full_reported = 0;

    return end_of_scan;
}

void fim_checker(const char *path,
                 event_data_t *evt_data,
                 const directory_t *parent_configuration,
                 TXN_HANDLE dbsync_txn,
                 fim_txn_context_t *ctx) {
    directory_t *configuration;
    int depth;

    if (!w_utf8_valid(path)) {
        mwarn(FIM_INVALID_FILE_NAME, path);
        return;
    }

#ifdef WIN32
    // Ignore the recycle bin.
    if (check_removed_file(path)){
        return;
    }
#endif

    configuration = fim_configuration_directory(path);
    if (configuration == NULL) {
        return;
    }

    if (parent_configuration == NULL) {
        // First time entering fim_checker
        // It's dangerous to go alone! Take this.
        parent_configuration = configuration;
    }

    if (evt_data->mode == FIM_SCHEDULED) {
        // If the directory has another configuration will scan it with that configuration
        if (parent_configuration != configuration) {
            return;
        }
    } else if (evt_data->mode != FIM_MODE(configuration->options)) {
        // If this event is not generated by a scan, the mode of the event and
        // the mode configured must match
        return;
    }

    depth = fim_check_depth(path, configuration);

    if (depth > configuration->recursion_level) {
        mdebug2(FIM_MAX_RECURSION_LEVEL, depth, configuration->recursion_level, path);
        return;
    }

    // Deleted file. Sending alert.
    if (w_stat(path, &(evt_data->statbuf)) == -1) {
        if(errno != ENOENT) {
            mdebug1(FIM_STAT_FAILED, path, errno, strerror(errno));
            return;
        }

        if((evt_data->mode == FIM_REALTIME && !(configuration->options & REALTIME_ACTIVE)) ||
           (evt_data->mode == FIM_WHODATA && !(configuration->options & WHODATA_ACTIVE))) {
            /* Don't send alert if received mode and mode in configuration aren't the same.
            Scheduled mode events must always be processed to preserve the state of the agent's DB.
            */
            return;
        }

        mwarn("fim_checker1");
        // Delete alerts in scheduled scan is triggered in the transaction delete rows operation.
        if (evt_data->mode != FIM_SCHEDULED) {
            evt_data->type = FIM_DELETE;
            get_data_ctx ctx = {
                .event = (event_data_t *)evt_data,
                .config = configuration,
                .path = path
            };
            mwarn("fim_checker2");
            callback_context_t callback_data;
            callback_data.callback = process_delete_event;
            callback_data.context = &ctx;
            fim_db_get_path(path, callback_data);

            mwarn("fim_checker3");
            if (configuration->options & CHECK_SEECHANGES)
            {
                fim_diff_process_delete_file(path);
            }
        }

        return;
    }

#ifdef WIN_WHODATA
    if (evt_data->w_evt && evt_data->w_evt->scan_directory == 1) {
        if (w_update_sacl(path)) {
            mdebug1(FIM_SCAL_NOREFRESH, path);
        }
    }
#endif

    if (HasFilesystem(path, syscheck.skip_fs)) {
        return;
    }

    if (fim_check_ignore(path) == 1) {
        return;
    }

    switch (evt_data->statbuf.st_mode & S_IFMT) {
#ifndef WIN32
    case FIM_LINK:
        // Fallthrough
#endif
    case FIM_REGULAR:
        if (fim_check_restrict(path, configuration->filerestrict) == 1) {
            return;
        }

        fim_file(path, configuration, evt_data, dbsync_txn, ctx);
        break;

    case FIM_DIRECTORY:
        if (depth == configuration->recursion_level) {
            mdebug2(FIM_DIR_RECURSION_LEVEL, path, depth);
            return;
        }
        fim_directory(path, evt_data, configuration, dbsync_txn, ctx);

#ifdef INOTIFY_ENABLED
        if (FIM_MODE(configuration->options) == FIM_REALTIME) {
            fim_add_inotify_watch(path, configuration);
        }
#endif
        break;
    }
}


int fim_directory(const char *dir,
                  event_data_t *evt_data,
                  const directory_t *configuration,
                  TXN_HANDLE dbsync_txn,
                  fim_txn_context_t *ctx) {
    DIR *dp;
    struct dirent *entry;
    char *f_name;
    char *s_name;
    size_t path_size;

    if (!dir) {
        merror(NULL_ERROR);
        return OS_INVALID;
    }

    // Open the directory given
    dp = opendir(dir);

    if (!dp) {
        mwarn(FIM_PATH_NOT_OPEN, dir, strerror(errno));
        return OS_INVALID;
    }

    os_calloc(PATH_MAX + 2, sizeof(char), f_name);
    while ((entry = readdir(dp)) != NULL) {
        // Ignore . and ..
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        strncpy(f_name, dir, PATH_MAX);
        path_size = strlen(dir);
        s_name = f_name + path_size;

        // Check if the file name is already null terminated
        if (*(s_name - 1) != PATH_SEP) {
            *s_name++ = PATH_SEP;
        }
        *(s_name) = '\0';
        path_size = strlen(f_name);

#ifdef WIN32
        // Check if the full path is too long if it is, skip this file
        // and log a warning, PATH_MAX is 260 on windows, but reserves 1 char
        // for the null terminator.
        if (path_size + strlen(entry->d_name) >= PATH_MAX) {
            mwarn(FIM_ERROR_PATH_TOO_LONG, f_name, entry->d_name, PATH_MAX);
            continue;
        }
#endif

        snprintf(s_name, PATH_MAX + 2 - path_size, "%s", entry->d_name);

#ifdef WIN32
        str_lowercase(f_name);
#endif
        // Process the event related to f_name
        fim_checker(f_name, evt_data, configuration, dbsync_txn, ctx);
    }

    os_free(f_name);
    closedir(dp);
    return 0;
}

void fim_event_callback(void* data, void * ctx)
{
    struct create_json_event_ctx* ctx_data = (struct create_json_event_ctx*)ctx;
    cJSON* json_event = (cJSON*)data;

    mwarn("fim_event_callback1");
    if (json_event != NULL) {
        cJSON* data_json = cJSON_GetObjectItem(json_event, "data");
        char* path;

        path = cJSON_GetStringValue(cJSON_GetObjectItem(data_json, "path"));

        cJSON *changed_attributes = cJSON_GetObjectItem(data_json, "changed_attributes");
        if (changed_attributes && cJSON_GetArraySize(changed_attributes) == 0) {
            mdebug2(FIM_EMPTY_CHANGED_ATTRIBUTES, path);
            return;
        }

        if (ctx_data->config->options & CHECK_SEECHANGES) {
            char* diff;

            diff = fim_file_diff(path, ctx_data->config);
            if (diff != NULL && ctx_data->event->type == FIM_MODIFICATION) {
                cJSON_AddStringToObject(data_json, "content_changes", diff);
            }
            os_free(diff);
        }

        if (ctx_data->event->w_evt) {
            cJSON_AddItemToObject(data_json, "audit", fim_audit_json(ctx_data->event->w_evt));
        }

        if (ctx_data->config->tag != NULL) {
            cJSON_AddStringToObject(data_json, "tags", ctx_data->config->tag);
        }

#ifdef WIN32
        cJSON* attributes_json = cJSON_GetObjectItem(data_json, "attributes");
        char* perm_string = cJSON_GetStringValue(cJSON_GetObjectItem(attributes_json, "perm"));
        cJSON_ReplaceItemInObject(attributes_json, "perm", cJSON_Parse(perm_string));

        cJSON* old_attributes_json = cJSON_GetObjectItem(data_json, "old_attributes");
        if (old_attributes_json) {
            char* old_perm_string = cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes_json, "perm"));
            cJSON_ReplaceItemInObject(old_attributes_json, "perm", cJSON_Parse(old_perm_string));
        }
#endif
        mwarn("fim_event_callback2");
        send_syscheck_msg(json_event);
        mwarn("fim_event_callback3");
    }
}

void fim_file(const char *path,
              const directory_t *configuration,
              event_data_t *evt_data,
              TXN_HANDLE txn_handle,
              fim_txn_context_t *txn_context) {
    assert(path != NULL);
    assert(configuration != NULL);
    assert(evt_data != NULL);

    fim_entry new_entry;

    check_max_fps();

    new_entry.type = FIM_TYPE_FILE;
    new_entry.file_entry.path = (char *)path;
    new_entry.file_entry.data = fim_get_data(path, configuration, &(evt_data->statbuf));

    if (new_entry.file_entry.data == NULL) {
        mdebug1(FIM_GET_ATTRIBUTES, path);
        return;
    }

    if (txn_handle != NULL) {
        txn_context->latest_entry = &new_entry;

        fim_db_transaction_sync_row(txn_handle, &new_entry);
        free_file_data(new_entry.file_entry.data);
        txn_context->latest_entry = NULL;
    } else {
        create_json_event_ctx ctx = {
            .event = evt_data,
            .config = configuration,
        };

        callback_context_t callback_data;
        callback_data.callback = fim_event_callback;
        callback_data.context = &ctx;

        mwarn("pre-fim_db_file_update");
        fim_db_file_update(&new_entry, callback_data);
        mwarn("post-fim_db_file_update");
        free_file_data(new_entry.file_entry.data);
    }


    return;
}

void fim_realtime_event(char *file) {
    struct stat file_stat;

    // If the file exists, generate add or modify events.
    if (w_stat(file, &file_stat) >= 0) {
        event_data_t evt_data = { .mode = FIM_REALTIME, .w_evt = NULL, .report_event = true };

        /* Need a sleep here to avoid triggering on vim
         * (and finding the file removed)
         */
        fim_rt_delay();

        fim_checker(file, &evt_data, NULL, NULL, NULL);
    } else {
        // Otherwise, it could be a file deleted or a directory moved (or renamed).
        fim_process_missing_entry(file, FIM_REALTIME, NULL);
    }
}

// Callback
void create_windows_who_data_events(void * data, void * ctx)
{
    char *path = (char *)data;
    whodata_evt *w_evt = (whodata_evt *)ctx;

    fim_process_missing_entry(path, FIM_WHODATA, w_evt);
}

void fim_whodata_event(whodata_evt * w_evt) {

    struct stat file_stat;

    // If the file exists, generate add or modify events.
    if(w_stat(w_evt->path, &file_stat) >= 0) {
        event_data_t evt_data = { .mode = FIM_WHODATA, .w_evt = w_evt, .report_event = true };

        fim_rt_delay();

        w_rwlock_rdlock(&syscheck.directories_lock);
        fim_checker(w_evt->path, &evt_data, NULL, NULL, NULL);
        w_rwlock_unlock(&syscheck.directories_lock);
    } else {
        // Otherwise, it could be a file deleted or a directory moved (or renamed).
        w_rwlock_rdlock(&syscheck.directories_lock);
        fim_process_missing_entry(w_evt->path, FIM_WHODATA, w_evt);
        w_rwlock_unlock(&syscheck.directories_lock);
#ifndef WIN32
        const unsigned long int inode = strtoul(w_evt->inode, NULL, 10);
        const unsigned long int dev = strtoul(w_evt->dev, NULL, 10);
        callback_context_t callback_data;
        callback_data.callback = create_windows_who_data_events;
        callback_data.context = w_evt;
        fim_db_file_inode_search(inode, dev, callback_data);
#endif
    }
}

// Callback
void fim_db_remove_entry(void * data, void * ctx)
{
    char *path = (char *)data;
    get_data_ctx *ctx_data = (struct get_data_ctx *)ctx;

    fim_generate_delete_event(path, ctx_data->event, ctx_data->config);
}

void fim_process_wildcard_removed(directory_t *configuration) {
    event_data_t evt_data = { .mode = FIM_SCHEDULED, .w_evt = NULL, .report_event = true, .type = FIM_DELETE };

    if (fim_generate_delete_event(configuration->path, &evt_data, configuration) == FIMDB_ERR)
    {
        return;
    }

    // Since the file doesn't exist, research if it's directory and have files in DB.
    char pattern[PATH_MAX] = {0};

    // Create the sqlite LIKE pattern -> "pathname/%"
    snprintf(pattern, PATH_MAX, "%s%c%%", configuration->path, PATH_SEP);
    get_data_ctx ctx = {
        .event = (event_data_t *)&evt_data,
        .config = configuration,
        .path = configuration->path
    };
    callback_context_t callback_data;
    callback_data.callback = fim_db_remove_entry;
    callback_data.context = &ctx;
    fim_db_file_pattern_search(pattern, callback_data);
}

// Callback
void fim_db_process_missing_entry(void * data, void * ctx)
{
    fim_entry *new_entry = (fim_entry *)data;
    struct get_data_ctx *ctx_data = (struct get_data_ctx *)ctx;

    fim_checker(new_entry->file_entry.path, ctx_data->event, NULL, NULL, NULL);
}

void fim_process_missing_entry(char * pathname, fim_event_mode mode, whodata_evt * w_evt) {
    event_data_t evt_data = { .mode = mode, .w_evt = w_evt, .report_event = true };
    directory_t *configuration = NULL;

    configuration = fim_configuration_directory(pathname);
    if (NULL == configuration) {
        return;
    }

    get_data_ctx ctx = {
        .event = (event_data_t *)&evt_data,
        .config = configuration,
        .path = pathname
    };

    callback_context_t callback_data;
    callback_data.callback = fim_db_process_missing_entry;
    callback_data.context = &ctx;

    // Exists, create event.
    if (fim_db_get_path(pathname, callback_data) == FIMDB_OK) {
        return;
    }

    if((evt_data.mode == FIM_REALTIME && !(configuration->options & REALTIME_ACTIVE)) ||
      (evt_data.mode == FIM_WHODATA && !(configuration->options & WHODATA_ACTIVE)))
    {
        /* Don't send alert if received mode and mode in configuration aren't the same.
        Scheduled mode events must always be processed to preserve the state of the agent's DB.
        */
        return;
    }
    // Since the file doesn't exist, research if it's directory and have files in DB.
    char pattern[PATH_MAX] = {0};

    // Create the sqlite LIKE pattern -> "pathname/%"
    snprintf(pattern, PATH_MAX, "%s%c%%", pathname, PATH_SEP);
    evt_data.type = FIM_DELETE;
    ctx.event = (event_data_t *)&evt_data;
    callback_data.callback = fim_db_remove_entry;
    callback_data.context = &ctx;
    fim_db_file_pattern_search(pattern, callback_data);
}

// Checks the DB state, sends a message alert if necessary
void fim_check_db_state(int nodes_limit, int nodes_count, fim_state_db* db_state, const char* table_name) {
    cJSON *json_event = NULL;
    char *json_plain = NULL;
    char alert_msg[OS_SIZE_256] = {'\0'};

    if (nodes_count < 0) {
        mwarn(FIM_DATABASE_NODES_COUNT_FAIL);
        return;
    }

    switch (*db_state) {
    case FIM_STATE_DB_FULL:
        if (nodes_count >= nodes_limit) {
            return;
        }
        break;
    case FIM_STATE_DB_90_PERCENTAGE:
        if ((nodes_count < nodes_limit) && (nodes_count >= nodes_limit * 0.9)) {
            return;
        }
        break;
    case FIM_STATE_DB_80_PERCENTAGE:
        if ((nodes_count < nodes_limit * 0.9) && (nodes_count >= nodes_limit * 0.8)) {
            return;
        }
        break;
    case FIM_STATE_DB_NORMAL:
        if (nodes_count == 0) {
            *db_state = FIM_STATE_DB_EMPTY;
            return;
        }
        else if (nodes_count < nodes_limit * 0.8) {
            return;
        }
        break;
    case FIM_STATE_DB_EMPTY:
        if (nodes_count == 0) {
            return;
        }
        else if (nodes_count < nodes_limit * 0.8) {
            *db_state = FIM_STATE_DB_NORMAL;
            return;
        }
        break;
    default: // LCOV_EXCL_LINE
        break; // LCOV_EXCL_LINE
    }

    json_event = cJSON_CreateObject();

    cJSON_AddStringToObject(json_event, "fim_db_table", table_name);

    if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
        cJSON_AddNumberToObject(json_event, "file_limit", nodes_limit);
        cJSON_AddNumberToObject(json_event, "file_count", nodes_count);
    }
#ifdef WIN32
    else {
        cJSON_AddNumberToObject(json_event, "registry_limit", nodes_limit);
        cJSON_AddNumberToObject(json_event, "values_count", fim_db_get_count_registry_data());
        cJSON_AddNumberToObject(json_event, "keys_count", fim_db_get_count_registry_key());
    }
#endif

    if (nodes_count >= nodes_limit) {
        *db_state = FIM_STATE_DB_FULL;
        mwarn(strcmp(table_name, FIMDB_FILE_TABLE_NAME) ? FIM_DB_FULL_ALERT_REG : FIM_DB_FULL_ALERT_FILE);
        cJSON_AddStringToObject(json_event, "alert_type", "full");
    }
    else if (nodes_count >= nodes_limit * 0.9) {
        *db_state = FIM_STATE_DB_90_PERCENTAGE;
        minfo(strcmp(table_name, FIMDB_FILE_TABLE_NAME) ? FIM_DB_90_PERCENTAGE_ALERT_REG : FIM_DB_90_PERCENTAGE_ALERT_FILE);
        cJSON_AddStringToObject(json_event, "alert_type", "90_percentage");
    }
    else if (nodes_count >= nodes_limit * 0.8) {
        *db_state = FIM_STATE_DB_80_PERCENTAGE;
        minfo(strcmp(table_name, FIMDB_FILE_TABLE_NAME) ? FIM_DB_80_PERCENTAGE_ALERT_REG : FIM_DB_80_PERCENTAGE_ALERT_FILE);
        cJSON_AddStringToObject(json_event, "alert_type", "80_percentage");
    }
    else if (nodes_count > 0) {
        *db_state = FIM_STATE_DB_NORMAL;
        minfo(strcmp(table_name, FIMDB_FILE_TABLE_NAME) ? FIM_DB_NORMAL_ALERT_REG : FIM_DB_NORMAL_ALERT_FILE);
        cJSON_AddStringToObject(json_event, "alert_type", "normal");
    }
    else {
        *db_state = FIM_STATE_DB_EMPTY;
        minfo(strcmp(table_name, FIMDB_FILE_TABLE_NAME) ? FIM_DB_NORMAL_ALERT_REG : FIM_DB_NORMAL_ALERT_FILE);
        cJSON_AddStringToObject(json_event, "alert_type", "normal");
    }

    json_plain = cJSON_PrintUnformatted(json_event);

    snprintf(alert_msg, OS_SIZE_256, "wazuh: FIM DB: %s", json_plain);

    send_log_msg(alert_msg);

    os_free(json_plain);
    cJSON_Delete(json_event);
}

// Returns the position of the path into directories array
directory_t *fim_configuration_directory(const char *path) {
    char full_path[OS_SIZE_4096 + 1] = {'\0'};
    char full_entry[OS_SIZE_4096 + 1] = {'\0'};
    directory_t *dir_it = NULL;
    directory_t *dir = NULL;
    OSListNode *node_it;
    int top = 0;
    int match = 0;

    if (!path || *path == '\0') {
        return NULL;
    }

    trail_path_separator(full_path, path, sizeof(full_path));

    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        char *real_path = fim_get_real_path(dir_it);

        trail_path_separator(full_entry, real_path, sizeof(full_entry));
        match = w_compare_str(full_entry, full_path);

        if (top < match && full_path[match - 1] == PATH_SEP) {
            dir = dir_it;
            top = match;
        }

        os_free(real_path);
    }

    return dir;
}

int fim_check_depth(const char *path, const directory_t *configuration) {
    const char * pos;
    int depth = -1;
    char *parent_path;
    unsigned int parent_path_size;

    assert(configuration != NULL);

    parent_path = fim_get_real_path(configuration);
    parent_path_size = strlen(parent_path);
    os_free(parent_path);

    if (parent_path_size > strlen(path)) {
        return -1;
    }

#ifdef WIN32
    // Check for monitoring of 'U:\'
    if(parent_path_size == 3 && path[2] == '\\') {
        depth = 0;
    }
#else
    // Check for monitoring of '/'
    if(parent_path_size == 1) {
        depth = 0;
    }
#endif

    pos = path + parent_path_size;
    while (pos) {
        if (pos = strchr(pos, PATH_SEP), pos) {
            depth++;
        } else {
            break;
        }
        pos++;
    }

    return depth;
}


// Get data from file
fim_file_data *fim_get_data(const char *file, const directory_t *configuration, const struct stat *statbuf) {
    fim_file_data * data = NULL;

    os_calloc(1, sizeof(fim_file_data), data);
    init_fim_data_entry(data);

    if (configuration->options & CHECK_SIZE) {
        data->size = statbuf->st_size;
    }

    if (configuration->options & CHECK_PERM) {
#ifdef WIN32
        int error;

        error = w_get_file_permissions(file, &(data->perm_json));
        if (error) {
            mdebug1(FIM_EXTRACT_PERM_FAIL, file, error);
            free_file_data(data);
            return NULL;
        }

        decode_win_acl_json(data->perm_json);
        data->perm = cJSON_PrintUnformatted(data->perm_json);
#else
        data->perm = agent_file_perm(statbuf->st_mode);
#endif
    }

#ifdef WIN32
    if (configuration->options & CHECK_ATTRS) {
        os_calloc(OS_SIZE_256, sizeof(char), data->attributes);
        decode_win_attributes(data->attributes, w_get_file_attrs(file));
    }
#endif

    if (configuration->options & CHECK_MTIME) {
#ifdef WIN32
        data->mtime = get_UTC_modification_time(file);
#else
        data->mtime = statbuf->st_mtime;
#endif
    }

#ifdef WIN32
    if (configuration->options & CHECK_OWNER) {
        data->user_name = get_file_user(file, &data->uid);
    }
#else
    if (configuration->options & CHECK_OWNER) {
        char aux[OS_SIZE_64];
        snprintf(aux, OS_SIZE_64, "%u", statbuf->st_uid);
        os_strdup(aux, data->uid);

        data->user_name = get_user(statbuf->st_uid);
    }

    if (configuration->options & CHECK_GROUP) {
        char aux[OS_SIZE_64];
        snprintf(aux, OS_SIZE_64, "%u", statbuf->st_gid);
        os_strdup(aux, data->gid);

        data->group_name = get_group(statbuf->st_gid);
    }
#endif

    snprintf(data->hash_md5, sizeof(os_md5), "%s", "d41d8cd98f00b204e9800998ecf8427e");
    snprintf(data->hash_sha1, sizeof(os_sha1), "%s", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    snprintf(data->hash_sha256, sizeof(os_sha256), "%s", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // The file exists and we don't have to delete it from the hash tables
    data->scanned = 1;

    // We won't calculate hash for symbolic links, empty or large files
    if (S_ISREG(statbuf->st_mode) && (statbuf->st_size > 0 && statbuf->st_size < syscheck.file_max_size) &&
        (configuration->options & (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM))) {
        if (OS_MD5_SHA1_SHA256_File(file, syscheck.prefilter_cmd, data->hash_md5,
                                    data->hash_sha1, data->hash_sha256, OS_BINARY, syscheck.file_max_size) < 0) {
            mdebug1(FIM_HASHES_FAIL, file);
            free_file_data(data);
            return NULL;
        }
    }

    if ((configuration->options & CHECK_MD5SUM) == 0) {
        data->hash_md5[0] = '\0';
    }

    if ((configuration->options & CHECK_SHA1SUM) == 0) {
        data->hash_sha1[0] = '\0';
    }

    if ((configuration->options & CHECK_SHA256SUM) == 0) {
        data->hash_sha256[0] = '\0';
    }

    data->inode = statbuf->st_ino;
    data->dev = statbuf->st_dev;
    data->options = configuration->options;
    data->last_event = time(NULL);
    fim_get_checksum(data);

    return data;
}

void init_fim_data_entry(fim_file_data *data) {
    data->size = 0;
    data->perm = NULL;
#ifdef WIN32
    data->perm_json = NULL;
#endif
    data->attributes = NULL;
    data->uid = NULL;
    data->gid = NULL;
    data->user_name = NULL;
    data->group_name = NULL;
    data->mtime = 0;
    data->inode = 0;
    data->hash_md5[0] = '\0';
    data->hash_sha1[0] = '\0';
    data->hash_sha256[0] = '\0';
}

void fim_get_checksum (fim_file_data * data) {
    int size;
    char *checksum = NULL;

    size = snprintf(0,
            0,
            "%llu:%s:%s:%s:%s:%s:%s:%lu:%llu:%s:%s:%s",
            data->size,
            data->perm ? data->perm : "",
            data->attributes ? data->attributes : "",
            data->uid ? data->uid : "",
            data->gid ? data->gid : "",
            data->user_name ? data->user_name : "",
            data->group_name ? data->group_name : "",
            data->mtime,
            data->inode,
            data->hash_md5,
            data->hash_sha1,
            data->hash_sha256);

    os_calloc(size + 1, sizeof(char), checksum);
    snprintf(checksum,
            size + 1,
            "%llu:%s:%s:%s:%s:%s:%s:%lu:%llu:%s:%s:%s",
            data->size,
            data->perm ? data->perm : "",
            data->attributes ? data->attributes : "",
            data->uid ? data->uid : "",
            data->gid ? data->gid : "",
            data->user_name ? data->user_name : "",
            data->group_name ? data->group_name : "",
            data->mtime,
            data->inode,
            data->hash_md5,
            data->hash_sha1,
            data->hash_sha256);

    OS_SHA1_Str(checksum, -1, data->checksum);
    free(checksum);
}

cJSON *fim_json_event(const fim_entry *new_data,
                      const fim_file_data *old_data,
                      const directory_t *configuration,
                      const event_data_t *evt_data,
                      const char *diff) {
    cJSON * changed_attributes = NULL;

    assert(new_data != NULL);

    if (old_data != NULL) {
        changed_attributes = fim_json_compare_attrs(old_data, new_data->file_entry.data);

        // If no such changes, do not send event.

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON * json_event = cJSON_CreateObject();
    cJSON_AddStringToObject(json_event, "type", "event");

    cJSON * data = cJSON_CreateObject();
    cJSON_AddItemToObject(json_event, "data", data);

    cJSON_AddStringToObject(data, "path", new_data->file_entry.path);
    cJSON_AddNumberToObject(data, "version", 2.0);
    cJSON_AddStringToObject(data, "mode", FIM_EVENT_MODE[evt_data->mode]);
    cJSON_AddStringToObject(data, "type", FIM_EVENT_TYPE_ARRAY[evt_data->type]);
    cJSON_AddNumberToObject(data, "timestamp", new_data->file_entry.data->last_event);

    cJSON_AddItemToObject(data, "attributes", fim_attributes_json(new_data->file_entry.data));

    if (old_data) {
        cJSON_AddItemToObject(data, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(data, "old_attributes", fim_attributes_json(old_data));
    }

    char * tags = NULL;
    if (evt_data->w_evt) {
        cJSON_AddItemToObject(data, "audit", fim_audit_json(evt_data->w_evt));
    }

    tags = configuration->tag;

    if (diff != NULL) {
        cJSON_AddStringToObject(data, "content_changes", diff);
    }

    if (tags != NULL) {
        cJSON_AddStringToObject(data, "tags", tags);
    }

    return json_event;
}

// Create file attribute set JSON from a FIM entry structure

cJSON * fim_attributes_json(const fim_file_data * data) {
    cJSON * attributes = cJSON_CreateObject();

    // TODO: Read structure.
    // SQLite Development
    cJSON_AddStringToObject(attributes, "type", "file");

    if (data->options & CHECK_SIZE) {
        cJSON_AddNumberToObject(attributes, "size", data->size);
    }

    if (data->options & CHECK_PERM) {
#ifndef WIN32
        cJSON_AddStringToObject(attributes, "perm", data->perm);
#else
        cJSON_AddItemToObject(attributes, "perm", cJSON_Parse(data->perm));
#endif
    }

    if (data->options & CHECK_OWNER && data->uid && *data->uid != '\0' ) {
        cJSON_AddStringToObject(attributes, "uid", data->uid);
    }

    if (data->options & CHECK_GROUP && data->gid && *data->gid != '\0' ) {
        cJSON_AddStringToObject(attributes, "gid", data->gid);
    }

    if (data->user_name && *data->user_name != '\0' ) {
        cJSON_AddStringToObject(attributes, "user_name", data->user_name);
    }

    if (data->group_name && *data->group_name != '\0') {
        cJSON_AddStringToObject(attributes, "group_name", data->group_name);
    }

    if (data->options & CHECK_INODE) {
        cJSON_AddNumberToObject(attributes, "inode", data->inode);
    }

    if (data->options & CHECK_MTIME) {
        cJSON_AddNumberToObject(attributes, "mtime", data->mtime);
    }

    if (data->options & CHECK_MD5SUM) {
        cJSON_AddStringToObject(attributes, "hash_md5", data->hash_md5);
    }

    if (data->options & CHECK_SHA1SUM) {
        cJSON_AddStringToObject(attributes, "hash_sha1", data->hash_sha1);
    }

    if (data->options & CHECK_SHA256SUM) {
        cJSON_AddStringToObject(attributes, "hash_sha256", data->hash_sha256);
    }

#ifdef WIN32
    if (data->options & CHECK_ATTRS) {
        cJSON_AddStringToObject(attributes, "attributes", data->attributes);
    }
#endif

    if (*data->checksum) {
        cJSON_AddStringToObject(attributes, "checksum", data->checksum);
    }

    return attributes;
}

// Create file attribute comparison JSON object

cJSON * fim_json_compare_attrs(const fim_file_data * old_data, const fim_file_data * new_data) {
    cJSON * changed_attributes = cJSON_CreateArray();

    if ( (old_data->options & CHECK_SIZE) && (old_data->size != new_data->size) ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("size"));
    }

#ifndef WIN32
    if ( (old_data->options & CHECK_PERM) && strcmp(old_data->perm, new_data->perm) != 0 ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("permission"));
    }
#else
    if ( (old_data->options & CHECK_PERM) && compare_win_permissions(old_data->perm_json, new_data->perm_json) == false ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("permission"));
    }

    if ( (old_data->options & CHECK_ATTRS) && strcmp(old_data->attributes, new_data->attributes) != 0 ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("attributes"));
    }
#endif

    if (old_data->options & CHECK_OWNER) {
        if (old_data->uid && new_data->uid && strcmp(old_data->uid, new_data->uid) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("uid"));
        }

#ifndef WIN32
        if (old_data->user_name && new_data->user_name && strcmp(old_data->user_name, new_data->user_name) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("user_name"));
        }
#else
        // AD might fail to solve the user name, we don't trigger an event if the user name is empty
        if (old_data->user_name && *old_data->user_name != '\0' && new_data->user_name &&
            *new_data->user_name != '\0' && strcmp(old_data->user_name, new_data->user_name) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("user_name"));
        }
#endif
    }

    if (old_data->options & CHECK_GROUP) {
        if (old_data->gid && new_data->gid && strcmp(old_data->gid, new_data->gid) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("gid"));
        }

        if (old_data->group_name && new_data->group_name && strcmp(old_data->group_name, new_data->group_name) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("group_name"));
        }
    }

    if ( (old_data->options & CHECK_MTIME) && (old_data->mtime != new_data->mtime) ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mtime"));
    }

#ifndef WIN32
    if ( (old_data->options & CHECK_INODE) && (old_data->inode != new_data->inode) ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("inode"));
    }
#endif

    if ( (old_data->options & CHECK_MD5SUM) && (strcmp(old_data->hash_md5, new_data->hash_md5) != 0) ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("md5"));
    }

    if ( (old_data->options & CHECK_SHA1SUM) && (strcmp(old_data->hash_sha1, new_data->hash_sha1) != 0) ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha1"));
    }

    if ( (old_data->options & CHECK_SHA256SUM) && (strcmp(old_data->hash_sha256, new_data->hash_sha256) != 0) ) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha256"));
    }

    return changed_attributes;
}

// Create file audit data JSON object

cJSON * fim_audit_json(const whodata_evt * w_evt) {
    cJSON * fim_audit = cJSON_CreateObject();

    mwarn("fim_audit_json1");
    if (w_evt->user_id) cJSON_AddStringToObject(fim_audit, "user_id", w_evt->user_id);
    if (w_evt->user_name) cJSON_AddStringToObject(fim_audit, "user_name", w_evt->user_name);
    if (w_evt->process_name) cJSON_AddStringToObject(fim_audit, "process_name", w_evt->process_name);
    cJSON_AddNumberToObject(fim_audit, "process_id", w_evt->process_id);
    mwarn("fim_audit_json2");
#ifndef WIN32
    mwarn("fim_audit_json3");
    if (w_evt->cwd) cJSON_AddStringToObject(fim_audit, "cwd", w_evt->cwd);
    if (w_evt->group_id) cJSON_AddStringToObject(fim_audit, "group_id", w_evt->group_id);
    if (w_evt->group_name) cJSON_AddStringToObject(fim_audit, "group_name", w_evt->group_name);
    if (w_evt->audit_uid) cJSON_AddStringToObject(fim_audit, "audit_uid", w_evt->audit_uid);
    mwarn("fim_audit_json4");
    if (w_evt->audit_name) cJSON_AddStringToObject(fim_audit, "audit_name", w_evt->audit_name);
    if (w_evt->effective_uid) cJSON_AddStringToObject(fim_audit, "effective_uid", w_evt->effective_uid);
    if (w_evt->effective_name) cJSON_AddStringToObject(fim_audit, "effective_name", w_evt->effective_name);
    if (w_evt->parent_name) cJSON_AddStringToObject(fim_audit, "parent_name", w_evt->parent_name);
    if (w_evt->parent_cwd) cJSON_AddStringToObject(fim_audit, "parent_cwd", w_evt->parent_cwd);
    cJSON_AddNumberToObject(fim_audit, "ppid", w_evt->ppid);
    mwarn("fim_audit_json5");
#endif

    return fim_audit;
}

// Create scan info JSON event

cJSON * fim_scan_info_json(fim_scan_event event, long timestamp) {
    cJSON * root = cJSON_CreateObject();
    cJSON * data = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "type", event == FIM_SCAN_START ? "scan_start" : "scan_end");
    cJSON_AddItemToObject(root, "data", data);
    cJSON_AddNumberToObject(data, "timestamp", timestamp);

    return root;
}

int fim_check_ignore (const char *file_name) {
    // Check if the file should be ignored
    if (syscheck.ignore) {
        int i = 0;
        while (syscheck.ignore[i] != NULL) {
            if (strncasecmp(syscheck.ignore[i], file_name, strlen(syscheck.ignore[i])) == 0) {
                mdebug2(FIM_IGNORE_ENTRY, file_name, syscheck.ignore[i]);
                return 1;
            }
            i++;
        }
    }

    // Check in the regex entry
    if (syscheck.ignore_regex) {
        int i = 0;
        while (syscheck.ignore_regex[i] != NULL) {
            if (OSMatch_Execute(file_name, strlen(file_name), syscheck.ignore_regex[i])) {
                mdebug2(FIM_IGNORE_SREGEX, file_name, syscheck.ignore_regex[i]->raw);
                return 1;
            }
            i++;
        }
    }

    return 0;
}


int fim_check_restrict (const char *file_name, OSMatch *restriction) {
    if (file_name == NULL) {
        merror(NULL_ERROR);
        return 1;
    }

    // Restrict file types
    if (restriction) {
        if (!OSMatch_Execute(file_name, strlen(file_name), restriction)) {
            mdebug2(FIM_FILE_IGNORE_RESTRICT, file_name, restriction->raw);
            return 1;
        }
    }

    return 0;
}


void free_file_data(fim_file_data * data) {
    if (!data) {
        return;
    }

#ifdef WIN32
    cJSON_Delete(data->perm_json);
#endif
    os_free(data->perm);
    os_free(data->attributes);
    os_free(data->uid);
    os_free(data->gid);
    os_free(data->user_name);
    os_free(data->group_name);

    os_free(data);
}

void fim_diff_folder_size() {
    char *diff_local;

    os_malloc(strlen(DIFF_DIR) + strlen("/local") + 1, diff_local);

    snprintf(diff_local, strlen(DIFF_DIR) + strlen("/local") + 1, "%s/local", DIFF_DIR);

    if (IsDir(diff_local) == 0) {
        syscheck.diff_folder_size = DirSize(diff_local) / 1024;
    }

    os_free(diff_local);
}

void update_wildcards_config() {
    OSList *removed_entries = NULL;
    OSListNode *node_it;
    OSListNode *aux_it;
    directory_t *dir_it;
    directory_t *new_entry;
    char **paths;

    if (syscheck.wildcards == NULL || syscheck.directories == NULL) {
        return;
    }

    mdebug2(FIM_WILDCARDS_UPDATE_START);
    w_rwlock_wrlock(&syscheck.directories_lock);

    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        dir_it->is_expanded = 0;
    }

    OSList_foreach(node_it, syscheck.wildcards) {
        dir_it = node_it->data;
        paths = expand_wildcards(dir_it->path);

        if (paths == NULL) {
            continue;
        }

        for (int i = 0; paths[i]; i++) {
            new_entry = fim_copy_directory(dir_it);
            os_free(new_entry->path);

            new_entry->path = paths[i];
#ifdef WIN32
            str_lowercase(new_entry->path);
#endif
            new_entry->is_expanded = 1;

            if (new_entry->diff_size_limit == -1) {
                new_entry->diff_size_limit = syscheck.file_size_limit;
            }

            fim_insert_directory(syscheck.directories, new_entry);
        }
        os_free(paths);
    }

    removed_entries = OSList_Create();
    if (removed_entries == NULL) {
        merror(MEM_ERROR, errno, strerror(errno));
        w_rwlock_unlock(&syscheck.directories_lock);
        return;
    }
    OSList_SetFreeDataPointer(removed_entries, (void (*)(void *))free_directory);

    node_it = OSList_GetFirstNode(syscheck.directories);
    while (node_it != NULL) {
        dir_it = node_it->data;
        if (dir_it->is_wildcard && dir_it->is_expanded == 0) {
#if INOTIFY_ENABLED
            if (FIM_MODE(dir_it->options) == FIM_REALTIME) {
                fim_realtime_delete_watches(dir_it);
            }
#endif
#if ENABLE_AUDIT
            if ((FIM_MODE(dir_it->options) == FIM_WHODATA) && (dir_it->options & AUDIT_DRIVER)) {
                remove_audit_rule_syscheck(dir_it->path);
            }
#endif
            // Inserting like this will cause the new list to have the order reversed to the one in syscheck.directories
            // This will cause the following loop to delete "inner" directories before "outer" ones
            OSList_PushData(removed_entries, dir_it);

            // Delete node
            aux_it = OSList_GetNext(syscheck.directories, node_it);
            OSList_DeleteThisNode(syscheck.directories, node_it);
            node_it = aux_it;
        } else {
            node_it = OSList_GetNext(syscheck.directories, node_it);
        }
    }

    w_rwlock_unlock(&syscheck.directories_lock);

    OSList_foreach(node_it, removed_entries) {
        dir_it = node_it->data;
        fim_process_wildcard_removed(dir_it);
        mdebug2(FIM_WILDCARDS_REMOVE_DIRECTORY, dir_it->path);
    }
    OSList_Destroy(removed_entries);

    mdebug2(FIM_WILDCARDS_UPDATE_FINALIZE);
}

// LCOV_EXCL_START
void fim_print_info(struct timespec start, struct timespec end, clock_t cputime_start) {
    mdebug1(FIM_RUNNING_SCAN,
            time_diff(&start, &end),
            (double)(clock() - cputime_start) / CLOCKS_PER_SEC);

#ifdef WIN32
    mdebug1(FIM_ENTRIES_INFO, fim_db_get_count_file_entry());
    mdebug1(FIM_REGISTRY_ENTRIES_INFO, fim_db_get_count_registry_key());
    mdebug1(FIM_REGISTRY_VALUES_ENTRIES_INFO, fim_db_get_count_registry_data());
#else
    unsigned inode_items = 0;
    unsigned inode_paths = 0;

    inode_items = fim_db_get_count_file_inode();
    inode_paths = fim_db_get_count_file_entry();

    mdebug1(FIM_INODES_INFO, inode_items, inode_paths);
#endif

    return;
}

char *fim_get_real_path(const directory_t *dir) {
    char *real_path = NULL;

#ifndef WIN32
    w_mutex_lock(&syscheck.fim_symlink_mutex);

    //Create a safe copy of the path to be used by other threads.
    if ((dir->options & CHECK_FOLLOW) == 0) {
        os_strdup(dir->path, real_path);
    } else if (dir->symbolic_links) {
        os_strdup(dir->symbolic_links, real_path);
    } else if (IsLink(dir->path) == 0) { // Broken link
        os_strdup("", real_path);
    } else {
        os_strdup(dir->path, real_path);
    }

    w_mutex_unlock(&syscheck.fim_symlink_mutex);
#else // WIN32
    os_strdup(dir->path, real_path);
#endif

    return real_path;
}

// Sleep during rt_delay milliseconds

void fim_rt_delay() {
    if (syscheck.rt_delay){
#ifdef WIN32
        Sleep(syscheck.rt_delay);
#else
        struct timeval timeout = {0, syscheck.rt_delay * 1000};
        select(0, NULL, NULL, NULL, &timeout);
#endif
    }
}

// LCOV_EXCL_STOP
