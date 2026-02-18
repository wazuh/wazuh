/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cJSON.h>
#include "file.h"
#include "debug_op.h"
#include "fimCommonDefs.h"
#include "shared.h"
#include "syscheck.h"
#include "syscheck-config.h"
#include "db.h"
#include "md5_op.h"
#include "sha1_op.h"
#include "agent_sync_protocol_c_interface.h"
#include "schemaValidator_c.h"

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "../../../unit_tests/wrappers/windows/stat64_wrappers.h"
#endif
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

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

cJSON* build_stateful_event_file(const char* path, const char* sha1_hash, const uint64_t document_version, const cJSON *dbsync_event, const fim_file_data *file_data, const OSList *directories_list){
    const directory_t* config = fim_configuration_directory(path, true, directories_list);

    // If config is NULL, we cannot proceed as fim_attributes_json requires it
    if (config == NULL) {
        merror("Failed to get configuration for path: %s", path);
        return NULL;
    }

    cJSON* stateful_event = cJSON_CreateObject();
    if (stateful_event == NULL) {
        return NULL;
    }

    // File
    cJSON* file_stateful = fim_attributes_json(dbsync_event, file_data, config);
    cJSON_AddItemToObject(stateful_event, "file", file_stateful);
#ifdef WIN32
     char *utf8_path = auto_to_utf8(path);
     if (utf8_path) {
        cJSON_AddStringToObject(file_stateful, "path", utf8_path);
        os_free(utf8_path);
     } else {
        cJSON_AddStringToObject(file_stateful, "path", path);
     }
 #else
     cJSON_AddStringToObject(file_stateful, "path", path);
 #endif

    // Checksum
    cJSON* checksum = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "checksum", checksum);
    cJSON* hash = cJSON_CreateObject();
    cJSON_AddItemToObject(checksum, "hash", hash);
    cJSON_AddStringToObject(hash, "sha1", sha1_hash);

    // State
    cJSON* state = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "state", state);
    char modified_at_time[32];
    get_iso8601_utc_time(modified_at_time, sizeof(modified_at_time));
    cJSON_AddStringToObject(state, "modified_at", modified_at_time);
    cJSON_AddNumberToObject(state, "document_version", document_version);

    return stateful_event;
}

// DBSync Callback

/**
 * @brief Handle delete events for files under paths that were removed from configuration.
 *
 * When a path is removed from the FIM configuration, files that were previously
 * monitored under that path need to generate delete events even though we no
 * longer have the configuration available. This function creates minimal
 * stateless and stateful delete events using only the information available
 * from the database.
 *
 * @param path The file path being deleted.
 * @param result_json Data from dbsync containing checksum and version.
 * @param txn_context Transaction context with event metadata.
 */
STATIC void handle_orphaned_delete(const char* path,
                                   const cJSON* result_json,
                                   callback_ctx* txn_context) {
    cJSON* stateless_event = NULL;
    cJSON* stateful_event = NULL;
    char iso_time[32];

    mdebug1("Generating delete event for orphaned file '%s' (path removed from configuration)", path);

    // Clean up any diff files that may exist for this path
    // Safe to call unconditionally - returns gracefully if no diff files exist
    fim_diff_process_delete_file(path);

    // Get checksum from result_json (file's SHA1 hash from database)
    cJSON* checksum_json = cJSON_GetObjectItem(result_json, "checksum");
    if (checksum_json == NULL) {
        mdebug1("Couldn't find checksum for orphaned delete '%s'", path);
        return;
    }
    char* sha1_checksum = cJSON_GetStringValue(checksum_json);
    if (sha1_checksum == NULL) {
        mdebug1("Invalid checksum value for orphaned delete '%s'", path);
        return;
    }

    // Get version from result_json (for DELETED events, version is at top level)
    cJSON* version_json = cJSON_GetObjectItem(result_json, "version");
    if (version_json == NULL) {
        mdebug1("Couldn't find version for orphaned delete '%s'", path);
        return;
    }
    uint64_t document_version = (uint64_t)version_json->valueint;

    // Build minimal stateless event
    stateless_event = cJSON_CreateObject();
    if (stateless_event == NULL) {
        return;
    }

    cJSON_AddStringToObject(stateless_event, "collector", "file");
    cJSON_AddStringToObject(stateless_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(stateless_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", FIM_EVENT_TYPE_ARRAY[FIM_DELETE]);

    cJSON* file_stateless = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "file", file_stateless);

#ifdef WIN32
    char* utf8_path = auto_to_utf8(path);
    if (utf8_path) {
        cJSON_AddStringToObject(file_stateless, "path", utf8_path);
        os_free(utf8_path);
    } else {
        cJSON_AddStringToObject(file_stateless, "path", path);
    }
#else
    cJSON_AddStringToObject(file_stateless, "path", path);
#endif

    cJSON_AddStringToObject(file_stateless, "mode", FIM_EVENT_MODE[txn_context->event->mode]);

    // Send stateless event if enabled
    if (notify_scan != 0 && txn_context->event->report_event) {
        send_syscheck_msg(stateless_event);
    }

    cJSON_Delete(stateless_event);

    // Build minimal stateful event for sync
    stateful_event = cJSON_CreateObject();
    if (stateful_event == NULL) {
        return;
    }

    cJSON* file_stateful = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "file", file_stateful);

#ifdef WIN32
    utf8_path = auto_to_utf8(path);
    if (utf8_path) {
        cJSON_AddStringToObject(file_stateful, "path", utf8_path);
        os_free(utf8_path);
    } else {
        cJSON_AddStringToObject(file_stateful, "path", path);
    }
#else
    cJSON_AddStringToObject(file_stateful, "path", path);
#endif

    cJSON* checksum_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "checksum", checksum_obj);
    cJSON* hash_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(checksum_obj, "hash", hash_obj);
    cJSON_AddStringToObject(hash_obj, "sha1", sha1_checksum);

    cJSON* state_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "state", state_obj);
    char modified_at_time[32];
    get_iso8601_utc_time(modified_at_time, sizeof(modified_at_time));
    cJSON_AddStringToObject(state_obj, "modified_at", modified_at_time);
    cJSON_AddNumberToObject(state_obj, "document_version", (double)document_version);

    // Compute SHA1 of path for sync ID
    char file_path_sha1[FILE_PATH_SHA1_BUFFER_SIZE] = {0};
    OS_SHA1_Str(path, -1, file_path_sha1);

    // Validate and persist the orphaned delete event
    // Note: For orphaned deletes, we don't mark for deletion from DBSync since the item is already deleted
    char item_desc[PATH_MAX + 32];
    snprintf(item_desc, sizeof(item_desc), "file %s", path);

    cJSON* sync_json = cJSON_GetObjectItem(result_json, "sync");
    if (sync_json == NULL) {
        mdebug1("Couldn't find sync for orphaned delete '%s'", path);
        return;
    }
    int sync_value = (int)cJSON_GetNumberValue(sync_json);
    validate_and_persist_fim_event(stateful_event, file_path_sha1, OPERATION_DELETE,
                                    FIM_FILES_SYNC_INDEX, document_version,
                                    item_desc, false, NULL, NULL, sync_value);

    cJSON_Delete(stateful_event);
}

/**
 * @brief File callback.
 *
 * @param resultType Action performed by DBSync (INSERTED|MODIFIED|DELETED|MAXROWS)
 * @param result_json Data returned by dbsync in JSON format.
 * @param user_data File transaction context.
 */
STATIC void transaction_callback(ReturnTypeCallback resultType,
                                 const cJSON* result_json,
                                 void* user_data) {
    cJSON* stateless_event = NULL;
    cJSON *json_path = NULL;
    cJSON* old_data = NULL;
    cJSON* old_attributes = NULL;
    cJSON* changed_attributes = NULL;
    char *diff = NULL;
    char *path = NULL;
    char iso_time[32];
    Operation_t sync_operation = OPERATION_NO_OP;
    int sync_flag = 1;

    callback_ctx *txn_context = (callback_ctx *) user_data;

    // In case of deletions, entry is NULL, so we need to get the path from the json event
    if (txn_context->entry == NULL) {
        if (json_path = cJSON_GetObjectItem(result_json, "path"), json_path == NULL) {
            goto end;
        }
        path = cJSON_GetStringValue(json_path);
    } else {
        path = txn_context->entry->file_entry.path;
    }

    // Extract version early so it's available for deferred sync items
    cJSON *version_aux = NULL;
    cJSON *new_data = cJSON_GetObjectItem(result_json, "new");
    if (new_data != NULL) {
        // For MODIFIED events, version is in the "new" object
        version_aux = cJSON_GetObjectItem(new_data, "version");
    } else {
        // For INSERTED/DELETED events, version is at the top level
        version_aux = cJSON_GetObjectItem(result_json, "version");
    }

    uint64_t document_version = 0;
    if (version_aux != NULL) {
        document_version = (uint64_t)version_aux->valueint;
    }

    if (txn_context->config == NULL) {
        // For DELETE events, don't log "not found" since path may have been removed from config
        txn_context->config = fim_configuration_directory(path, resultType != DELETED, syscheck.directories);
        if (txn_context->config == NULL) {
            // For DELETE events of orphaned files (path removed from config),
            // generate minimal delete events without requiring configuration
            if (resultType == DELETED) {
                handle_orphaned_delete(path, result_json, txn_context);
            }
            goto end;
        }
    }

    if (txn_context->config->options & CHECK_SEECHANGES && resultType != DELETED) {
        diff = fim_file_diff(path, txn_context->config);
    }

    switch (resultType) {
        case INSERTED:
            txn_context->event->type = FIM_ADD;
            sync_operation = OPERATION_CREATE;
            // For CREATE events: determine if within limit and defer sync flag update
            if (syscheck.file_limit > 0) {
                sync_flag = (synced_docs_files < syscheck.file_limit) ? 1 : 0;
                mdebug2("INSERTED: synced_docs_files=%d, file_limit=%d, sync_flag=%d, path=%s",
                        synced_docs_files, syscheck.file_limit, sync_flag, path);
            } else {
                sync_flag = 1;
                mdebug2("INSERTED: file_limit=0 (unlimited), sync_flag=1, path=%s", path);
            }
            // Add to deferred list if sync_flag should be 1
            if (sync_flag == 1 && txn_context->pending_sync_updates != NULL) {
                synced_docs_files++;
                cJSON* sync_item = cJSON_CreateObject();
                if (sync_item != NULL) {
                    cJSON_AddStringToObject(sync_item, "path", path);
                    cJSON_AddNumberToObject(sync_item, "version", (double)document_version);
                    add_pending_sync_item(txn_context->pending_sync_updates, sync_item, 1);
                    cJSON_Delete(sync_item);
                } else {
                    merror("Failed to create cJSON object for deferred sync item");
                }
            }
            break;

        case MODIFIED:
            txn_context->event->type = FIM_MODIFICATION;
            sync_operation = OPERATION_MODIFY;

            // Get the old sync flag value to track synced documents and determine if promotion is needed
            old_data = cJSON_GetObjectItem(result_json, "old");
            cJSON *sync_json = cJSON_GetObjectItem(old_data, "sync");
            if (sync_json != NULL && cJSON_IsNumber(sync_json)) {
                sync_flag = sync_json->valueint;
                // NOTE: We don't add to deferred list here because syncRow preserves the sync flag
                // when it's not in the input data. The sync flag is already 1 after the transaction.
            }

            if (sync_flag == 0 && syscheck.file_limit > 0) { // Promote
                if (synced_docs_files < syscheck.file_limit) {
                    synced_docs_files++;
                    cJSON* sync_item = cJSON_CreateObject();
                    if (sync_item != NULL) {
                        cJSON_AddStringToObject(sync_item, "path", path);
                        cJSON_AddNumberToObject(sync_item, "version", (double)document_version);
                        add_pending_sync_item(txn_context->pending_sync_updates, sync_item, 1);
                        cJSON_Delete(sync_item);
                        sync_flag = 1;
                    } else {
                        merror("Failed to create cJSON object for deferred sync item");
                    }
                }
            }
            break;

        case DELETED:
            if (txn_context->config->options & CHECK_SEECHANGES) {
                fim_diff_process_delete_file(path);
            }
            txn_context->event->type = FIM_DELETE;
            sync_operation = OPERATION_DELETE;
            // For DELETE events: entry is NULL, read sync flag from DB result
            {
                cJSON *sync_json = cJSON_GetObjectItem(result_json, "sync");
                if (sync_json != NULL && cJSON_IsNumber(sync_json)) {
                    sync_flag = sync_json->valueint;
                    if (sync_flag == 1) {
                        synced_docs_files--;
                    }
                }
            }
            break;

        case MAX_ROWS:
            mdebug1("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", path);

        // Fallthrough
        default:
            goto end;
            break;
    }

    stateless_event = cJSON_CreateObject();
    if (stateless_event == NULL) {
        goto end; // LCOV_EXCL_LINE
    }

    cJSON_AddStringToObject(stateless_event, "collector", "file");
    cJSON_AddStringToObject(stateless_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(stateless_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", FIM_EVENT_TYPE_ARRAY[txn_context->event->type]);

    cJSON* file_stateless = fim_attributes_json(result_json, (txn_context->entry != NULL) ? txn_context->entry->file_entry.data : NULL, txn_context->config);
    cJSON_AddItemToObject(data, "file", file_stateless);

#ifdef WIN32
     char *utf8_path = auto_to_utf8(path);
     if (utf8_path) {
        cJSON_AddStringToObject(file_stateless, "path", utf8_path);
        os_free(utf8_path);
     } else {
        cJSON_AddStringToObject(file_stateless, "path", path);
     }
 #else
     cJSON_AddStringToObject(file_stateless, "path", path);
 #endif

    cJSON_AddStringToObject(file_stateless, "mode", FIM_EVENT_MODE[txn_context->event->mode]);

    old_data = cJSON_GetObjectItem(result_json, "old");
    if (old_data != NULL) {
        old_attributes = cJSON_CreateObject();
        changed_attributes = cJSON_CreateArray();
        cJSON_AddItemToObject(file_stateless, "previous", old_attributes);
        cJSON_AddItemToObject(event, "changed_fields", changed_attributes);

        fim_calculate_dbsync_difference(txn_context->config,
                                        old_data,
                                        changed_attributes,
                                        old_attributes);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            mdebug2(FIM_EMPTY_CHANGED_ATTRIBUTES, path);
            goto end;
        }
    }

    if (diff != NULL && resultType == MODIFIED) {
        cJSON_AddStringToObject(file_stateless, "content_changes", diff);
    }

    if (txn_context->event->w_evt) {
        cJSON_AddItemToObject(file_stateless, "audit", fim_audit_json(txn_context->event->w_evt));
    }

    if (txn_context->config->tag != NULL) {
        cJSON_AddStringToObject(file_stateless, "tags", txn_context->config->tag);
    }

    if (notify_scan != 0 && txn_context->event->report_event) {
        send_syscheck_msg(stateless_event);
    }

    char* sha1_checksum;
    if (txn_context->entry != NULL && txn_context->entry->file_entry.data != NULL) {
        sha1_checksum = txn_context->entry->file_entry.data->checksum;
    } else {
        cJSON *aux = cJSON_GetObjectItem(result_json, "checksum");
        if (aux != NULL) {
            sha1_checksum = cJSON_GetStringValue(aux);
        } else {
            mdebug1("Couldn't find checksum for '%s", path);
            goto end; // LCOV_EXCL_LINE
        }
    }

    if (document_version == 0) {
        mdebug1("Couldn't find version for '%s'", path);
        goto end; // LCOV_EXCL_LINE
    }

    char file_path_sha1[FILE_PATH_SHA1_BUFFER_SIZE] = {0};
    OS_SHA1_Str(path, -1, file_path_sha1);

    cJSON* stateful_event = build_stateful_event_file(path, sha1_checksum, document_version, result_json, (txn_context->entry != NULL) ? txn_context->entry->file_entry.data : NULL, syscheck.directories);
    if (!stateful_event) {
        merror("Couldn't create stateful event for %s", path);
        goto end; // LCOV_EXCL_LINE
    }

    // Validate and persist the event
    // For INSERT/MODIFY operations that fail validation, mark for deletion from DBSync
    char item_desc[PATH_MAX + 32];
    snprintf(item_desc, sizeof(item_desc), "file %s", path);

    char* path_copy = (resultType == INSERTED || resultType == MODIFIED) ? strdup(path) : NULL;
    bool mark_for_deletion = (resultType == INSERTED || resultType == MODIFIED) && path_copy != NULL;

    bool validation_passed = validate_and_persist_fim_event(stateful_event, file_path_sha1, sync_operation,
                                                             FIM_FILES_SYNC_INDEX, document_version,
                                                             item_desc, mark_for_deletion,
                                                             txn_context->failed_paths, path_copy, sync_flag);

    // If validation passed, we need to free path_copy (it wasn't added to the list)
    // If validation failed, path_copy was added to the list and will be freed later
    if (validation_passed && path_copy) {
        os_free(path_copy);
    }

    cJSON_Delete(stateful_event);

end:
    os_free(diff);
    cJSON_Delete(stateless_event);
}

// Callback
void fim_db_remove_entry(void * data, void * ctx)
{
    char *path = (char *)data;
    callback_ctx *ctx_data = (struct callback_ctx *)ctx;

    fim_generate_delete_event(path, ctx_data->event, ctx_data->config);
}

// Callback
void fim_db_process_missing_entry(void * data, void * ctx)
{
    fim_entry *new_entry = (fim_entry *)data;
    struct callback_ctx *ctx_data = (struct callback_ctx *)ctx;

    fim_checker(new_entry->file_entry.path, ctx_data->event, NULL, NULL, NULL);
}

// Callback
void fim_db_remove_validated_path(void * data, void * ctx)
{
    char *path = (char *)data;
    struct callback_ctx *ctx_data = (struct callback_ctx *)ctx;

    directory_t *validated_configuration = fim_configuration_directory(path, true, syscheck.directories);

    if (validated_configuration == ctx_data->config)
    {
        fim_generate_delete_event(path, ctx_data->event, ctx_data->config);
    }
}

directory_t *fim_configuration_directory(const char *key, bool notify_not_found, const OSList *directories_list) {
    char full_path[OS_SIZE_4096 + 1] = {'\0'};
    char full_entry[OS_SIZE_4096 + 1] = {'\0'};
    directory_t *dir_it = NULL;
    directory_t *dir = NULL;
    OSListNode *node_it;
    int top = 0;
    int match = 0;
    char *pathname = NULL;

    if (!key || *key == '\0') {
        return NULL;
    }

    if (!directories_list) {
        merror("fim_configuration_directory called with NULL directories_list");
        return NULL;
    }

#ifdef WIN32
     pathname = auto_to_ansi(key);
     if (!pathname) {
         return NULL;
     }
 #else
     os_strdup(key, pathname);
 #endif

    trail_path_separator(full_path, pathname, sizeof(full_path));

    OSList_foreach(node_it, (OSList *)directories_list) {
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

    if (dir == NULL && notify_not_found) {
        mdebug2(FIM_CONFIGURATION_NOTFOUND, "file", key);
    }

    os_free(pathname);
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

int fim_check_ignore (const char *file_name, mode_t path_type) {
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
                if (path_type == FIM_DIRECTORY && syscheck.ignore_regex[i]->raw[0] == '!') {
                    return 0;
                } else {
                    mdebug2(FIM_IGNORE_SREGEX, file_name, syscheck.ignore_regex[i]->raw);
                    return 1;
                }
            }
            i++;
        }
    }

    return 0;
}

int fim_check_restrict(const char *file_name, OSMatch *restriction) {
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

void fim_get_checksum(fim_file_data * data) {
    int size;
    char *checksum = NULL;

    size = snprintf(0,
            0,
            "%llu:%s:%s:%s:%s:%s:%s:%s:%lu:%llu:%s:%s:%s",
            data->size,
            data->path,
            data->permissions ? data->permissions : "",
            data->attributes ? data->attributes : "",
            data->uid ? data->uid : "",
            data->gid ? data->gid : "",
            data->owner ? data->owner : "",
            data->group ? data->group : "",
            data->mtime,
            data->inode,
            data->hash_md5,
            data->hash_sha1,
            data->hash_sha256);

    os_calloc(size + 1, sizeof(char), checksum);
    snprintf(checksum,
            size + 1,
            "%llu:%s:%s:%s:%s:%s:%s:%s:%lu:%llu:%s:%s:%s",
            data->size,
            data->path,
            data->permissions ? data->permissions : "",
            data->attributes ? data->attributes : "",
            data->uid ? data->uid : "",
            data->gid ? data->gid : "",
            data->owner ? data->owner : "",
            data->group ? data->group : "",
            data->mtime,
            data->inode,
            data->hash_md5,
            data->hash_sha1,
            data->hash_sha256);

    OS_SHA1_Str(checksum, -1, data->checksum);
    free(checksum);
}

void init_fim_data_entry(fim_file_data *data) {
    data->size = 0;
    data->path = NULL;
    data->permissions = NULL;
#ifdef WIN32
    data->perm_json = NULL;
#endif
    data->attributes = NULL;
    data->uid = NULL;
    data->gid = NULL;
    data->owner = NULL;
    data->group = NULL;
    data->mtime = 0;
    data->inode = 0;
    data->hash_md5[0] = '\0';
    data->hash_sha1[0] = '\0';
    data->hash_sha256[0] = '\0';
}

void free_file_data(fim_file_data * data) {
    if (!data) {
        return;
    }

#ifdef WIN32
    cJSON_Delete(data->perm_json);
#endif
    os_free(data->path);
    os_free(data->permissions);
    os_free(data->attributes);
    os_free(data->uid);
    os_free(data->gid);
    os_free(data->owner);
    os_free(data->group);

    os_free(data);
}

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
        data->permissions = cJSON_PrintUnformatted(data->perm_json);
#else
        data->permissions = agent_file_perm(statbuf->st_mode);
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
        data->owner = get_file_user(file, &data->uid);
    }
#else
    if (configuration->options & CHECK_OWNER) {
        char aux[OS_SIZE_64];
        snprintf(aux, OS_SIZE_64, "%u", statbuf->st_uid);
        os_strdup(aux, data->uid);

        data->owner = get_user(statbuf->st_uid);
    }

    if (configuration->options & CHECK_GROUP) {
        char aux[OS_SIZE_64];
        snprintf(aux, OS_SIZE_64, "%u", statbuf->st_gid);
        os_strdup(aux, data->gid);

        data->group = get_group(statbuf->st_gid);
    }
#endif

    snprintf(data->hash_md5, sizeof(os_md5), "%s", "d41d8cd98f00b204e9800998ecf8427e");
    snprintf(data->hash_sha1, sizeof(os_sha1), "%s", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    snprintf(data->hash_sha256, sizeof(os_sha256), "%s", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // We won't calculate hash for symbolic links, empty or large files
    if (S_ISREG(statbuf->st_mode) && (statbuf->st_size > 0 && (size_t)statbuf->st_size < syscheck.file_max_size) &&
        (configuration->options & (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM))) {
        if (OS_MD5_SHA1_SHA256_File(file, data->hash_md5, data->hash_sha1, data->hash_sha256,
                                    OS_BINARY, syscheck.file_max_size) < 0) {
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
    data->device = statbuf->st_dev;
    os_strdup(file, data->path);
    fim_get_checksum(data);

    return data;
}

void fim_checker(const char *path,
                 event_data_t *evt_data,
                 const directory_t *parent_configuration,
                 TXN_HANDLE dbsync_txn,
                 callback_ctx *ctx) {
    directory_t *configuration;
    int depth;

#ifdef WIN32
    // Ignore the recycle bin.
    if (check_removed_file(path)){
        return;
    }
#endif

    configuration = fim_configuration_directory(path, true, syscheck.directories);
    if (configuration == NULL) {
        return;
    }

    if (parent_configuration == NULL) {
        // First time entering
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
    if (w_lstat(path, &(evt_data->statbuf)) == -1) {
        if(errno != ENOENT) {
            mdebug1(FIM_STAT_FAILED, path, errno, strerror(errno));
            return;
        }

        // Delete alerts in scheduled scan is triggered in the transaction delete rows operation.
        if (evt_data->mode != FIM_SCHEDULED) {
            evt_data->type = FIM_DELETE;
            fim_generate_delete_event(path, evt_data, configuration);
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
    mode_t path_type = evt_data->statbuf.st_mode & S_IFMT;

    if (HasFilesystem(path, syscheck.skip_fs)) {
        return;
    }

    if (fim_check_ignore(path, path_type) == 1) {
        return;
    }

    switch (path_type) {
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
                  callback_ctx *ctx) {
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
    dp = wopendir(dir);

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

void fim_file(const char *path,
              const directory_t *configuration,
              event_data_t *evt_data,
              TXN_HANDLE txn_handle,
              callback_ctx *txn_context) {
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
        txn_context->entry = &new_entry;
        txn_context->config = configuration;

        fim_db_transaction_sync_row(txn_handle, &new_entry);

        free_file_data(new_entry.file_entry.data);
        txn_context->entry = NULL;
        txn_context->config = NULL;
    } else {
        OSList* failed_paths = OSList_Create();
        if (!failed_paths) {
            free_file_data(new_entry.file_entry.data);
            return;
        }
        OSList_SetFreeDataPointer(failed_paths, (void (*)(void *))free);

        callback_ctx ctx = {
            .event = evt_data,
            .config = configuration,
            .entry = &new_entry,
            .failed_paths = failed_paths
        };

        callback_context_t callback_data;
        callback_data.callback_txn = transaction_callback;
        callback_data.context = &ctx;

        fim_db_file_update(&new_entry, callback_data);

        // Delete files that failed schema validation (outside transaction)
        cleanup_failed_fim_files(failed_paths);
        OSList_Destroy(failed_paths);
        free_file_data(new_entry.file_entry.data);
    }
}

void fim_process_missing_entry(char * pathname, fim_event_mode mode, whodata_evt * w_evt) {
    directory_t *configuration = NULL;

    configuration = fim_configuration_directory(pathname, true, syscheck.directories);
    if (NULL == configuration) {
        return;
    }

    event_data_t evt_data = {
        .mode = mode,
        .w_evt = w_evt,
        .report_event = true,
        .type = FIM_DELETE
    };

    if (evt_data.mode != FIM_MODE(configuration->options)) {
        /* Don't send alert if received mode and mode in configuration aren't the same.
        Scheduled mode events must always be processed to preserve the state of the agent's DB.
        */
        return;
    }

    // We will first validate the file, so flag to_delete is false.
    // If the file is not found, then we will delete it from the DB.
    fim_handle_delete_by_path(pathname, &evt_data, configuration, false, true);
}

void fim_link_delete_range(directory_t *config) {
    char pattern[PATH_MAX] = {0};

    event_data_t evt_data = {
        .mode = FIM_SCHEDULED,
        .w_evt = NULL,
        .report_event = false,
        .type = FIM_DELETE
    };

    callback_ctx ctx = {
        .event = (event_data_t *)&evt_data,
        .config = config,
        .entry = NULL,
        .failed_paths = NULL
    };

    // Create the sqlite LIKE pattern.
    snprintf(pattern, PATH_MAX, "%s%c%%", config->symbolic_links, PATH_SEP);
    callback_context_t callback_data;
    callback_data.callback = fim_db_remove_validated_path;
    callback_data.context = &ctx;

    fim_db_file_pattern_search(pattern, callback_data);
}

void fim_generate_delete_event(const char *file_path,
                              const void *_evt_data,
                              const void *configuration){
    const directory_t *config = (const directory_t *)configuration;
    const event_data_t *evt_data = (const event_data_t *)_evt_data;

    fim_handle_delete_by_path(file_path, evt_data, config, true, false);
}

void fim_handle_delete_by_path(const char *path,
                               const event_data_t *evt_data,
                               const directory_t *config,
                               bool to_delete,
                               bool fallback_cb)
{
    callback_ctx ctx = {
        .event = (event_data_t *)evt_data,
        .config = config,
        .entry = NULL,
        .failed_paths = NULL
    };

    callback_context_t cb = {
        .context = &ctx
    };

    if (to_delete) {
        cb.callback_txn = transaction_callback;
    } else {
        cb.callback = fim_db_process_missing_entry;
    }

    if (fim_db_get_path(path, cb, to_delete) == FIMDB_OK) {
        return;
    }

    if (fallback_cb == true) {
        // File not found in DB: fallback to LIKE pattern ("path/%")
        char pattern[PATH_MAX] = {0};
        snprintf(pattern, PATH_MAX, "%s%c%%", path, PATH_SEP);

        cb.callback = fim_db_remove_entry;
        fim_db_file_pattern_search(pattern, cb);
    }
}

void fim_file_scan() {
    OSListNode *node_it;
    directory_t *dir_it;

    // Check if directories are configured - if syscheck.directories is NULL or empty,
    // but we have data in the database, we need to send DataClean for files index
    if (syscheck.directories == NULL || OSList_GetFirstNode(syscheck.directories) == NULL) {
        int files_count = fim_db_get_count_file_entry();

        if (files_count > 0) {
            mdebug1("No directory paths configured but database has %d files. Initiating DataClean for files.",
                    files_count);

            if (syscheck.sync_handle) {
                // Prepare indices vector for data clean notification
                const char* indices[1] = {FIM_FILES_SYNC_INDEX};
                size_t indices_count = 1;

                // Send DataClean notification for files index
                bool dataCleanSent = asp_notify_data_clean(syscheck.sync_handle, indices, indices_count);
                if (dataCleanSent) {
                    minfo("DataClean notification sent successfully for files index (all directory paths removed from configuration).");
                } else {
                    mwarn("DataClean notification failed for files index. Indexer may retain stale file data.");
                }

                // Clear file table from database
                fim_db_clean_file_table();
            } else {
                mdebug1("Sync protocol not initialized, cannot send DataClean notification for files.");
            }
        }
        return;
    }

    OSList* failed_paths = OSList_Create();
    if (!failed_paths) {
        merror("Failed to create failed_paths list for schema validation cleanup");
        return;
    }
    OSList_SetFreeDataPointer(failed_paths, (void (*)(void *))free);

    event_data_t evt_data = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };

    // Initialize pending sync updates list for sync flag updates after transaction commit
    OSList *pending_sync_updates = OSList_Create();
    if (!pending_sync_updates) {
        merror("Failed to create pending sync updates list");
        return;
    }
    OSList_SetFreeDataPointer(pending_sync_updates, free_pending_sync_item);

    callback_ctx txn_ctx = { .event = &evt_data, .entry = NULL, .config = NULL, .failed_paths = failed_paths, .pending_sync_updates = pending_sync_updates };

    TXN_HANDLE db_transaction_handle = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE, transaction_callback, &txn_ctx);
    if (db_transaction_handle == NULL) {
        merror(FIM_ERROR_TRANSACTION, FIMDB_FILE_TXN_TABLE);
        OSList_Destroy(failed_paths);
        OSList_Destroy(pending_sync_updates);
        return;
    }

    w_mutex_lock(&syscheck.fim_scan_mutex);
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

    fim_db_transaction_deleted_rows(db_transaction_handle, transaction_callback, &txn_ctx);

    // Delete files that failed schema validation (outside transaction)
    cleanup_failed_fim_files(failed_paths);
    OSList_Destroy(failed_paths);

    // Process pending sync flag updates now that transaction is committed
    process_pending_sync_updates(FIMDB_FILE_TABLE_NAME, pending_sync_updates);

    // Cleanup pending sync updates list
    OSList_Destroy(pending_sync_updates);
}
