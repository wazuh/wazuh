/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef WIN32

#include <cJSON.h>
#include "registry.h"
#include "shared.h"
#include "syscheck.h"
#include "syscheck-config.h"
#include "db.h"
#include "md5_op.h"
#include "sha1_op.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "agent_sync_protocol_c_interface.h"
#include "schemaValidator_c.h"

#ifdef WAZUH_UNIT_TESTING
#include "../../../unit_tests/wrappers/windows/winreg_wrappers.h"
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

/* Default values */
#define MAX_KEY_LENGTH 260
#define MAX_VALUE_NAME 16383

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

/**
 * @brief Get the abbreviation of the registry hive from the full path.
 *
 * @param path The full path of the registry key.
 * @return The abbreviation of the registry hive.
 */
STATIC const char* get_registry_hive_abbreviation(const char* path) {
    struct {
        const char *full;
        const char *abbr;
    } hives[] = {
        {"HKEY_CLASSES_ROOT", "HKCR"},
        {"HKEY_CURRENT_USER", "HKCU"},
        {"HKEY_LOCAL_MACHINE", "HKLM"},
        {"HKEY_USERS", "HKU"},
        {"HKEY_CURRENT_CONFIG", "HKCC"}
    };

    for (size_t i = 0; i < sizeof(hives)/sizeof(hives[0]); ++i) {
        size_t len = strlen(hives[i].full);
        if (strncmp(path, hives[i].full, len) == 0 &&
            (path[len] == '\\' || path[len] == '\0')) {
            return hives[i].abbr;
        }
    }

    return "";
}

/**
 * @brief Get the full registry key path without the hive abbreviation.
 *
 * @param path The full path of the registry key.
 * @return The full registry key path without the hive abbreviation.
 */
STATIC const char* get_registry_key(const char* path) {
    const char *prefixes[] = {
        "HKEY_CLASSES_ROOT\\",
        "HKEY_CURRENT_USER\\",
        "HKEY_LOCAL_MACHINE\\",
        "HKEY_USERS\\",
        "HKEY_CURRENT_CONFIG\\"
    };

    for (size_t i = 0; i < sizeof(prefixes)/sizeof(prefixes[0]); ++i) {
        size_t len = strlen(prefixes[i]);
        if (strncmp(path, prefixes[i], len) == 0) {
            return path + len;
        }
    }

    return path;
}

cJSON* build_stateful_event_registry(const char* path, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, cJSON* registry_stateful){
    cJSON* stateful_event = cJSON_CreateObject();
    if (stateful_event == NULL) {
        return NULL;
    }
    cJSON_AddItemToObject(stateful_event, "registry", registry_stateful);

    char *utf8_path = auto_to_utf8(path);
    cJSON_AddStringToObject(registry_stateful, "path", utf8_path ? utf8_path : path);
    os_free(utf8_path);

    const char *hive = get_registry_hive_abbreviation(path);
    const char *key = get_registry_key(path);

    if (strlen(hive) > 0 && strlen(key) > 0) {
        size_t full_key_len = strlen(hive) + 1 + strlen(key) + 1;
        char *full_key = NULL;
        os_malloc(full_key_len, full_key);
        snprintf(full_key, full_key_len, "%s\\%s", hive, key);
        char *utf8_full_key = auto_to_utf8(full_key);
        cJSON_AddStringToObject(registry_stateful, "key", utf8_full_key ? utf8_full_key : full_key);
        os_free(utf8_full_key);
        os_free(full_key);
    } else {
        char *utf8_key_path = auto_to_utf8(path);
        cJSON_AddStringToObject(registry_stateful, "key", utf8_key_path ? utf8_key_path : path);
        os_free(utf8_key_path);
    }
    cJSON_AddStringToObject(registry_stateful, "hive", hive);

    cJSON_AddStringToObject(registry_stateful, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");

    cJSON* checksum = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "checksum", checksum);
    cJSON* hash = cJSON_CreateObject();
    cJSON_AddItemToObject(checksum, "hash", hash);

    cJSON* state = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "state", state);
    cJSON_AddStringToObject(hash, "sha1", sha1_hash);

    char modified_at_time[32];
    get_iso8601_utc_time(modified_at_time, sizeof(modified_at_time));
    cJSON_AddStringToObject(state, "modified_at", modified_at_time);

    cJSON_AddNumberToObject(state, "document_version", document_version);

    return stateful_event;
}


cJSON* build_stateful_event_registry_key(const char* path, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, fim_registry_key *registry_data){
    const registry_t* config = fim_registry_configuration(path, arch);
    cJSON* registry_stateful = fim_registry_key_attributes_json(dbsync_event, registry_data, config);

    cJSON* stateful_event = build_stateful_event_registry(path, sha1_hash, document_version, arch, dbsync_event, registry_stateful);

    if (!stateful_event) {
        if (registry_stateful) {
            cJSON_Delete(registry_stateful);
        }
        return NULL;
    }
    return stateful_event;
}

cJSON* build_stateful_event_registry_value(const char* path, const char* value, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, fim_registry_value_data *registry_data){
    const registry_t* config = fim_registry_configuration(path, arch);
    cJSON* registry_stateful = fim_registry_value_attributes_json(dbsync_event, registry_data, config);

    char *utf8_value = auto_to_utf8(value);
    cJSON_AddStringToObject(registry_stateful, "value", utf8_value ? utf8_value : value);
    os_free(utf8_value);

    cJSON* stateful_event = build_stateful_event_registry(path, sha1_hash, document_version, arch, dbsync_event, registry_stateful);

    return stateful_event;
}

/**
 * @brief Handle delete events for registry keys under paths that were removed from configuration.
 *
 * When a registry path is removed from the FIM configuration, keys that were previously
 * monitored under that path need to generate delete events even though we no
 * longer have the configuration available. This function creates minimal
 * stateless and stateful delete events using only the information available
 * from the database.
 *
 * @param path The registry key path being deleted.
 * @param arch The architecture (ARCH_32BIT or ARCH_64BIT).
 * @param result_json Data from dbsync containing checksum and version.
 * @param txn_context Transaction context with event metadata.
 */
STATIC void handle_orphaned_delete_registry_key(const char* path,
                                                 int arch,
                                                 const cJSON* result_json,
                                                 fim_key_txn_context_t* txn_context) {
    cJSON* stateless_event = NULL;
    cJSON* stateful_event = NULL;
    char iso_time[32];

    mdebug1("Generating delete event for orphaned registry key '%s' (path removed from configuration)", path);

    // Get checksum from result_json
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

    cJSON_AddStringToObject(stateless_event, "collector", "registry_key");
    cJSON_AddStringToObject(stateless_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(stateless_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", FIM_EVENT_TYPE_ARRAY[FIM_DELETE]);

    cJSON* registry_stateless = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "registry", registry_stateless);

    char* utf8_path = auto_to_utf8(path);
    cJSON_AddStringToObject(registry_stateless, "path", utf8_path ? utf8_path : path);
    os_free(utf8_path);

    const char* hive = get_registry_hive_abbreviation(path);
    const char* key = get_registry_key(path);

    if (strlen(hive) > 0 && strlen(key) > 0) {
        size_t full_key_len = strlen(hive) + 1 + strlen(key) + 1;
        char* full_key = NULL;
        os_malloc(full_key_len, full_key);
        snprintf(full_key, full_key_len, "%s\\%s", hive, key);
        char* utf8_full_key = auto_to_utf8(full_key);
        cJSON_AddStringToObject(registry_stateless, "key", utf8_full_key ? utf8_full_key : full_key);
        os_free(utf8_full_key);
        os_free(full_key);
    } else {
        char* utf8_key_path = auto_to_utf8(path);
        cJSON_AddStringToObject(registry_stateless, "key", utf8_key_path ? utf8_key_path : path);
        os_free(utf8_key_path);
    }
    cJSON_AddStringToObject(registry_stateless, "hive", hive);

    cJSON_AddStringToObject(registry_stateless, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");
    cJSON_AddStringToObject(registry_stateless, "mode", FIM_EVENT_MODE[txn_context->evt_data->mode]);

    // Send stateless event if enabled
    if (notify_scan != 0 && txn_context->evt_data->report_event) {
        send_syscheck_msg(stateless_event);
    }

    cJSON_Delete(stateless_event);

    // Build minimal stateful event for sync
    stateful_event = cJSON_CreateObject();
    if (stateful_event == NULL) {
        return;
    }

    cJSON* registry_stateful = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "registry", registry_stateful);

    utf8_path = auto_to_utf8(path);
    cJSON_AddStringToObject(registry_stateful, "path", utf8_path ? utf8_path : path);
    os_free(utf8_path);

    if (strlen(hive) > 0 && strlen(key) > 0) {
        size_t full_key_len = strlen(hive) + 1 + strlen(key) + 1;
        char* full_key = NULL;
        os_malloc(full_key_len, full_key);
        snprintf(full_key, full_key_len, "%s\\%s", hive, key);
        char* utf8_full_key = auto_to_utf8(full_key);
        cJSON_AddStringToObject(registry_stateful, "key", utf8_full_key ? utf8_full_key : full_key);
        os_free(utf8_full_key);
        os_free(full_key);
    } else {
        char* utf8_key_path = auto_to_utf8(path);
        cJSON_AddStringToObject(registry_stateful, "key", utf8_key_path ? utf8_key_path : path);
        os_free(utf8_key_path);
    }
    cJSON_AddStringToObject(registry_stateful, "hive", hive);
    cJSON_AddStringToObject(registry_stateful, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");

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

    // Compute SHA1 of arch:path for sync ID
    char id_source_string[OS_MAXSTR] = {0};
    snprintf(id_source_string, OS_MAXSTR - 1, "%d:%s", arch, path);

    char registry_key_sha1[FILE_PATH_SHA1_BUFFER_SIZE] = {0};
    OS_SHA1_Str(id_source_string, -1, registry_key_sha1);

    // Read sync flag from result_json
    int sync_flag = 0;
    cJSON* sync_json = cJSON_GetObjectItem(result_json, "sync");
    if (sync_json != NULL && cJSON_IsNumber(sync_json)) {
        sync_flag = sync_json->valueint;
    }

    // Validate and persist the orphaned delete event
    // Note: For orphaned deletes, we don't mark for deletion from DBSync since the item is already deleted
    char item_desc[PATH_MAX + 64];
    snprintf(item_desc, sizeof(item_desc), "registry key %s", path);
    validate_and_persist_fim_event(stateful_event, registry_key_sha1, OPERATION_DELETE,
                                    FIM_REGISTRY_KEYS_SYNC_INDEX, document_version,
                                    item_desc, false, NULL, NULL, sync_flag);

    cJSON_Delete(stateful_event);
}

/**
 * @brief Handle delete events for registry values under paths that were removed from configuration.
 *
 * When a registry path is removed from the FIM configuration, values that were previously
 * monitored under that path need to generate delete events even though we no
 * longer have the configuration available. This function creates minimal
 * stateless and stateful delete events using only the information available
 * from the database.
 *
 * @param path The registry key path where the value resides.
 * @param value The registry value name being deleted.
 * @param arch The architecture (ARCH_32BIT or ARCH_64BIT).
 * @param result_json Data from dbsync containing checksum and version.
 * @param txn_context Transaction context with event metadata.
 */
STATIC void handle_orphaned_delete_registry_value(const char* path,
                                                   const char* value,
                                                   int arch,
                                                   const cJSON* result_json,
                                                   fim_val_txn_context_t* txn_context) {
    cJSON* stateless_event = NULL;
    cJSON* stateful_event = NULL;
    char iso_time[32];

    mdebug1("Generating delete event for orphaned registry value '%s\\%s' (path removed from configuration)", path, value);

    // Get checksum from result_json
    cJSON* checksum_json = cJSON_GetObjectItem(result_json, "checksum");
    if (checksum_json == NULL) {
        mdebug1("Couldn't find checksum for orphaned delete '%s\\%s'", path, value);
        return;
    }
    char* sha1_checksum = cJSON_GetStringValue(checksum_json);
    if (sha1_checksum == NULL) {
        mdebug1("Invalid checksum value for orphaned delete '%s\\%s'", path, value);
        return;
    }

    // Get version from result_json (for DELETED events, version is at top level)
    cJSON* version_json = cJSON_GetObjectItem(result_json, "version");
    if (version_json == NULL) {
        mdebug1("Couldn't find version for orphaned delete '%s\\%s'", path, value);
        return;
    }
    uint64_t document_version = (uint64_t)version_json->valueint;

    // Build minimal stateless event
    stateless_event = cJSON_CreateObject();
    if (stateless_event == NULL) {
        return;
    }

    cJSON_AddStringToObject(stateless_event, "collector", "registry_value");
    cJSON_AddStringToObject(stateless_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(stateless_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", FIM_EVENT_TYPE_ARRAY[FIM_DELETE]);

    cJSON* registry_stateless = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "registry", registry_stateless);

    char* utf8_path = auto_to_utf8(path);
    cJSON_AddStringToObject(registry_stateless, "path", utf8_path ? utf8_path : path);
    os_free(utf8_path);

    const char* hive = get_registry_hive_abbreviation(path);
    const char* key = get_registry_key(path);

    if (strlen(hive) > 0 && strlen(key) > 0) {
        size_t full_key_len = strlen(hive) + 1 + strlen(key) + 1;
        char* full_key = NULL;
        os_malloc(full_key_len, full_key);
        snprintf(full_key, full_key_len, "%s\\%s", hive, key);
        char* utf8_full_key = auto_to_utf8(full_key);
        cJSON_AddStringToObject(registry_stateless, "key", utf8_full_key ? utf8_full_key : full_key);
        os_free(utf8_full_key);
        os_free(full_key);
    } else {
        char* utf8_key_path = auto_to_utf8(path);
        cJSON_AddStringToObject(registry_stateless, "key", utf8_key_path ? utf8_key_path : path);
        os_free(utf8_key_path);
    }
    cJSON_AddStringToObject(registry_stateless, "hive", hive);

    cJSON_AddStringToObject(registry_stateless, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");

    char* utf8_value = auto_to_utf8(value);
    cJSON_AddStringToObject(registry_stateless, "value", utf8_value ? utf8_value : value);
    os_free(utf8_value);

    cJSON_AddStringToObject(registry_stateless, "mode", FIM_EVENT_MODE[txn_context->evt_data->mode]);

    // Send stateless event if enabled
    if (notify_scan != 0 && txn_context->evt_data->report_event) {
        send_syscheck_msg(stateless_event);
    }

    cJSON_Delete(stateless_event);

    // Build minimal stateful event for sync
    stateful_event = cJSON_CreateObject();
    if (stateful_event == NULL) {
        return;
    }

    cJSON* registry_stateful = cJSON_CreateObject();
    cJSON_AddItemToObject(stateful_event, "registry", registry_stateful);

    utf8_path = auto_to_utf8(path);
    cJSON_AddStringToObject(registry_stateful, "path", utf8_path ? utf8_path : path);
    os_free(utf8_path);

    if (strlen(hive) > 0 && strlen(key) > 0) {
        size_t full_key_len = strlen(hive) + 1 + strlen(key) + 1;
        char* full_key = NULL;
        os_malloc(full_key_len, full_key);
        snprintf(full_key, full_key_len, "%s\\%s", hive, key);
        char* utf8_full_key = auto_to_utf8(full_key);
        cJSON_AddStringToObject(registry_stateful, "key", utf8_full_key ? utf8_full_key : full_key);
        os_free(utf8_full_key);
        os_free(full_key);
    } else {
        char* utf8_key_path = auto_to_utf8(path);
        cJSON_AddStringToObject(registry_stateful, "key", utf8_key_path ? utf8_key_path : path);
        os_free(utf8_key_path);
    }
    cJSON_AddStringToObject(registry_stateful, "hive", hive);
    cJSON_AddStringToObject(registry_stateful, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");

    utf8_value = auto_to_utf8(value);
    cJSON_AddStringToObject(registry_stateful, "value", utf8_value ? utf8_value : value);
    os_free(utf8_value);

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

    // Compute SHA1 of path:arch:value for sync ID
    char id_source_string[OS_MAXSTR] = {0};
    snprintf(id_source_string, OS_MAXSTR - 1, "%s:%d:%s", path, arch, value);

    char registry_value_sha1[FILE_PATH_SHA1_BUFFER_SIZE] = {0};
    OS_SHA1_Str(id_source_string, -1, registry_value_sha1);

    // Read sync flag from result_json
    int sync_flag = 0;
    cJSON* sync_json = cJSON_GetObjectItem(result_json, "sync");
    if (sync_json != NULL && cJSON_IsNumber(sync_json)) {
        sync_flag = sync_json->valueint;
    }

    // Validate and persist the orphaned delete event
    // Note: For orphaned deletes, we don't mark for deletion from DBSync since the item is already deleted
    char item_desc[PATH_MAX + 128];
    snprintf(item_desc, sizeof(item_desc), "registry value %s:%s", path, value);
    validate_and_persist_fim_event(stateful_event, registry_value_sha1, OPERATION_DELETE,
                                    FIM_REGISTRY_VALUES_SYNC_INDEX, document_version,
                                    item_desc, false, NULL, NULL, sync_flag);

    cJSON_Delete(stateful_event);
}

// DBSync Callbacks

/**
 * @brief Registry key callback.
 *
 * @param resultType Action performed by DBSync (INSERTED|MODIFIED|DELETED|MAXROWS)
 * @param result_json Data returned by dbsync in JSON format.
 * @param user_data Registry key transaction context.
 */
STATIC void registry_key_transaction_callback(ReturnTypeCallback resultType,
                                              const cJSON* result_json,
                                              void* user_data) {

    cJSON *stateless_event = NULL;
    cJSON *json_path = NULL;
    cJSON *json_arch = NULL;
    cJSON *old_data = NULL;
    cJSON *old_attributes = NULL;
    cJSON *changed_attributes = NULL;
    char *path = NULL;
    int arch = -1;
    char iso_time[32];
    Operation_t sync_operation = OPERATION_NO_OP;
    int sync_flag = 0;

    fim_key_txn_context_t *event_data = (fim_key_txn_context_t *) user_data;

    // In case of deletions, key is NULL, so we need to get the path and arch from the json event
    if (event_data->key == NULL) {
        if (json_path = cJSON_GetObjectItem(result_json, "path"), json_path == NULL) {
            goto end;
        }
        if (json_arch = cJSON_GetObjectItem(result_json, "architecture"), json_arch == NULL) {
            goto end;
        }
        path = cJSON_GetStringValue(json_path);
        arch = (strcmp(cJSON_GetStringValue(json_arch), "[x32]") == 0) ? ARCH_32BIT: ARCH_64BIT;

    } else {
        path = event_data->key->path;
        arch = event_data->key->architecture;
    }

    if (event_data->config == NULL) {
        event_data->config = fim_registry_configuration(path, arch);
        if (event_data->config == NULL) {
            // For DELETE events of orphaned registry keys (path removed from config),
            // generate minimal delete events without requiring configuration
            if (resultType == DELETED) {
                handle_orphaned_delete_registry_key(path, arch, result_json, event_data);
            }
            goto end;
        }
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

    switch (resultType) {
        case INSERTED:
            event_data->evt_data->type = FIM_ADD;
            sync_operation = OPERATION_CREATE;
            // For CREATE events: determine if within limit and defer sync flag update
            if (syscheck.registry_key_limit > 0) {
                sync_flag = (synced_docs_registry_keys < syscheck.registry_key_limit) ? 1 : 0;
            } else {
                sync_flag = 1;
            }
            // Add to deferred list if sync_flag should be 1
            if (sync_flag == 1 && event_data->pending_sync_updates != NULL) {
                synced_docs_registry_keys++;
                cJSON* sync_item = cJSON_CreateObject();
                if (sync_item != NULL) {
                    cJSON_AddStringToObject(sync_item, "path", path);
                    cJSON_AddStringToObject(sync_item, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");
                    cJSON_AddNumberToObject(sync_item, "version", (double)document_version);
                    add_pending_sync_item(event_data->pending_sync_updates, sync_item, 1);
                    cJSON_Delete(sync_item);
                } else {
                    merror("Failed to create cJSON object for deferred sync item");
                }
            }
            break;

        case MODIFIED:
            event_data->evt_data->type = FIM_MODIFICATION;
            sync_operation = OPERATION_MODIFY;

            // Get the old sync flag value to track synced documents and determine if promotion is needed
            old_data = cJSON_GetObjectItem(result_json, "old");
            cJSON *sync_json = cJSON_GetObjectItem(old_data, "sync");
            if (sync_json != NULL && cJSON_IsNumber(sync_json)) {
                sync_flag = sync_json->valueint;
                // NOTE: We don't add to deferred list here because syncRow preserves the sync flag
                // when it's not in the input data. The sync flag is already 1 after the transaction.
            }

            if (sync_flag == 0 && syscheck.registry_key_limit > 0) { // Promote
                if (synced_docs_registry_keys < syscheck.registry_key_limit) {
                    synced_docs_registry_keys++;
                    cJSON* sync_item = cJSON_CreateObject();
                    if (sync_item != NULL) {
                        cJSON_AddStringToObject(sync_item, "path", path);
                        cJSON_AddStringToObject(sync_item, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");
                        cJSON_AddNumberToObject(sync_item, "version", (double)document_version);
                        add_pending_sync_item(event_data->pending_sync_updates, sync_item, 1);
                        cJSON_Delete(sync_item);
                        sync_flag = 1;
                    } else {
                        merror("Failed to create cJSON object for deferred sync item");
                    }
                }
            }
            break;

        case DELETED:
            event_data->evt_data->type = FIM_DELETE;
            sync_operation = OPERATION_DELETE;
            // For DELETE events: entry is NULL, read sync flag from DB result
            {
            cJSON *sync_json = cJSON_GetObjectItem(result_json, "sync");
                if (sync_json != NULL && cJSON_IsNumber(sync_json)) {
                    sync_flag = sync_json->valueint;
                    if (sync_flag == 1) {
                        synced_docs_registry_keys--;
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
        return;
    }

    cJSON_AddStringToObject(stateless_event, "collector", "registry_key");
    cJSON_AddStringToObject(stateless_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(stateless_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", FIM_EVENT_TYPE_ARRAY[event_data->evt_data->type]);

    cJSON* registry_stateless = fim_registry_key_attributes_json(result_json, event_data->key, event_data->config);
    cJSON_AddItemToObject(data, "registry", registry_stateless);

    char *utf8_path = auto_to_utf8(path);
    cJSON_AddStringToObject(registry_stateless, "path", utf8_path ? utf8_path : path);
    os_free(utf8_path);

    const char *hive = get_registry_hive_abbreviation(path);
    const char *key = get_registry_key(path);

    if (strlen(hive) > 0 && strlen(key) > 0) {
        size_t full_key_len = strlen(hive) + 1 + strlen(key) + 1;
        char *full_key = NULL;
        os_malloc(full_key_len, full_key);
        snprintf(full_key, full_key_len, "%s\\%s", hive, key);
        char *utf8_full_key = auto_to_utf8(full_key);
        cJSON_AddStringToObject(registry_stateless, "key", utf8_full_key ? utf8_full_key : full_key);
        os_free(utf8_full_key);
        os_free(full_key);
    } else {
        char *utf8_key_path = auto_to_utf8(path);
        cJSON_AddStringToObject(registry_stateless, "key", utf8_key_path ? utf8_key_path : path);
        os_free(utf8_key_path);
    }
    cJSON_AddStringToObject(registry_stateless, "hive", hive);

    cJSON_AddStringToObject(registry_stateless, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");

    cJSON_AddStringToObject(registry_stateless, "mode", FIM_EVENT_MODE[event_data->evt_data->mode]);

    old_data = cJSON_GetObjectItem(result_json, "old");
    if (old_data != NULL) {
        old_attributes = cJSON_CreateObject();
        changed_attributes = cJSON_CreateArray();
        cJSON_AddItemToObject(registry_stateless, "previous", old_attributes);
        cJSON_AddItemToObject(event, "changed_fields", changed_attributes);

        fim_calculate_dbsync_difference_key(event_data->config,
                                            old_data,
                                            changed_attributes,
                                            old_attributes);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            mdebug2(FIM_EMPTY_CHANGED_ATTRIBUTES, path);
            goto end;
        }
    }

    if (event_data->config->tag != NULL) {
        cJSON_AddStringToObject(registry_stateless, "tags", event_data->config->tag);
    }

    if (notify_scan != 0 && event_data->evt_data->report_event) {
        send_syscheck_msg(stateless_event);
    }

    char id_source_string[OS_MAXSTR] = {0};
    snprintf(id_source_string, OS_MAXSTR - 1, "%d:%s", arch, path);

    char registry_key_sha1[FILE_PATH_SHA1_BUFFER_SIZE] = {0};
    OS_SHA1_Str(id_source_string, -1, registry_key_sha1);

    // Calculate checksum
    const char* sha1_hash;
    if (event_data->key != NULL) {
        sha1_hash = event_data->key->checksum;
    } else {
        cJSON *aux = cJSON_GetObjectItem(result_json, "checksum");
        if (aux != NULL) {
            sha1_hash = cJSON_GetStringValue(aux);
        } else {
            mdebug1("Couldn't find checksum for '%s", path);
            return;
        }
    }
    cJSON* stateful_event = build_stateful_event_registry_key(path, sha1_hash, document_version, arch, result_json, event_data->key);
    if (!stateful_event) {
        merror("Couldn't create stateful event for %s", path);
        goto end; // LCOV_EXCL_LINE
    }

    // Validate and persist the event
    // For INSERT/MODIFY operations that fail validation, mark for deletion from DBSync
    char item_desc[PATH_MAX + 64];
    snprintf(item_desc, sizeof(item_desc), "registry key %s", path);

    failed_registry_key_t *failed_key = NULL;
    bool mark_for_deletion = false;

    if (resultType == INSERTED || resultType == MODIFIED) {
        failed_key = malloc(sizeof(failed_registry_key_t));
        if (failed_key) {
            failed_key->path = strdup(path);
            failed_key->arch = arch;
            mark_for_deletion = (failed_key->path != NULL);
            if (!mark_for_deletion) {
                os_free(failed_key);
                failed_key = NULL;
            }
        }
    }

    bool validation_passed = validate_and_persist_fim_event(stateful_event, registry_key_sha1, sync_operation,
                                                             FIM_REGISTRY_KEYS_SYNC_INDEX, document_version,
                                                             item_desc, mark_for_deletion,
                                                             event_data->failed_keys, failed_key, sync_flag);

    // If validation passed, we need to free failed_key (it wasn't added to the list)
    // If validation failed, failed_key was added to the list and will be freed later
    if (validation_passed && failed_key) {
        os_free(failed_key->path);
        os_free(failed_key);
    }

    cJSON_Delete(stateful_event);
end:
    cJSON_Delete(stateless_event);
}

/**
 * @brief Registry value callback.
 *
 * @param resultType Action performed by DBSync (INSERTED|MODIFIED|DELETED|MAXROWS)
 * @param result_json Data returned by dbsync in JSON format.
 * @param user_data Registry value transaction context.
 */
STATIC void registry_value_transaction_callback(ReturnTypeCallback resultType,
                                                const cJSON* result_json,
                                                void* user_data) {

    cJSON *stateless_event = NULL;
    cJSON *json_path = NULL;
    cJSON *json_arch = NULL;
    cJSON *json_value = NULL;
    cJSON *old_data = NULL;
    cJSON *old_attributes = NULL;
    cJSON *changed_attributes = NULL;
    char *path = NULL;
    char *value = NULL;
    int arch = -1;
    char iso_time[32];
    Operation_t sync_operation = OPERATION_NO_OP;
    int sync_flag = 0;

    fim_val_txn_context_t *event_data = (fim_val_txn_context_t *) user_data;

    // In case of deletions, data is NULL, so we need to get the path and arch from the json event
    if (event_data->data == NULL) {
        if (json_path = cJSON_GetObjectItem(result_json, "path"), json_path == NULL) {
            goto end;
        }
        if (json_arch = cJSON_GetObjectItem(result_json, "architecture"), json_arch == NULL) {
            goto end;
        }
        if (json_value = cJSON_GetObjectItem(result_json, "value"), json_value == NULL) {
            goto end;
        }
        path = cJSON_GetStringValue(json_path);
        arch = (strcmp(cJSON_GetStringValue(json_arch), "[x32]") == 0) ? ARCH_32BIT: ARCH_64BIT;
        value = cJSON_GetStringValue(json_value);
    } else {
        path = event_data->data->path;
        arch = event_data->data->architecture;
        value = event_data->data->value;
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

    if (event_data->config == NULL) {
        event_data->config = fim_registry_configuration(path, arch);
        if (event_data->config == NULL) {
            // For DELETE events of orphaned registry values (path removed from config),
            // generate minimal delete events without requiring configuration
            if (resultType == DELETED) {
                handle_orphaned_delete_registry_value(path, value, arch, result_json, event_data);
            }
            goto end;
        }
    }

    switch (resultType) {
        case INSERTED:
            event_data->evt_data->type = FIM_ADD;
            sync_operation = OPERATION_CREATE;
            // For CREATE events: determine if within limit and defer sync flag update
            if (syscheck.registry_value_limit > 0) {
                sync_flag = (synced_docs_registry_values < syscheck.registry_value_limit) ? 1 : 0;
            } else {
                sync_flag = 1;
            }
            // Add to deferred list if sync_flag should be 1
            if (sync_flag == 1 && event_data->pending_sync_updates != NULL) {
                synced_docs_registry_values++;
                cJSON* sync_item = cJSON_CreateObject();
                if (sync_item != NULL) {
                    cJSON_AddStringToObject(sync_item, "path", path);
                    cJSON_AddStringToObject(sync_item, "value", value);
                    cJSON_AddStringToObject(sync_item, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");
                    cJSON_AddNumberToObject(sync_item, "version", (double)document_version);
                    add_pending_sync_item(event_data->pending_sync_updates, sync_item, 1);
                    cJSON_Delete(sync_item);
                } else {
                    merror("Failed to create cJSON object for deferred sync item");
                }
            }
            break;

        case MODIFIED:
            event_data->evt_data->type = FIM_MODIFICATION;
            sync_operation = OPERATION_MODIFY;

            // Get the old sync flag value to track synced documents and determine if promotion is needed
            old_data = cJSON_GetObjectItem(result_json, "old");
            cJSON *sync_json = cJSON_GetObjectItem(old_data, "sync");
            if (sync_json != NULL && cJSON_IsNumber(sync_json)) {
                sync_flag = sync_json->valueint;
                // NOTE: We don't add to deferred list here because syncRow preserves the sync flag
                // when it's not in the input data. The sync flag is already 1 after the transaction.
            }

            if (sync_flag == 0 && syscheck.registry_value_limit > 0) { // Promote
                if (synced_docs_registry_values < syscheck.registry_value_limit) {
                    synced_docs_registry_values++;
                    cJSON* sync_item = cJSON_CreateObject();
                    if (sync_item != NULL) {
                        cJSON_AddStringToObject(sync_item, "path", path);
                        cJSON_AddStringToObject(sync_item, "value", value);
                        cJSON_AddStringToObject(sync_item, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");
                        cJSON_AddNumberToObject(sync_item, "version", (double)document_version);
                        add_pending_sync_item(event_data->pending_sync_updates, sync_item, 1);
                        cJSON_Delete(sync_item);
                        sync_flag = 1;
                    } else {
                        merror("Failed to create cJSON object for deferred sync item");
                    }
                }
            }
            break;

        case DELETED:
            if (event_data->config->opts & CHECK_SEECHANGES) {
                fim_diff_process_delete_value(path, value, arch);
            }
            event_data->evt_data->type = FIM_DELETE;
            sync_operation = OPERATION_DELETE;
            // For DELETE events: entry is NULL, read sync flag from DB result
            {
            cJSON *sync_json = cJSON_GetObjectItem(result_json, "sync");
                if (sync_json != NULL && cJSON_IsNumber(sync_json)) {
                    sync_flag = sync_json->valueint;
                    if (sync_flag == 1) {
                        synced_docs_registry_values--;
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
        goto end;
    }

    cJSON_AddStringToObject(stateless_event, "collector", "registry_value");
    cJSON_AddStringToObject(stateless_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(stateless_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", FIM_EVENT_TYPE_ARRAY[event_data->evt_data->type]);

    cJSON* registry_stateless = fim_registry_value_attributes_json(result_json, event_data->data, event_data->config);
    cJSON_AddItemToObject(data, "registry", registry_stateless);

    char *utf8_path = auto_to_utf8(path);
    cJSON_AddStringToObject(registry_stateless, "path", utf8_path ? utf8_path : path);
    os_free(utf8_path);

    const char *hive = get_registry_hive_abbreviation(path);
    const char *key = get_registry_key(path);

    if (strlen(hive) > 0 && strlen(key) > 0) {
        size_t full_key_len = strlen(hive) + 1 + strlen(key) + 1;
        char *full_key = NULL;
        os_malloc(full_key_len, full_key);
        snprintf(full_key, full_key_len, "%s\\%s", hive, key);
        char *utf8_full_key = auto_to_utf8(full_key);
        cJSON_AddStringToObject(registry_stateless, "key", utf8_full_key ? utf8_full_key : full_key);
        os_free(utf8_full_key);
        os_free(full_key);
    } else {
        char *utf8_key_path = auto_to_utf8(path);
        cJSON_AddStringToObject(registry_stateless, "key", utf8_key_path ? utf8_key_path : path);
        os_free(utf8_key_path);
    }
    cJSON_AddStringToObject(registry_stateless, "hive", hive);

    cJSON_AddStringToObject(registry_stateless, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");
    char *utf8_value = auto_to_utf8(value);
    cJSON_AddStringToObject(registry_stateless, "value", utf8_value ? utf8_value : value);
    os_free(utf8_value);

    cJSON_AddStringToObject(registry_stateless, "mode", FIM_EVENT_MODE[event_data->evt_data->mode]);

    old_data = cJSON_GetObjectItem(result_json, "old");
    if (old_data != NULL) {
        old_attributes = cJSON_CreateObject();
        changed_attributes = cJSON_CreateArray();
        cJSON_AddItemToObject(registry_stateless, "previous", old_attributes);
        cJSON_AddItemToObject(event, "changed_fields", changed_attributes);

        fim_calculate_dbsync_difference_value(event_data->config,
                                              old_data,
                                              changed_attributes,
                                              old_attributes);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            mdebug2(FIM_EMPTY_CHANGED_ATTRIBUTES, path);
            goto end;
        }
    }

    if (event_data->config->tag != NULL) {
        cJSON_AddStringToObject(registry_stateless, "tags", event_data->config->tag);
    }

    if (event_data->diff != NULL && resultType == MODIFIED) {
        cJSON_AddStringToObject(registry_stateless, "content_changes", event_data->diff);
    }

    if (notify_scan != 0 && event_data->evt_data->report_event) {
        send_syscheck_msg(stateless_event);
    }

    // Calculate checksum
    const char* sha1_hash;
    if (event_data->data != NULL) {
        sha1_hash = event_data->data->checksum;
    } else {
        cJSON *aux = cJSON_GetObjectItem(result_json, "checksum");
        if (aux != NULL) {
            sha1_hash = cJSON_GetStringValue(aux);
        } else {
            mdebug1("Couldn't find checksum for '%s", path);
            return;
        }
    }
    char id_source_string[OS_MAXSTR] = {0};
    snprintf(id_source_string, OS_MAXSTR - 1, "%s:%d:%s", path, arch, value);

    char registry_value_sha1[FILE_PATH_SHA1_BUFFER_SIZE] = {0};
    OS_SHA1_Str(id_source_string, -1, registry_value_sha1);

    cJSON* stateful_event = build_stateful_event_registry_value(path, value, sha1_hash, document_version, arch, result_json, event_data->data);
    if (!stateful_event) {
        merror("Couldn't create stateful event for %s", path);
        goto end; // LCOV_EXCL_LINE
    }

    // Validate and persist the event
    // For INSERT/MODIFY operations that fail validation, mark for deletion from DBSync
    char item_desc[PATH_MAX + 128];
    snprintf(item_desc, sizeof(item_desc), "registry value %s:%s", path, value);

    failed_registry_value_t *failed_value = NULL;
    bool mark_for_deletion = false;

    if (resultType == INSERTED || resultType == MODIFIED) {
        failed_value = malloc(sizeof(failed_registry_value_t));
        if (failed_value) {
            failed_value->path = strdup(path);
            failed_value->value = strdup(value);
            failed_value->arch = arch;
            mark_for_deletion = (failed_value->path != NULL && failed_value->value != NULL);
            if (!mark_for_deletion) {
                os_free(failed_value->path);
                os_free(failed_value->value);
                os_free(failed_value);
                failed_value = NULL;
            }
        }
    }

    bool validation_passed = validate_and_persist_fim_event(stateful_event, registry_value_sha1, sync_operation,
                                                             FIM_REGISTRY_VALUES_SYNC_INDEX, document_version,
                                                             item_desc, mark_for_deletion,
                                                             event_data->failed_values, failed_value, sync_flag);

    // If validation passed, we need to free failed_value (it wasn't added to the list)
    // If validation failed, failed_value was added to the list and will be freed later
    if (validation_passed && failed_value) {
        os_free(failed_value->path);
        os_free(failed_value->value);
        os_free(failed_value);
    }

    cJSON_Delete(stateful_event);

end:
    os_free(event_data->diff);
    cJSON_Delete(stateless_event);
}

/**
 * @brief Set the root key and subkey associated with a given key.
 *
 * @param root_key_handle A pointer to a handle which will hold the root key handle on success, NULL on failure.
 * @param full_key A string holding the full path to a registry key.
 * @param sub_key A pointer to a pointer which will point to the byte where the first sub key of full_key starts,
 * unchanged on error.
 * @return 0 if the root key is properly set, -1 otherwise.
 */
int fim_set_root_key(HKEY *root_key_handle, const char *full_key, const char **sub_key) {
    int root_key_length;

    if (root_key_handle == NULL || full_key == NULL || sub_key == NULL) {
        return -1;
    }

    /* Verify valid root tree */
    if (strncmp(full_key, "HKEY_LOCAL_MACHINE", 18) == 0) {
        *root_key_handle = HKEY_LOCAL_MACHINE;
        root_key_length = 18;
    } else if (strncmp(full_key, "HKEY_CLASSES_ROOT", 17) == 0) {
        *root_key_handle = HKEY_CLASSES_ROOT;
        root_key_length = 17;
    } else if (strncmp(full_key, "HKEY_CURRENT_CONFIG", 19) == 0) {
        *root_key_handle = HKEY_CURRENT_CONFIG;
        root_key_length = 19;
    } else if (strncmp(full_key, "HKEY_USERS", 10) == 0) {
        *root_key_handle = HKEY_USERS;
        root_key_length = 10;
    } else {
        *root_key_handle = NULL;
        return -1;
    }

    if (full_key[root_key_length] != '\\') {
        *root_key_handle = NULL;
        return -1;
    }

    *sub_key = &full_key[root_key_length + 1];
    return 0;
}

registry_t *fim_registry_configuration(const char *key, int arch) {
    int it = 0;
    int top = 0;
    int match;
    registry_t *ret = NULL;

    for (it = 0; syscheck.registry[it].entry; it++) {
        if (arch != syscheck.registry[it].arch) {
            continue;
        }

        match = w_compare_str(syscheck.registry[it].entry, key);

        if (top < match) {
            ret = &syscheck.registry[it];
            top = match;
        }
    }

    if (ret == NULL) {
        mdebug2(FIM_CONFIGURATION_NOTFOUND, "registry", key);
    }

    return ret;
}

/**
 * @brief Validates the recursion level of a registry key.
 *
 * @param key_path Path of the key
 * @param configuration The configuration associated with the registry entry.
 * @return 0 if the path is valid, -1 if the path is to be excluded.
 */
int fim_registry_validate_recursion_level(const char *key_path, const registry_t *configuration) {
    const char *pos;
    int depth = 0;
    unsigned int parent_path_size;

    if (key_path == NULL || configuration == NULL) {
        return -1;
    }

    /* Verify recursion level */
    parent_path_size = strlen(configuration->entry);
    // Recursion level only for registry keys
    if (parent_path_size > strlen(key_path)) {
        return -1;
    }

    pos = key_path + parent_path_size;
    while (pos = strchr(pos, PATH_SEP), pos) {
        depth++;
        pos++;
    }

    if (depth > configuration->recursion_level) {
        mdebug2(FIM_MAX_RECURSION_LEVEL, depth, configuration->recursion_level, key_path);
        return -1;
    }

    return 0;
}

/**
 * @brief Validates ignore restrictions of registry entry.
 *
 * @param entry A string holding the full path of the key or the name of the value to be validated.
 * @param configuration The configuration associated with the registry entry.
 * @param key 1 if the entry is a key, 0 if the entry is a value.
 * @return 0 if the path is valid, -1 if the path is to be excluded.
 */
int fim_registry_validate_ignore(const char *entry, const registry_t *configuration, int key) {
    int ign_it;
    registry_ignore **ignore_list;
    registry_ignore_regex **ignore_list_regex;

    if (entry == NULL || configuration == NULL) {
        return -1;
    }

    if (key) {
        ignore_list = &syscheck.key_ignore;
        ignore_list_regex = &syscheck.key_ignore_regex;
    } else {
        ignore_list = &syscheck.value_ignore;
        ignore_list_regex = &syscheck.value_ignore_regex;
    }

    if (*ignore_list) {
        for (ign_it = 0; (*ignore_list)[ign_it].entry; ign_it++) {
            if ((*ignore_list)[ign_it].arch != configuration->arch) {
                continue;
            }
            if (strncasecmp((*ignore_list)[ign_it].entry, entry, strlen((*ignore_list)[ign_it].entry)) == 0) {
                mdebug2(FIM_REG_IGNORE_ENTRY, key ? "registry" : "value",
                        (*ignore_list)[ign_it].arch == ARCH_32BIT ? "[x32]" : "[x64]", entry,
                        (*ignore_list)[ign_it].entry);
                return -1;
            }
        }
    }
    if (*ignore_list_regex) {
        for (ign_it = 0; (*ignore_list_regex)[ign_it].regex; ign_it++) {
            if ((*ignore_list_regex)[ign_it].arch != configuration->arch) {
                continue;

            }
            if (OSMatch_Execute(entry, strlen(entry), (*ignore_list_regex)[ign_it].regex)) {
                mdebug2(FIM_REG_IGNORE_SREGEX, key ? "registry" : "value",
                        (*ignore_list_regex)[ign_it].arch == ARCH_32BIT ? "[x32]" : "[x64]", entry,
                        (*ignore_list_regex)[ign_it].regex->raw);
                return -1;
            }
        }
    }
    return 0;
}

/**
 * @brief Checks if a specific folder has been configured to be checked with a specific restriction
 *
 * @param entry A string holding the full path of the key or the name of the value to be validated.
 * @param restriction The regex restriction to be checked
 * @return 1 if the folder has been configured with the specified restriction, 0 if not
 */
int fim_registry_validate_restrict(const char *entry, OSMatch *restriction) {
    if (entry == NULL) {
        merror(NULL_ERROR);
        return 1;
    }

    // Restrict file types
    if (restriction) {
        if (!OSMatch_Execute(entry, strlen(entry), restriction)) {
            mdebug2(FIM_FILE_IGNORE_RESTRICT, entry, restriction->raw);
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Compute checksum of a registry key
 *
 * @param data FIM registry key whose checksum will be computed
 */
void fim_registry_get_checksum_key(fim_registry_key *data) {
    char *checksum = NULL;
    int size;

    size = snprintf(0,
            0,
            "%s:%s:%s:%s:%s:%s:%lu:%d",
            data->path ? data->path : "",
            data->permissions ? data->permissions : "",
            data->uid ? data->uid : "",
            data->owner ? data->owner : "",
            data->gid ? data->gid : "",
            data->group ? data->group : "",
            data->mtime,
            data->architecture);

    os_calloc(size + 1, sizeof(char), checksum);
    snprintf(checksum,
            size + 1,
            "%s:%s:%s:%s:%s:%s:%lu:%d",
            data->path ? data->path : "",
            data->permissions ? data->permissions : "",
            data->uid ? data->uid : "",
            data->gid ? data->gid : "",
            data->owner ? data->owner : "",
            data->group ? data->group : "",
            data->mtime,
            data->architecture);

    OS_SHA1_Str(checksum, -1, data->checksum);
    free(checksum);
}

/**
 * @brief Compute checksum of a registry value
 *
 * @param data FIM registry value whose checksum will be computed
 */
void fim_registry_get_checksum_value(fim_registry_value_data *data) {
    char *checksum = NULL;
    int size;

    size = snprintf(0,
            0,
            "%s:%s:%d:%u:%llu:%s:%s:%s",
            data->path ? data->path : "",
            data->value ? data->value : "",
            data->architecture,
            data->type,
            data->size,
            data->hash_md5 ,
            data->hash_sha1,
            data->hash_sha256);

    os_calloc(size + 1, sizeof(char), checksum);
    snprintf(checksum,
            size + 1,
            "%s:%s:%d:%u:%llu:%s:%s:%s",
            data->path ? data->path : "",
            data->value ? data->value : "",
            data->architecture,
            data->type,
            data->size,
            data->hash_md5 ,
            data->hash_sha1,
            data->hash_sha256);

    OS_SHA1_Str(checksum, -1, data->checksum);
    free(checksum);
}

/**
 * @brief Initialize digest context according to a provided configuration
 *
 * @param opts An integer holding the registry configuration.
 * @param md5_ctx An uninitialized md5 context.
 * @param sha1_ctx An uninitialized sha1 context.
 * @param sha256_ctx An uninitialized sha256 context.
 */
void fim_registry_init_digests(int opts, EVP_MD_CTX *md5_ctx, EVP_MD_CTX *sha1_ctx, EVP_MD_CTX *sha256_ctx) {
    if (opts & CHECK_MD5SUM) {
        EVP_DigestInit(md5_ctx, EVP_md5());
    }

    if (opts & CHECK_SHA1SUM) {
        EVP_DigestInit(sha1_ctx, EVP_sha1());
    }

    if (opts & CHECK_SHA256SUM) {
        EVP_DigestInit(sha256_ctx, EVP_sha256());
    }
}

/**
 * @brief Update digests from a provided buffer.
 *
 * @param buffer A raw data buffer used to update digests.
 * @param length An integer holding the length of buffer.
 * @param opts An integer holding the registry configuration.
 * @param md5_ctx An MD5 CTX to be updated with the contents of buffer.
 * @param sha1_ctx An SHA1 CTX to be updated with the contents of buffer.
 * @param sha256_ctx An SHA256 CTX to be updated with the contents of buffer.
 */
void fim_registry_update_digests(const BYTE *buffer,
                                 size_t length,
                                 int opts,
                                 EVP_MD_CTX *md5_ctx,
                                 EVP_MD_CTX *sha1_ctx,
                                 EVP_MD_CTX *sha256_ctx) {
    if (opts & CHECK_MD5SUM) {
        EVP_DigestUpdate(md5_ctx, buffer, length);
    }

    if (opts & CHECK_SHA1SUM) {
        EVP_DigestUpdate(sha1_ctx, buffer, length);
    }

    if (opts & CHECK_SHA256SUM) {
        EVP_DigestUpdate(sha256_ctx, buffer, length);
    }
}

/**
 * @brief Prints out hashes from the provided contexts, destryoing them in the process.
 *
 * @param opts An integer holding the registry configuration.
 * @param md5_ctx An MD5 CTX used to print the corresponding hash.
 * @param sha1_ctx An SHA1 CTX used to print the corresponding hash.
 * @param sha256_ctx An SHA256 CTX used to print the corresponding hash.
 * @param md5_output A buffer holding the MD5 hash on exit.
 * @param sha1_output A buffer holding the SHA1 hash on exit.
 * @param sha256_output A buffer holding the SHA256 hash on exit.
 */
void fim_registry_final_digests(int opts,
                                EVP_MD_CTX *md5_ctx,
                                EVP_MD_CTX *sha1_ctx,
                                EVP_MD_CTX *sha256_ctx,
                                os_md5 md5_output,
                                os_sha1 sha1_output,
                                os_sha256 sha256_output) {
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    int n;

    if (opts & CHECK_MD5SUM) {
        EVP_DigestFinal(md5_ctx, md5_digest, NULL);
        for (n = 0; n < MD5_DIGEST_LENGTH; n++) {
            snprintf(md5_output, 3, "%02x", md5_digest[n]);
            md5_output += 2;
        }
    }

    if (opts & CHECK_SHA1SUM) {
        EVP_DigestFinal(sha1_ctx, sha1_digest, NULL);
        for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
            snprintf(sha1_output, 3, "%02x", sha1_digest[n]);
            sha1_output += 2;
        }
    }

    if (opts & CHECK_SHA256SUM) {
        EVP_DigestFinal(sha256_ctx, sha256_digest, NULL);
        for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
            snprintf(sha256_output, 3, "%02x", sha256_digest[n]);
            sha256_output += 2;
        }
    }
}

/**
 * @brief Calculate and store value hashes.
 *
 * @param entry FIM entry holding information from a value.
 * @param configuration The confguration associated with the value.
 * @param data_buffer Raw buffer holding the value's contents.
 */
void fim_registry_calculate_hashes(fim_entry *entry, registry_t *configuration, BYTE *data_buffer) {
    EVP_MD_CTX *md5_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();

    char *string_it;
    BYTE buffer[OS_SIZE_2048];
    size_t length;
    bool is_successful = true;

    entry->registry_entry.value->hash_md5[0] = '\0';
    entry->registry_entry.value->hash_sha1[0] = '\0';
    entry->registry_entry.value->hash_sha256[0] = '\0';

    if ((configuration->opts & (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM)) == 0) {
        return;
    }

    /* Initialize configured hashes */
    fim_registry_init_digests(configuration->opts, md5_ctx, sha1_ctx, sha256_ctx);

    switch (entry->registry_entry.value->type) {
    case REG_SZ:
    case REG_EXPAND_SZ: {
        WCHAR *w_data = (WCHAR *)data_buffer;
        char *utf8_data = wide_to_utf8(w_data);
        if (utf8_data) {
            fim_registry_update_digests((BYTE *)utf8_data, strlen(utf8_data), configuration->opts,
                                        md5_ctx, sha1_ctx, sha256_ctx);
            os_free(utf8_data);
        } else {
            mdebug1("Error converting registry value data to UTF-8.");
            is_successful = false;
        }
    }
    break;
    case REG_MULTI_SZ: {
        WCHAR *w_data = (WCHAR *)data_buffer;

        // Multi string check
        while (*w_data) {
            char *utf8_data = wide_to_utf8(w_data);
            if (utf8_data) {
                fim_registry_update_digests((BYTE *)utf8_data, strlen(utf8_data), configuration->opts,
                                            md5_ctx, sha1_ctx, sha256_ctx);
                os_free(utf8_data);
            }
            else {
                mdebug1("Error converting registry value data to UTF-8.");
                is_successful = false;
                break;
            }
            w_data += wcslen(w_data) + 1; // Update pointer to next string location
        }
    }
    break;
    case REG_DWORD:
        length = snprintf((char *)buffer, OS_SIZE_2048, "%08x", *((unsigned int *)data_buffer));
        fim_registry_update_digests(buffer, length, configuration->opts, md5_ctx, sha1_ctx, sha256_ctx);
        break;
    default:
        for (unsigned int i = 0; i < entry->registry_entry.value->size; i++) {
            length = snprintf((char *)buffer, 3, "%02x", (unsigned int)data_buffer[i] & 0xFF);
            fim_registry_update_digests(buffer, length, configuration->opts, md5_ctx, sha1_ctx, sha256_ctx);
        }
        break;
    }

    if (!is_successful) {
        EVP_MD_CTX_free(md5_ctx);
        EVP_MD_CTX_free(sha1_ctx);
        EVP_MD_CTX_free(sha256_ctx);
        return;
    }

    fim_registry_final_digests(configuration->opts, md5_ctx, sha1_ctx, sha256_ctx,
                               entry->registry_entry.value->hash_md5, entry->registry_entry.value->hash_sha1,
                               entry->registry_entry.value->hash_sha256);

    EVP_MD_CTX_free(md5_ctx);
    EVP_MD_CTX_free(sha1_ctx);
    EVP_MD_CTX_free(sha256_ctx);
}

/**
 * @brief Free all memory associated with a registry key.
 *
 * @param data A fim_registry_key object to be free'd.
 */
void fim_registry_free_key(fim_registry_key *key) {
    if (key) {
        os_free(key->path);
        os_free(key->permissions);
        cJSON_Delete(key->perm_json);
        os_free(key->uid);
        os_free(key->gid);
        os_free(key->owner);
        os_free(key->group);
        free(key);
    }
}

/**
 * @brief Gets all information from a given registry key.
 *
 * @param key_handle A handle to the key whose information we want.
 * @param path A string holding the full path to the key we want to query.
 * @param configuration The confguration associated with the key.
 * @return A fim_registry_key object holding the information from the queried key, NULL on error.
 */
fim_registry_key *fim_registry_get_key_data(HKEY key_handle, const char *path, const registry_t *configuration) {
    fim_registry_key *key;

    os_calloc(1, sizeof(fim_registry_key), key);

    os_strdup(path, key->path);

    key->architecture = configuration->arch;

     if (configuration->opts & CHECK_OWNER) {
        key->owner = get_registry_user(path, &key->uid, key_handle);
    }

    if (configuration->opts & CHECK_GROUP) {
        key->group = get_registry_group(&key->gid, key_handle);
    }

    if (configuration->opts & CHECK_PERM) {
        int error;

        key->perm_json = NULL;
        error = get_registry_permissions(key_handle, &(key->perm_json));
        if (error) {
            mdebug1(FIM_EXTRACT_PERM_FAIL, path, error);
            fim_registry_free_key(key);
            return NULL;
        }

        decode_win_acl_json(key->perm_json);
        key->permissions = cJSON_PrintUnformatted(key->perm_json);
    }

    if (configuration->opts & CHECK_MTIME) {
        key->mtime = get_registry_mtime(key_handle);
    }

    fim_registry_get_checksum_key(key);

    return key;
}

/**
 * @brief Free all memory associated with a registry value.
 *
 * @param data A fim_registry_value_data object to be free'd.
 */
void fim_registry_free_value_data(fim_registry_value_data *data) {
    if (data) {
        os_free(data->value);
        free(data);
    }
}

void fim_registry_free_entry(fim_entry *entry) {
    if (entry) {
        fim_registry_free_key(entry->registry_entry.key);
        fim_registry_free_value_data(entry->registry_entry.value);
        os_free(entry);
    }
}

/**
 * @brief Convert registry value data to UTF-8 format for diff generation.
 *
 * @param data_buffer The registry value data buffer.
 * @param data_type The registry value type (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, etc.).
 *
 * @return Pointer to UTF-8 string data. For REG_SZ, REG_EXPAND_SZ, and REG_MULTI_SZ,
 *         returns newly allocated memory that must be freed by caller. For other types,
 *         returns the original buffer cast to char* (no allocation). Returns NULL if
 *         UTF-16 to UTF-8 conversion fails.
 */
STATIC char *fim_registry_convert_value_for_diff(const BYTE *data_buffer, DWORD data_type) {
    char *value_data_for_diff = NULL;

    if (data_type == REG_SZ || data_type == REG_EXPAND_SZ) {
        value_data_for_diff = wide_to_utf8((WCHAR*)data_buffer);
    } else if (data_type == REG_MULTI_SZ) {
        WCHAR *w_data = (WCHAR *)data_buffer;
        size_t total_size = 0;
        WCHAR *it;
        char *cur;

        it = w_data;
        while (*it) {
            char *utf8_temp = wide_to_utf8(it);
            if (utf8_temp) {
                total_size += strlen(utf8_temp) + 1;
                os_free(utf8_temp);
            } else {
                return NULL;
            }
            it += wcslen(it) + 1;
        }
        total_size += 1;

        os_calloc(total_size, sizeof(char), value_data_for_diff);

        cur = value_data_for_diff;
        while (*w_data) {
            char *utf8_data = wide_to_utf8(w_data);
            if (utf8_data) {
                size_t len = strlen(utf8_data);
                memcpy(cur, utf8_data, len + 1);
                cur += len + 1;
                os_free(utf8_data);
            } else {
                os_free(value_data_for_diff);
                return NULL;
            }
            w_data += wcslen(w_data) + 1;
        }
        *cur = '\0';
    } else {
        value_data_for_diff = (char *)data_buffer;
    }

    return value_data_for_diff;
}

/**
 * @brief Query the values belonging to a key.
 *
 * @param key_handle A handle to the key holding the values to query.
 * @param new A fim_entry object holding the information gathered from the key.
 * @param saved A fim_entry object holding the information from the key retrieved from the database.
 * @param value_count An integer holding the amount of values stored in the queried key.
 * @param max_value_length The size of longest value name contained in the key in unicode characters.
 * @param max_value_data_length The size of the biggest data contained in of the keys values in bytes.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 */
void fim_read_values(HKEY key_handle,
                     char* path,
                     int arch,
                     DWORD value_count,
                     DWORD max_value_length,
                     DWORD max_value_data_length,
                     TXN_HANDLE regval_txn_handler,
                     fim_val_txn_context_t *txn_ctx_regval) {
    fim_registry_value_data value_data;
    WCHAR *value_name_buffer;
    BYTE *data_buffer;
    DWORD i;
    fim_entry new;
    char *value_path;
    size_t value_path_length;
    registry_t *configuration = NULL;
    char* diff = NULL;

    value_data.architecture = arch;
    value_data.path = path;
    value_data.value = NULL;
    new.registry_entry.value = &value_data;
    new.registry_entry.key = NULL;

    os_calloc(max_value_length + 1, sizeof(WCHAR), value_name_buffer);
    os_calloc(max_value_data_length + 4, sizeof(BYTE), data_buffer);

    for (i = 0; i < value_count; i++) {
        DWORD value_size = max_value_length + 1;
        DWORD data_size = max_value_data_length;
        DWORD data_type = 0;

        configuration = fim_registry_configuration(path, arch);
        if (configuration == NULL) {
            os_free(value_data.value);
            os_free(value_name_buffer);
            os_free(data_buffer);
            return;
        }

        if (RegEnumValueW(key_handle, i, value_name_buffer, &value_size, NULL, &data_type, data_buffer, &data_size) !=
            ERROR_SUCCESS) {
            break;
        }

        os_free(value_data.value);

        char *value_name_utf8 = wide_to_utf8(value_name_buffer);

        if (value_name_utf8 == NULL) {
            mdebug1("Failed to convert value name to UTF-8");
            continue;
        }

        new.registry_entry.value->value = value_name_utf8;
        new.registry_entry.value->type = data_type <= REG_QWORD ? data_type : REG_UNKNOWN;
        new.registry_entry.value->size = data_size;
        new.type = FIM_TYPE_REGISTRY;

        value_path_length = strlen(new.registry_entry.value->path) + strlen(new.registry_entry.value->value) + 2;

        os_malloc(value_path_length, value_path);
        snprintf(value_path, value_path_length, "%s\\%s", new.registry_entry.value->path, new.registry_entry.value->value);

        if (fim_registry_validate_ignore(value_path, configuration, 0)) {
            os_free(value_path);
            os_free(value_data.value);
            continue;
        }

        os_free(value_path);

        if (fim_registry_validate_restrict(new.registry_entry.value->value, configuration->restrict_value)) {
            continue;
        }

        fim_registry_calculate_hashes(&new, configuration, data_buffer);

        fim_registry_get_checksum_value(new.registry_entry.value);

        if (configuration->opts & CHECK_SEECHANGES) {
            char *value_data_for_diff = fim_registry_convert_value_for_diff(data_buffer, data_type);

            if (value_data_for_diff) {
                diff = fim_registry_value_diff(new.registry_entry.value->path, new.registry_entry.value->value,
                                           value_data_for_diff, new.registry_entry.value->type, configuration);
            }

            // Free only if allocated in this function
            if (data_type == REG_SZ || data_type == REG_EXPAND_SZ || data_type == REG_MULTI_SZ) {
                os_free(value_data_for_diff);
            }
        }
        txn_ctx_regval->diff = diff;
        txn_ctx_regval->data = new.registry_entry.value;
        txn_ctx_regval->config = configuration;

        int result_transaction = fim_db_transaction_sync_row(regval_txn_handler, &new);
        if (result_transaction < 0) {
            mdebug2("dbsync transaction failed due to %d", result_transaction);
        }

        txn_ctx_regval->config = NULL;
    }

    new.registry_entry.value = NULL;
    os_free(value_data.value);
    os_free(value_name_buffer);
    os_free(data_buffer);
}

/**
 * @brief Open a registry key and scan its contents.
 *
 * @param root_key_handle A handle to the root key to which the key to be scanned belongs.
 * @param full_key A string holding the full path to the key to scan.
 * @param sub_key A string holding the path to the key to scan, excluding the root key part of the path.
 * @param arch An integer specifying the bit count of the register to scan, must be ARCH_32BIT or ARCH_64BIT.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 * @param parent_configuration A pointer to the configuration of this key's "parent".
 */
void fim_open_key(HKEY root_key_handle,
                  const char *full_key,
                  const char *sub_key,
                  int arch,
                  fim_event_mode mode,
                  registry_t *parent_configuration,
                  TXN_HANDLE regkey_txn_handler,
                  TXN_HANDLE regval_txn_handler,
                  fim_val_txn_context_t *txn_ctx_regval,
                  fim_key_txn_context_t *txn_ctx_reg) {

    HKEY current_key_handle = NULL;
    REGSAM access_rights;
    DWORD sub_key_count = 0;
    DWORD value_count;
    DWORD max_value_length;
    DWORD max_value_data_length;
    FILETIME file_time = { 0 };
    DWORD i;
    fim_entry new;
    registry_t *configuration;
    int result_transaction = -1;

    if (root_key_handle == NULL || full_key == NULL || sub_key == NULL) {
        return;
    }

    configuration = fim_registry_configuration(full_key, arch);
    if (configuration == NULL) {
        return;
    }

    if (mode == FIM_SCHEDULED && parent_configuration != NULL && parent_configuration != configuration) {
        // If a more specific configuration is available in scheduled mode, we will scan this registry later.
        return;
    }

    // Recursion level restrictions.
    if (fim_registry_validate_recursion_level(full_key, configuration)) {
        return;
    }

    // Ignore restriction
    if (fim_registry_validate_ignore(full_key, configuration, 1)) {
        return;
    }

    access_rights = KEY_READ | (arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);

    WCHAR *sub_key_wide = auto_to_wide(sub_key);

    if (sub_key_wide == NULL) {
        mdebug1("Failed to convert registry key to wide character: '%s'", sub_key);
        return;
    }

    LONG reg_result = RegOpenKeyExW(root_key_handle, sub_key_wide, 0, access_rights, &current_key_handle);
    os_free(sub_key_wide);

    if (reg_result != ERROR_SUCCESS) {
        mdebug1(FIM_REG_OPEN, sub_key, arch == ARCH_32BIT ? "[x32]" : "[x64]", reg_result);
        return;
    }

    /* We use the class_name, sub_key_count and the value count */
    if (RegQueryInfoKey(current_key_handle, NULL, NULL, NULL, &sub_key_count, NULL, NULL, &value_count,
                        &max_value_length, &max_value_data_length, NULL, &file_time) != ERROR_SUCCESS) {
        RegCloseKey(current_key_handle);
        return;
    }

    /* Query each sub_key and call open_key */
    for (i = 0; i < sub_key_count; i++) {
        char *new_full_key;
        char *new_sub_key;
        size_t new_full_key_length;
        WCHAR sub_key_name_b[MAX_KEY_LENGTH + 1];
        DWORD sub_key_name_s = MAX_KEY_LENGTH + 1;

        if (RegEnumKeyExW(current_key_handle, i, sub_key_name_b, &sub_key_name_s, NULL, NULL, NULL, NULL) !=
            ERROR_SUCCESS) {
            continue;
        }

        char *sub_key_name_utf8 = wide_to_utf8(sub_key_name_b);

        if (sub_key_name_utf8 == NULL) {
            mdebug1("Failed to convert sub key name to UTF-8");
            continue;
        }

        new_full_key_length = strlen(full_key) + strlen(sub_key_name_utf8) + 2;

        os_malloc(new_full_key_length, new_full_key);

        snprintf(new_full_key, new_full_key_length, "%s\\%s", full_key, sub_key_name_utf8);

        os_free(sub_key_name_utf8);

        if (new_sub_key = strchr(new_full_key, '\\'), new_sub_key) {
            new_sub_key++;
        }

        /* Open sub_key */
        fim_open_key(root_key_handle, new_full_key, new_sub_key, arch, mode, configuration, regkey_txn_handler,
                     regval_txn_handler, txn_ctx_regval, txn_ctx_reg);

        os_free(new_full_key);
    }

    // Restrict check
    if (fim_registry_validate_restrict(full_key, configuration->restrict_key)) {
        return;
    }

    // Done scanning sub_keys, trigger an alert on the current key if required.
    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = fim_registry_get_key_data(current_key_handle, full_key, configuration);
    new.registry_entry.value = NULL;

    if (new.registry_entry.key == NULL) {
        return;
    }

    txn_ctx_reg->key = new.registry_entry.key;
    txn_ctx_reg->config = configuration;

    result_transaction = fim_db_transaction_sync_row(regkey_txn_handler, &new);
    if(result_transaction < 0){
        merror("Dbsync registry transaction failed due to %d", result_transaction);
    }

    if (value_count) {
        fim_read_values(current_key_handle, new.registry_entry.key->path, new.registry_entry.key->architecture, value_count, max_value_length, max_value_data_length,
                        regval_txn_handler, txn_ctx_regval);
    }

    txn_ctx_reg->config = NULL;

    fim_registry_free_key(new.registry_entry.key);
    RegCloseKey(current_key_handle);
}

void fim_registry_scan() {
    HKEY root_key_handle = NULL;
    const char *sub_key = NULL;
    int i = 0;

    // Check if registries are configured - if syscheck.registry is NULL or empty,
    // but we have data in the database, we need to send DataClean for registry indices
    if (syscheck.registry == NULL || syscheck.registry[0].entry == NULL) {
        int registry_keys_count = fim_db_get_count_registry_key();
        int registry_values_count = fim_db_get_count_registry_data();

        if (registry_keys_count > 0 || registry_values_count > 0) {
            mdebug1("No registry paths configured but database has %d keys and %d values. Initiating DataClean for registries.",
                    registry_keys_count, registry_values_count);

            if (syscheck.sync_handle) {
                // Prepare indices vector for data clean notification
                const char* indices[2] = {NULL, NULL};
                size_t indices_count = 0;

                if (registry_keys_count > 0) {
                    indices[indices_count++] = FIM_REGISTRY_KEYS_SYNC_INDEX;
                }
                if (registry_values_count > 0) {
                    indices[indices_count++] = FIM_REGISTRY_VALUES_SYNC_INDEX;
                }

                // Send DataClean notification for registry indices
                bool dataCleanSent = asp_notify_data_clean(syscheck.sync_handle, indices, indices_count);
                if (dataCleanSent) {
                    minfo("DataClean notification sent successfully for registry indices (all registry paths removed from configuration).");
                } else {
                    mwarn("DataClean notification failed for registry indices. Indexer may retain stale registry data.");
                }

                // Clear registry tables from both databases
                fim_db_clean_registry_tables();
            } else {
                mdebug1("Sync protocol not initialized, cannot send DataClean notification for registries.");
            }
        }
        mdebug1(FIM_WINREGISTRY_ENDED);
        return;
    }

    // Create lists for deferred deletion of validation failures
    OSList *failed_keys = OSList_Create();
    OSList *failed_values = OSList_Create();
    if (!failed_keys || !failed_values) {
        merror("Failed to create failed registry lists for schema validation cleanup");
        if (failed_keys) OSList_Destroy(failed_keys);
        if (failed_values) OSList_Destroy(failed_values);
        return;
    }
    // Set free functions that will free the structures AND their string members
    OSList_SetFreeDataPointer(failed_keys, (void (*)(void *))free);
    OSList_SetFreeDataPointer(failed_values, (void (*)(void *))free);

    // Create lists for pending sync flag updates
    OSList *pending_sync_keys = OSList_Create();
    OSList *pending_sync_values = OSList_Create();
    if (!pending_sync_keys || !pending_sync_values) {
        merror("Failed to create pending sync lists for registry");
        if (pending_sync_keys) OSList_Destroy(pending_sync_keys);
        if (pending_sync_values) OSList_Destroy(pending_sync_values);
        if (failed_keys) OSList_Destroy(failed_keys);
        if (failed_values) OSList_Destroy(failed_values);
        return;
    }
    OSList_SetFreeDataPointer(pending_sync_keys, free_pending_sync_item);
    OSList_SetFreeDataPointer(pending_sync_values, free_pending_sync_item);

    // Initialize synced docs counters from database before scan
    synced_docs_registry_keys = fim_db_count_synced_docs(FIMDB_REGISTRY_KEY_TABLENAME);
    synced_docs_registry_values = fim_db_count_synced_docs(FIMDB_REGISTRY_VALUE_TABLENAME);

    event_data_t evt_data_registry_key = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
    fim_key_txn_context_t txn_ctx_reg = { .evt_data = &evt_data_registry_key, .config = NULL, .failed_keys = failed_keys, .pending_sync_updates = pending_sync_keys };
    TXN_HANDLE regkey_txn_handler = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, registry_key_transaction_callback, &txn_ctx_reg);
    event_data_t evt_data_registry_value = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
    fim_val_txn_context_t txn_ctx_regval = { .evt_data = &evt_data_registry_value, .config = NULL, .failed_values = failed_values, .pending_sync_updates = pending_sync_values };
    TXN_HANDLE regval_txn_handler = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE,
                                                             registry_value_transaction_callback, &txn_ctx_regval);

    w_mutex_lock(&syscheck.fim_registry_scan_mutex);
    /* Debug entries */
    mdebug1(FIM_WINREGISTRY_START);
    /* Get sub class and a valid registry entry */
    for (i = 0; syscheck.registry[i].entry; i++) {
        /* Ignored entries are zeroed */
        if (*syscheck.registry[i].entry == '\0') {
            continue;
        }

        /* Read syscheck registry entry */
        mdebug2(FIM_READING_REGISTRY, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32] ",
                syscheck.registry[i].entry);

        if (fim_set_root_key(&root_key_handle, syscheck.registry[i].entry, &sub_key) != 0) {
            mdebug1(FIM_INV_REG, syscheck.registry[i].entry,
                    syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32]");
            *syscheck.registry[i].entry = '\0';
            continue;
        }
        fim_open_key(root_key_handle, syscheck.registry[i].entry, sub_key, syscheck.registry[i].arch, FIM_SCHEDULED,
                     NULL, regkey_txn_handler, regval_txn_handler, &txn_ctx_regval, &txn_ctx_reg);
    }
    w_mutex_unlock(&syscheck.fim_registry_scan_mutex);
    txn_ctx_reg.key = NULL;
    txn_ctx_regval.data = NULL;
    fim_db_transaction_deleted_rows(regval_txn_handler, registry_value_transaction_callback, &txn_ctx_regval);
    fim_db_transaction_deleted_rows(regkey_txn_handler, registry_key_transaction_callback, &txn_ctx_reg);
    regkey_txn_handler = NULL;
    regval_txn_handler = NULL;

    // Process pending sync flag updates after transaction commit
    if (pending_sync_keys != NULL) {
        process_pending_sync_updates(FIMDB_REGISTRY_KEY_TABLENAME, pending_sync_keys);
        OSList_Destroy(pending_sync_keys);
    }
    if (pending_sync_values != NULL) {
        process_pending_sync_updates(FIMDB_REGISTRY_VALUE_TABLENAME, pending_sync_values);
        OSList_Destroy(pending_sync_values);
    }

    // Delete registry keys and values that failed schema validation (outside transaction)
    cleanup_failed_registry_keys(failed_keys);
    cleanup_failed_registry_values(failed_values);

    OSList_Destroy(failed_keys);
    OSList_Destroy(failed_values);

    mdebug1(FIM_WINREGISTRY_ENDED);
}

#endif
