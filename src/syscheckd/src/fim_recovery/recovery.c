#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cJSON.h>

#include "shared.h"
#include "recovery.h"
#include "../../config/syscheck-config.h"
#include "time_op.h"
#include "db.h"
#include "agent_sync_protocol_c_interface.h"
#include "../os_crypto/sha1/sha1_op.h"

#ifdef WIN32
#include "utf8_winapi_wrapper.h"
#endif

/**
 * @brief Build stateful event for a file from JSON string
 * @param path File path
 * @param file_json_str JSON string containing file attributes
 * @param sha1_hash SHA1 hash of the file
 * @param document_version Version number of the document
 * @return Stateful event as a JSON string (must be freed by caller), NULL on error
 */
static char* buildFileStatefulEventFromJSONString(const char* path, const char* file_json_str, const char* sha1_hash, uint64_t document_version) {
    // Parse input JSON
    cJSON* file_attributes = cJSON_Parse(file_json_str);
    if (file_attributes == NULL) {
        merror("Error parsing JSON for file: %s", path);
        return NULL;
    }

    // Patch inode: convert from number to string (same as file.c:fim_db_file_update)
    cJSON* inode_item = cJSON_GetObjectItem(file_attributes, "inode");
    if (inode_item != NULL && cJSON_IsNumber(inode_item)) {
        uint64_t inode_value = (uint64_t)cJSON_GetNumberValue(inode_item);
        char inode_str[32];
        snprintf(inode_str, sizeof(inode_str), "%lu", (unsigned long)inode_value);
        cJSON_DeleteItemFromObject(file_attributes, "inode");
        cJSON_AddStringToObject(file_attributes, "inode", inode_str);
    }

    cJSON* result = build_stateful_event_file(path, sha1_hash, document_version, file_attributes, NULL);

    return result;
}

#ifdef WIN32
/**
 * @brief Build stateful event for a registry key from JSON string
 * @param path Registry key path
 * @param key_json_str JSON string containing registry key attributes
 * @param sha1_hash SHA1 hash of the key
 * @param document_version Version number of the document
 * @param arch Architecture (ARCH_32BIT or ARCH_64BIT)
 * @return Stateful event as a JSON string (must be freed by caller), NULL on error
 */
static char* buildRegistryKeyStatefulEventFromJSONString(const char* path, const char* key_json_str, const char* sha1_hash, uint64_t document_version, int arch) {
    // Parse input JSON
    cJSON* file_attributes = cJSON_Parse(file_json_str);
    if (file_attributes == NULL) {
        merror("Error parsing JSON for file: %s", path);
        return NULL;
    }
    cJSON* result = build_stateful_event_file(path, sha1_hash, document_version, file_attributes, NULL);
    return result;
}

/**
 * @brief Build stateful event for a registry value from JSON string
 * @param path Registry value path
 * @param value_json_str JSON string containing registry value attributes
 * @param sha1_hash SHA1 hash of the value
 * @param document_version Version number of the document
 * @param arch Architecture (ARCH_32BIT or ARCH_64BIT)
 * @return Stateful event as a JSON string (must be freed by caller), NULL on error
 */
static char* buildRegistryValueStatefulEventFromJSONString(const char* path, const char* value_json_str, const char* sha1_hash, uint64_t document_version, int arch) {
    
}
#endif // WIN32

void fim_recovery_persist_table_and_resync(char* table_name, AgentSyncProtocolHandle* handle, SynchronizeModuleCallback test_callback){
    // Get all items from the table
    cJSON* items = fim_db_get_every_element(table_name);
    if (!items) {
        merror("Failed to retrieve elements from table: %s", table_name);
        return;
    }

    int item_count = cJSON_GetArraySize(items);

    // Make sure memory is clean before we start to persist
    asp_clear_in_memory_data(handle);

    // Process each item
    for (int i = 0; i < item_count; i++) {
        cJSON* item = cJSON_GetArrayItem(items, i);

        // Extract common fields
        cJSON* path_obj = cJSON_GetObjectItem(item, "path");
        cJSON* checksum_obj = cJSON_GetObjectItem(item, "checksum");
        cJSON* version_obj = cJSON_GetObjectItem(item, "version");

        const char* path = cJSON_GetStringValue(path_obj);
        const char* checksum = cJSON_GetStringValue(checksum_obj);
        uint64_t document_version = (uint64_t)cJSON_GetNumberValue(version_obj);

        // Calculate ID and index based on table type
        char* id_str = NULL;
        const char* index = NULL;
        int arch = 0;

        if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
            id_str = strdup(path);
            index = FIM_FILES_SYNC_INDEX;
        }
#ifdef WIN32
        else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
            cJSON* arch_obj = cJSON_GetObjectItem(item, "architecture");
            const char* arch_str = cJSON_GetStringValue(arch_obj);
            arch = (strcmp(arch_str, "[x32]") == 0) ? ARCH_32BIT : ARCH_64BIT;

            // Build id as "arch:path"
            size_t id_len = snprintf(NULL, 0, "%d:%s", arch, path) + 1;
            id_str = malloc(id_len);
            snprintf(id_str, id_len, "%d:%s", arch, path);
            index = FIM_REGISTRY_KEYS_SYNC_INDEX;
        }
        else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
            cJSON* arch_obj = cJSON_GetObjectItem(item, "architecture");
            cJSON* value_obj = cJSON_GetObjectItem(item, "value");
            const char* arch_str = cJSON_GetStringValue(arch_obj);
            const char* value = cJSON_GetStringValue(value_obj);
            arch = (strcmp(arch_str, "[x32]") == 0) ? ARCH_32BIT : ARCH_64BIT;

            // Build id as "path:arch:value"
            size_t id_len = snprintf(NULL, 0, "%s:%d:%s", path, arch, value) + 1;
            id_str = malloc(id_len);
            snprintf(id_str, id_len, "%s:%d:%s", path, arch, value);
            index = FIM_REGISTRY_VALUES_SYNC_INDEX;
        }
#endif // WIN32

        // Calculate SHA1 hash of id
        os_sha1 hashed_id;
        OS_SHA1_Str(id_str, -1, hashed_id);

        // Build stateful event
        char* item_str = cJSON_PrintUnformatted(item);
        char* stateful_event_str = NULL;

        if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
            stateful_event_str = buildFileStatefulEventFromJSONString(path, item_str, checksum, document_version);
        }
#ifdef WIN32
        else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
            stateful_event_str = buildRegistryKeyStatefulEventFromJSONString(path, item_str, checksum, document_version, arch);
        }
        else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
            stateful_event_str = buildRegistryValueStatefulEventFromJSONString(path, item_str, checksum, document_version, arch);
        }
#endif // WIN32

        if (stateful_event_str) {
            asp_persist_diff_in_memory(handle, hashed_id, CREATE, index, stateful_event_str, document_version);
            free(stateful_event_str);
        }

        free(item_str);
        free(id_str);
    }

    minfo("Persisted %d recovery items in memory", item_count);
    minfo("Starting recovery synchronization...");

    // Clean up items array
    cJSON_Delete(items);

    // Synchronize
    bool success;
    if (test_callback) { // TODO: see if still needed
        success = test_callback();
    } else {
        success = asp_sync_module(handle, MODE_FULL);
    }

    if (success) {
        minfo("Recovery completed successfully, in-memory data cleared");
    } else {
        minfo("Recovery synchronization failed, will retry later");
    }
}

// Excluding from coverage since this function is a simple wrapper around calculateTableChecksum and requiresFullSync
// LCOV_EXCL_START
bool fim_recovery_check_if_full_sync_required(char* table_name, AgentSyncProtocolHandle* handle){
    minfo("Attempting to get checksum for %s table", table_name);

    char* final_checksum = fim_db_calculate_table_checksum(table_name);
    if (!final_checksum) {
        merror("Failed to calculate checksum for table: %s", table_name);
        return false;
    }

    minfo("Success! Final file table checksum is: %s", final_checksum);

    // Determine index based on table name
    const char* index = NULL;
    if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
        index = FIM_FILES_SYNC_INDEX;
    }
#ifdef WIN32
    else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
        index = FIM_REGISTRY_KEYS_SYNC_INDEX;
    }
    else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
        index = FIM_REGISTRY_VALUES_SYNC_INDEX;
    }
#endif // WIN32

    bool needs_full_sync = asp_requires_full_sync(handle, index, final_checksum);
    free(final_checksum);

    if (needs_full_sync) {
        minfo("Checksum mismatch detected for table %s, full sync required", table_name);
    } else {
        minfo("Checksum valid for table %s, delta sync sufficient", table_name);
    }

    return needs_full_sync;
}
// LCOV_EXCL_STOP

bool fim_recovery_integrity_interval_has_elapsed(char* table_name, int64_t integrity_interval){
    int64_t current_time = (int64_t)time(NULL);
    int64_t last_sync_time = fim_db_get_last_sync_time(table_name);

    // If never checked before (last_sync_time == 0), initialize timestamp and don't run check yet
    // This enables integrity checks to run after the configured interval
    if (last_sync_time == 0) {
        fim_db_update_last_sync_time_value(table_name, current_time);
        return false;
    }

    int64_t new_sync_time = current_time - last_sync_time;
    return (new_sync_time >= integrity_interval);
}
