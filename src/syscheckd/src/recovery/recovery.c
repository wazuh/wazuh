#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <cJSON.h>

#include "debug_op.h"
#include "shared.h"
#include "recovery.h"
#include "syscheck-config.h"
#include "time_op.h"
#include "db.h"
#include "agent_sync_protocol_c_interface.h"
#include "sha1_op.h"
#include "file.h"
#include "schemaValidator_c.h"
#ifdef WIN32
#include "utf8_winapi_wrapper.h"
#include "registry.h"
#endif

/**
 * @brief Build stateful event for a file from cJSON object
 * @param path File path
 * @param file_data cJSON object containing file attributes
 * @param sha1_hash SHA1 hash of the file
 * @param document_version Version number of the document
 * @return Stateful event as a cJSON object (must be freed by caller), NULL on error
 */
cJSON* buildFileStatefulEvent(const char* path, cJSON* file_data, const char* sha1_hash, uint64_t document_version, const OSList *directories_list) {
    if (!path || !file_data || !sha1_hash || !directories_list) {
        merror("Invalid parameters to buildFileStatefulEvent");
        return NULL;
    }

    // Patch the inode from int to string, like fim_db_file_update does in file.cpp
    cJSON* inode_item = cJSON_GetObjectItem(file_data, "inode");
    if (inode_item && cJSON_IsNumber(inode_item)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lu", (unsigned long)cJSON_GetNumberValue(inode_item));

        if (inode_item->valuestring) {
            free(inode_item->valuestring);
        }
        inode_item->type = cJSON_String;
        inode_item->valuestring = strdup(buf);
    }
    // Call the actual builder
    cJSON* result = build_stateful_event_file(path, sha1_hash, document_version, file_data, NULL, directories_list);

    return result;
}

#ifdef WIN32
/**
 * @brief Build stateful event for a registry key from cJSON object
 * @param path Registry key path
 * @param key_data cJSON object containing registry key attributes
 * @param sha1_hash SHA1 hash of the key
 * @param document_version Version number of the document
 * @param arch Architecture (ARCH_32BIT or ARCH_64BIT)
 * @return Stateful event as a cJSON object (must be freed by caller), NULL on error
 */
cJSON* buildRegistryKeyStatefulEvent(const char* path, cJSON* key_data, const char* sha1_hash, uint64_t document_version, int arch) {
    return build_stateful_event_registry_key(path, sha1_hash, document_version, arch, key_data, NULL);
}

/**
 * @brief Build stateful event for a registry value from cJSON object
 * @param path Registry value path
 * @param value_data cJSON object containing registry value attributes
 * @param sha1_hash SHA1 hash of the value
 * @param document_version Version number of the document
 * @param arch Architecture (ARCH_32BIT or ARCH_64BIT)
 * @return Stateful event as a cJSON object (must be freed by caller), NULL on error
 */
cJSON* buildRegistryValueStatefulEvent(const char* path, char* value, cJSON* value_data, const char* sha1_hash, uint64_t document_version, int arch) {
    return build_stateful_event_registry_value(path, value, sha1_hash, document_version, arch, value_data, NULL);
}
#endif // WIN32

void fim_recovery_persist_table_and_resync(char* table_name, AgentSyncProtocolHandle* handle, const OSList *directories_list){
    int increase_result = fim_db_increase_each_entry_version(table_name);
    if (increase_result == -1) {
        merror("Failed to increase version for each entry in %s", table_name);
        return;
    }
    // Get all synced items from the table
    cJSON* items = fim_db_get_every_element(table_name, "WHERE sync=1");
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

        // Create a working copy to avoid any corruption of the items array
        cJSON* item_copy = cJSON_Duplicate(item, 1);
        if (!item_copy) {
            merror("Failed to duplicate item at index %d", i);
            continue;
        }

        // Extract common fields from the copy
        cJSON* path_obj = cJSON_GetObjectItem(item_copy, "path");
        cJSON* checksum_obj = cJSON_GetObjectItem(item_copy, "checksum");
        cJSON* version_obj = cJSON_GetObjectItem(item_copy, "version");

        const char* path = cJSON_GetStringValue(path_obj);
        const char* checksum = cJSON_GetStringValue(checksum_obj);

        if (!path || !checksum || !version_obj) {
            merror("Missing required fields in item at index %d", i);
            cJSON_Delete(item_copy);
            continue;
        }

        uint64_t document_version = (uint64_t)cJSON_GetNumberValue(version_obj);

        // Calculate ID and index based on table type
        char* id_str = NULL;
        const char* index = NULL;

#ifdef WIN32
        int arch = 0;
        char* value = NULL;
#endif
        if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
            id_str = strdup(path);
            index = FIM_FILES_SYNC_INDEX;
        }
#ifdef WIN32
        else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
            cJSON* arch_obj = cJSON_GetObjectItem(item_copy, "architecture");
            const char* arch_str = cJSON_GetStringValue(arch_obj);
            arch = (strcmp(arch_str, "[x32]") == 0) ? ARCH_32BIT : ARCH_64BIT;

            // Build id as "arch:path"
            size_t id_len = snprintf(NULL, 0, "%d:%s", arch, path) + 1;
            os_calloc(id_len, sizeof(char), id_str);
            snprintf(id_str, id_len, "%d:%s", arch, path);
            index = FIM_REGISTRY_KEYS_SYNC_INDEX;
        }
        else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
            cJSON* arch_obj = cJSON_GetObjectItem(item_copy, "architecture");
            cJSON* value_obj = cJSON_GetObjectItem(item_copy, "value");
            const char* arch_str = cJSON_GetStringValue(arch_obj);
            value = cJSON_GetStringValue(value_obj);
            arch = (strcmp(arch_str, "[x32]") == 0) ? ARCH_32BIT : ARCH_64BIT;

            // Build id as "path:arch:value"
            size_t id_len = snprintf(NULL, 0, "%s:%d:%s", path, arch, value) + 1;
            os_calloc(id_len, sizeof(char), id_str);
            snprintf(id_str, id_len, "%s:%d:%s", path, arch, value);
            index = FIM_REGISTRY_VALUES_SYNC_INDEX;
        }
#endif // WIN32
        else {
            merror("Invalid table name: %s", table_name);
            cJSON_Delete(item_copy);
            cJSON_Delete(items);
            return;
        }

        // Calculate SHA1 hash of id
        os_sha1 hashed_id;
        OS_SHA1_Str(id_str, -1, hashed_id);

        // Build stateful event using the copy
        cJSON* stateful_event = NULL;

        if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
            stateful_event = buildFileStatefulEvent(path, item_copy, checksum, document_version, directories_list);
        }
#ifdef WIN32
        else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
            stateful_event = buildRegistryKeyStatefulEvent(path, item_copy, checksum, document_version, arch);
        }
        else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
            stateful_event = buildRegistryValueStatefulEvent(path, value, item_copy, checksum, document_version, arch);
        }
#endif // WIN32
        if (stateful_event) {
            char* stateful_event_str = cJSON_PrintUnformatted(stateful_event);
            if (stateful_event_str) {
                // Validate stateful event before persisting for recovery
                bool validation_passed = true;
                if (schema_validator_is_initialized()) {
                    char* errorMessage = NULL;

                    if (!schema_validator_validate(index, stateful_event_str, &errorMessage)) {
                        // Validation failed - log but don't persist
                        if (errorMessage) {
                            merror("Schema validation failed for recovery event (table: %s, id: %s, index: %s). Errors: %s",
                                   table_name, id_str, index, errorMessage);
                            os_free(errorMessage);
                        }

                        merror("Raw recovery event that failed validation: %s", stateful_event_str);
                        mdebug1("Skipping persistence of invalid recovery event for %s", id_str);
                        validation_passed = false;
                    }
                }

                // Persist only if validation passed
                if (validation_passed) {
                    asp_persist_diff_in_memory(handle, hashed_id, OPERATION_CREATE, index, stateful_event_str, document_version);
                }

                os_free(stateful_event_str);
            }
            cJSON_Delete(stateful_event);
        }

        // Clean up the working copy
        cJSON_Delete(item_copy);
        os_free(id_str);
    }

    mdebug1("Persisted %d recovery items in memory", item_count);
    mdebug1("Starting recovery synchronization...");

    // Clean up items array
    cJSON_Delete(items);

    // Synchronize
    bool success = asp_sync_module(handle, MODE_FULL);

    if (success) {
        mdebug1("Recovery completed successfully");
    } else {
        mdebug1("Recovery synchronization failed, will retry later");
    }
}

// Excluding from coverage since this function is a simple wrapper around calculateTableChecksum and requiresFullSync
// LCOV_EXCL_START
bool fim_recovery_check_if_full_sync_required(char* table_name, AgentSyncProtocolHandle* handle){
    mdebug1("Attempting to get checksum for %s table", table_name);

    char* final_checksum = fim_db_calculate_table_checksum(table_name);
    if (!final_checksum) {
        merror("Failed to calculate checksum for table: %s", table_name);
        return false;
    }

    mdebug1("Success! Final file table checksum is: %s", final_checksum);

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
    os_free(final_checksum);

    if (needs_full_sync) {
        mdebug1("Checksum mismatch detected for table %s, full sync required", table_name);
    } else {
        mdebug1("Checksum valid for table %s, delta sync sufficient", table_name);
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
