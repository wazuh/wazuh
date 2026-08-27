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

bool fim_recovery_persist_table_and_resync(char* table_name, AgentSyncProtocolHandle* handle, const OSList *directories_list){
    int increase_result = fim_db_increase_each_entry_version(table_name);
    if (increase_result == -1) {
        merror("Failed to increase version for each entry in %s", table_name);
        return false;
    }
    // Get all synced items from the table
    cJSON* items = fim_db_get_every_element(table_name, "WHERE sync=1");
    if (!items) {
        merror("Failed to retrieve elements from table: %s", table_name);
        return false;
    }

    int item_count = cJSON_GetArraySize(items);

    // The sync index only depends on the table, not on any individual item.
    const char* recovery_index = NULL;
    if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
        recovery_index = FIM_FILES_SYNC_INDEX;
    }
#ifdef WIN32
    else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
        recovery_index = FIM_REGISTRY_KEYS_SYNC_INDEX;
    }
    else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
        recovery_index = FIM_REGISTRY_VALUES_SYNC_INDEX;
    }
#endif
    else {
        merror("Invalid table name: %s", table_name);
        cJSON_Delete(items);
        return false;
    }

    // Clear the manager's index for this table before resending: recovery is now a
    // DataClean followed by a DELTA sync of the fresh snapshot, never Mode::FULL (which
    // used to make the manager unconditionally deleteByQuery over a byte-capped/truncated
    // payload and could permanently drop whatever didn't fit in that one session).
    const char* clean_indices[] = { recovery_index };
    if (!asp_notify_data_clean(handle, clean_indices, 1)) {
        merror("Failed to clear index '%s' before recovery resync for table %s; will retry later",
               recovery_index, table_name);
        cJSON_Delete(items);
        return false;
    }

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
            return false;
        }

        // Calculate SHA1 hash of id
        os_sha1 hashed_id;
        OS_SHA1_Str(id_str, -1, hashed_id);

        // Build stateful event using the copy
        cJSON* stateful_event = NULL;

        if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
            // Skip rows whose path is no longer covered by the current FIM configuration
            // (e.g. a group with a realtime rule was removed since the row was synced).
            // The scheduled scan emits the real DELETE for these rows via handle_orphaned_delete.
            if (fim_configuration_directory(path, false, directories_list) == NULL) {
                mdebug2("Skipping recovery of orphaned path (no active configuration): %s", path);
                cJSON_Delete(item_copy);
                os_free(id_str);
                continue;
            }
            stateful_event = buildFileStatefulEvent(path, item_copy, checksum, document_version, directories_list);
        }
#ifdef WIN32
        else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0 ||
                 strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
            // Same reasoning as the file_entry branch above, resolved against syscheck.registry:
            // a shared-config push can replace the <syscheck> registry entries, leaving rows whose
            // path no longer matches any configured entry for this architecture.
            if (fim_registry_configuration(path, arch) == NULL) {
                mdebug2("Skipping recovery of orphaned path (no active configuration): %s", path);
                cJSON_Delete(item_copy);
                os_free(id_str);
                continue;
            }

            if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
                stateful_event = buildRegistryKeyStatefulEvent(path, item_copy, checksum, document_version, arch);
            } else {
                stateful_event = buildRegistryValueStatefulEvent(path, value, item_copy, checksum, document_version, arch);
            }
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
                    asp_persist_diff(handle, hashed_id, OPERATION_CREATE, index, stateful_event_str, document_version);
                }

                os_free(stateful_event_str);
            }
            cJSON_Delete(stateful_event);
        }

        // Clean up the working copy
        cJSON_Delete(item_copy);
        os_free(id_str);
    }

    mdebug1("Persisted %d recovery items", item_count);
    mdebug1("Starting recovery synchronization...");

    // Clean up items array
    cJSON_Delete(items);

    // Synchronize
    SyncModuleResult_t result = asp_sync_module(handle, MODE_DELTA);

    if (result.success) {
        mdebug1("Recovery completed successfully");
    } else {
        mdebug1("Recovery synchronization failed, will retry later%s%s", result.failure_reason[0] != '\0' ? ": " : "", result.failure_reason);
    }

    // True from here on: the manager accepted the DataClean above and every row is queued, so
    // a caller gating durable state on this is recording something the manager really saw. A
    // failed final sync is not that -- the rows stay queued and the ordinary cycle drains them.
    return true;
}

/* Declared here rather than by including syscheck.h: that header pulls in audit_op.h and with it
 * the kernel's linux/audit.h, which is not on this translation unit's include path. */
bool fim_shutdown_process_on(void);

bool fim_resync_on_agent_id_change(AgentSyncProtocolHandle* handle, char** table_names, int table_count, const OSList* directories_list) {
    const long current_id = asp_get_agent_id();

    if (current_id == 0) {
        // Nothing published yet. "Unknown" -- an unavailable provider, or one still holding the
        // previous id, must never read as a new identity.
        return false;
    }

    int64_t synced_id = 0;

    if (!fim_db_try_get_last_sync_time(FIM_SYNCED_AGENT_ID_METADATA_KEY, &synced_id)) {
        // The read itself failed -- a busy database, not an answer. Adopting here would be the
        // worst outcome available: a single transient failure in the window right after a
        // re-enrollment would record the new id as already synchronized and suppress the resync
        // permanently. Treat it like an unknown id and try again next cycle.
        return false;
    }

    if (synced_id <= 0) {
        if (fim_shutdown_process_on()) {
            // "Absent" is not trustworthy here. FIMDB::executeQuery answers a read with a silent
            // no-op once the database is stopping or not yet initialized, and that reaches this
            // caller as a clean read of an empty row -- the one ambiguity this whole decision
            // procedure exists to avoid. FIMDB::updateItem is gated by the identical condition
            // today, so the adoption below would write nothing anyway, but that is two distant
            // guards happening to agree rather than a contract either of them states. Refuse
            // explicitly and let the next boot decide with a database that can answer.
            return false;
        }

        // Read cleanly, and nothing recorded: a clean install, or a database from before this
        // marker existed. Adopt it and resync nothing -- on a clean install the ordinary first
        // sync covers it, and on an upgraded agent the manager's copy is the one this agent has
        // been maintaining all along.
        fim_db_update_last_sync_time_value(FIM_SYNCED_AGENT_ID_METADATA_KEY, (int64_t)current_id);
        return false;
    }

    if (synced_id == (int64_t)current_id) {
        return false;
    }

    minfo("FIM data was last synchronized as agent %ld, now running as agent %ld. Resending every monitored entry.",
          (long)synced_id, current_id);

    bool any_failed = false;

    for (int i = 0; i < table_count; i++) {
        if (fim_shutdown_process_on()) {
            // Cut short by shutdown, like the integrity loop that follows this one: leave the
            // marker alone so the next boot re-fires rather than recording a partial pass.
            return false;
        }

        if (!fim_recovery_persist_table_and_resync(table_names[i], handle, directories_list)) {
            // Keep going, like Syscollector::checkAgentIdentity(): the tables that can be resent
            // should be, and abandoning the pass here would make every later one re-clear and
            // re-upload the tables that had already succeeded. On Windows this is three tables,
            // not one. The marker is the part that must not move -- recording it would claim the
            // manager holds data it never received -- so remember the failure for the end.
            any_failed = true;
        }
    }

    if (any_failed) {
        // Not fully resynchronized, so the identity is not adopted and the next cycle retries.
        return false;
    }

    fim_db_update_last_sync_time_value(FIM_SYNCED_AGENT_ID_METADATA_KEY, (int64_t)current_id);
    return true;
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
