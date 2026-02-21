/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Syscheck
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 */

#include "cJSON.h"
#include "debug_op.h"
#include "shared.h"
#include "syscheck.h"
#include "rootcheck.h"
#include "file.h"
#include "db.h"
#include "fimCommonDefs.h"
#include "ebpf_whodata.h"
#include "agent_sync_protocol_c_interface.h"
#include "schemaValidator_c.h"
#include "agentd_query.h"
#include <limits.h>

// Global variables
syscheck_config syscheck;
int notify_scan = 0;
int sys_debug_level;
int audit_queue_full_reported = 0;
int synced_docs_files = 0;
int synced_docs_registry_keys = 0;
int synced_docs_registry_values = 0;

#ifdef USE_MAGIC
#include <magic.h>
magic_t magic_cookie = 0;


void init_magic(magic_t *cookie_ptr)
{
    if (!cookie_ptr || *cookie_ptr) {
        return;
    }

    *cookie_ptr = magic_open(MAGIC_MIME_TYPE);

    if (!*cookie_ptr) {
        const char *err = magic_error(*cookie_ptr);
        merror(FIM_ERROR_LIBMAGIC_START, err ? err : "unknown");
    } else if (magic_load(*cookie_ptr, NULL) < 0) {
        const char *err = magic_error(*cookie_ptr);
        merror(FIM_ERROR_LIBMAGIC_LOAD, err ? err : "unknown");
        magic_close(*cookie_ptr);
        *cookie_ptr = 0;
    }
}
#endif /* USE_MAGIC */

/* Read syscheck internal options */
void read_internal(int debug_level)
{
    syscheck.rt_delay = getDefine_Int("syscheck", "rt_delay", 0, 1000);
    syscheck.max_depth = getDefine_Int("syscheck", "default_max_depth", 1, 320);
    syscheck.file_max_size = (size_t)getDefine_Int("syscheck", "file_max_size", 0, 4095) * 1024 * 1024;
    syscheck.sym_checker_interval = getDefine_Int("syscheck", "symlink_scan_interval", 1, 2592000);

#ifndef WIN32
    syscheck.max_audit_entries = getDefine_Int("syscheck", "max_audit_entries", 1, 4096);
#endif
    sys_debug_level = getDefine_Int("syscheck", "debug", 0, 2);

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        int debug_level = sys_debug_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    return;
}

void free_pending_sync_item(void *data) {
    if (data) {
        pending_sync_item_t *item = (pending_sync_item_t *)data;
        cJSON_Delete(item->json);
        free(item);
    }
}

void add_pending_sync_item(OSList *pending_items, const cJSON *json, int sync_value) {
    if (pending_items == NULL || json == NULL) {
        return;
    }

    pending_sync_item_t *item = (pending_sync_item_t *)malloc(sizeof(pending_sync_item_t));
    if (item == NULL) {
        merror("Failed to allocate memory for pending sync item");
        return;
    }

    item->json = cJSON_Duplicate(json, true);
    if (item->json == NULL) {
        merror("Failed to duplicate item for pending sync item");
        free(item);
        return;
    }

    item->sync_value = sync_value;

    OSList_AddData(pending_items, item);

    const cJSON* path = cJSON_GetObjectItem(json, "path");
    const cJSON* version = cJSON_GetObjectItem(json, "version");

    if (cJSON_IsString(path) && cJSON_IsNumber(version)) {
        mdebug2("Added item to pending sync list: %s (version: %d, sync: %d)",
                cJSON_GetStringValue(path), (int)cJSON_GetNumberValue(version), sync_value);
    } else {
        mdebug2("Added item to pending sync list (sync: %d)", sync_value);
    }
}

void process_pending_sync_updates(char* table_name, OSList *pending_items) {
    if (pending_items == NULL) {
        return;
    }

    int count = 0;
    OSListNode *node_it;
    OSList_foreach(node_it, pending_items) {
        pending_sync_item_t *item = (pending_sync_item_t *)node_it->data;
        if (item != NULL && item->json != NULL) {
            const cJSON* path = cJSON_GetObjectItem(item->json, "path");
            mdebug2("Setting sync=%d for path: %s", item->sync_value, cJSON_GetStringValue(path));
            fim_db_set_sync_flag(table_name, item, item->sync_value);
            count++;
        }
    }
    mdebug1("Processed %d pending sync flag updates", count);
}

/**
 * @brief Extract primary keys from full document for sync flag update
 *
 * @param table_name Name of the table
 * @param full_doc Full document JSON
 * @return cJSON object with only primary keys and version, or NULL on error
 */
cJSON* extract_primary_keys(const char* table_name, const cJSON* full_doc) {
    cJSON* keys = cJSON_CreateObject();
    if (!keys) {
        return NULL;
    }

    // All tables have path and version
    const cJSON* path = cJSON_GetObjectItem(full_doc, "path");
    const cJSON* version = cJSON_GetObjectItem(full_doc, "version");

    if (path) cJSON_AddStringToObject(keys, "path", cJSON_GetStringValue(path));
    if (version) cJSON_AddNumberToObject(keys, "version", cJSON_GetNumberValue(version));

    // Registry tables also have architecture
    if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0 ||
        strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
        const cJSON* arch = cJSON_GetObjectItem(full_doc, "architecture");
        if (arch) cJSON_AddStringToObject(keys, "architecture", cJSON_GetStringValue(arch));
    }

    // Registry value table also has value field
    if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
        const cJSON* value = cJSON_GetObjectItem(full_doc, "value");
        if (value) cJSON_AddStringToObject(keys, "value", cJSON_GetStringValue(value));
    }

    return keys;
}

/**
 * @brief Send promoted documents to persistent queue
 *
 * @param table_name Name of the table (file_entry, registry_key, registry_data)
 * @param docs_to_promote cJSON array with full document data
 */
void persist_sync_documents(char* table_name, cJSON* docs, Operation_t operation) {
    if (!docs || !cJSON_IsArray(docs)) {
        return;
    }

    cJSON* item = NULL;
    int count = 0;
    const char* operation_name = (operation == OPERATION_CREATE) ? "promoted" : "demoted";

    cJSON_ArrayForEach(item, docs) {
        const cJSON* path_json = cJSON_GetObjectItem(item, "path");
        const cJSON* version_json = cJSON_GetObjectItem(item, "version");

        if (!path_json || !version_json) {
            mwarn("Skipping %s document with missing required fields", operation_name);
            continue;
        }

        const char* path = cJSON_GetStringValue(path_json);
        uint64_t document_version = (uint64_t)cJSON_GetNumberValue(version_json);

        // For promoted documents, checksum is required
        const char* checksum = NULL;
        if (operation == OPERATION_CREATE) {
            const cJSON* checksum_json = cJSON_GetObjectItem(item, "checksum");
            if (!checksum_json) {
                mwarn("Skipping promoted document with missing checksum");
                continue;
            }
            checksum = cJSON_GetStringValue(checksum_json);
        }

        cJSON* stateful_event = NULL;
        char id[FILE_PATH_SHA1_BUFFER_SIZE] = {0};
        const char* sync_index = NULL;

        // Build stateful event based on table type and operation
        if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
            sync_index = FIM_FILES_SYNC_INDEX;
            OS_SHA1_Str(path, -1, id);

            if (operation == OPERATION_CREATE) {
                stateful_event = build_stateful_event_file(path, checksum, document_version, item, NULL, syscheck.directories);
            } else {
                // Build minimal DELETE event for file
                stateful_event = cJSON_CreateObject();
                if (stateful_event) {
                    cJSON* file_obj = cJSON_CreateObject();
                    cJSON_AddItemToObject(stateful_event, "file", file_obj);
                    cJSON_AddStringToObject(file_obj, "path", path);

                    cJSON* state_obj = cJSON_CreateObject();
                    cJSON_AddItemToObject(stateful_event, "state", state_obj);
                    cJSON_AddNumberToObject(state_obj, "document_version", (double)document_version);
                }
            }
        }
#ifdef WIN32
        else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
            sync_index = FIM_REGISTRY_KEYS_SYNC_INDEX;
            const cJSON* arch_json = cJSON_GetObjectItem(item, "architecture");
            int arch = (strcmp(cJSON_GetStringValue(arch_json), "[x32]") == 0) ? ARCH_32BIT : ARCH_64BIT;

            char id_source[OS_MAXSTR] = {0};
            snprintf(id_source, OS_MAXSTR - 1, "%d:%s", arch, path);
            OS_SHA1_Str(id_source, -1, id);

            if (operation == OPERATION_CREATE) {
                stateful_event = build_stateful_event_registry_key(path, checksum, document_version, arch, item, NULL);
            } else {
                // Build minimal DELETE event for registry key
                stateful_event = cJSON_CreateObject();
                if (stateful_event) {
                    cJSON* registry_obj = cJSON_CreateObject();
                    cJSON_AddItemToObject(stateful_event, "registry", registry_obj);
                    cJSON_AddStringToObject(registry_obj, "path", path);
                    cJSON_AddStringToObject(registry_obj, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");

                    cJSON* state_obj = cJSON_CreateObject();
                    cJSON_AddItemToObject(stateful_event, "state", state_obj);
                    cJSON_AddNumberToObject(state_obj, "document_version", (double)document_version);
                }
            }
        }
        else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
            sync_index = FIM_REGISTRY_VALUES_SYNC_INDEX;
            const cJSON* arch_json = cJSON_GetObjectItem(item, "architecture");
            const cJSON* value_json = cJSON_GetObjectItem(item, "value");

            int arch = (strcmp(cJSON_GetStringValue(arch_json), "[x32]") == 0) ? ARCH_32BIT : ARCH_64BIT;
            const char* value = cJSON_GetStringValue(value_json);

            char id_source[OS_MAXSTR] = {0};
            snprintf(id_source, OS_MAXSTR - 1, "%s:%d:%s", path, arch, value);
            OS_SHA1_Str(id_source, -1, id);

            if (operation == OPERATION_CREATE) {
                stateful_event = build_stateful_event_registry_value(path, value, checksum, document_version, arch, item, NULL);
            } else {
                // Build minimal DELETE event for registry value
                stateful_event = cJSON_CreateObject();
                if (stateful_event) {
                    cJSON* registry_obj = cJSON_CreateObject();
                    cJSON_AddItemToObject(stateful_event, "registry", registry_obj);
                    cJSON_AddStringToObject(registry_obj, "path", path);
                    cJSON_AddStringToObject(registry_obj, "value", value);
                    cJSON_AddStringToObject(registry_obj, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");

                    cJSON* state_obj = cJSON_CreateObject();
                    cJSON_AddItemToObject(stateful_event, "state", state_obj);
                    cJSON_AddNumberToObject(state_obj, "document_version", (double)document_version);
                }
            }
        }
#endif

        if (stateful_event) {
            char item_desc[PATH_MAX + 128];
            // Use same description format as transaction callbacks
            if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
                snprintf(item_desc, sizeof(item_desc), "file %s", path);
            }
#ifdef WIN32
            else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
                snprintf(item_desc, sizeof(item_desc), "registry key %s", path);
            }
            else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
                const cJSON* value_json = cJSON_GetObjectItem(item, "value");
                const char* value = cJSON_GetStringValue(value_json);
                snprintf(item_desc, sizeof(item_desc), "registry value %s:%s", path, value);
            }
#endif

            // Send to persistent queue with sync_flag=1
            validate_and_persist_fim_event(stateful_event, id, operation,
                                          sync_index, document_version,
                                          item_desc, false, NULL, NULL, 1);
            cJSON_Delete(stateful_event);
            count++;
        }
    }

    mdebug1("Sent %d %s documents to persistent queue for table %s", count, operation_name, table_name);
}

static int fim_startmq(const char* key, short type, short attempts) {
    return StartMQ(key, type, attempts);
}

static int fim_send_binary_msg(int queue, const void* message, size_t message_len, const char* locmsg, char loc) {
    return SendBinaryMSG(queue, message, message_len, locmsg, loc);
}

/**
 * @brief Fetch document sync limits from agentd.
 *
 * Queries agentd for FIM document sync limits and updates syscheck configuration.
 * The limits control how many documents are synced for each table type.
 *
 * @return true if limits were successfully fetched and parsed, false otherwise.
 */
bool fetch_document_limits_from_agentd(){
    char json_buffer[OS_MAXSTR] = {0};

    if (!w_query_agentd(SYSCHECK, "getdoclimits fim", json_buffer, sizeof(json_buffer)))
    {
        mdebug1("Failed to query agentd for document limits");
        return false;
    }

    cJSON* root = cJSON_Parse(json_buffer);
    if (!root)
    {
        mdebug1("Failed to parse getdoclimits fim response");
        return false;
    }

    cJSON* file = cJSON_GetObjectItem(root, "file");
    if (file && cJSON_IsNumber(file))
    {
        const double value = cJSON_GetNumberValue(file);
        if (value >= 0)
        {
            syscheck.file_limit = (int)value;
        }
    }

    cJSON* registry_key = cJSON_GetObjectItem(root, "registry_key");
    if (registry_key && cJSON_IsNumber(registry_key))
    {
        const double value = cJSON_GetNumberValue(registry_key);
        if (value >= 0)
        {
            syscheck.registry_key_limit = (int)value;
        }
    }

    cJSON* registry_value = cJSON_GetObjectItem(root, "registry_value");
    if (registry_value && cJSON_IsNumber(registry_value))
    {
        const double value = cJSON_GetNumberValue(registry_value);
        if (value >= 0)
        {
            syscheck.registry_value_limit = (int)value;
        }
    }

    cJSON_Delete(root);
    return true;
}

void fim_initialize() {
    // Create store data
#ifndef WIN32
    FIMDBErrorCode ret_val = fim_db_init(FIM_DB_DISK,
                                         loggingFunction,
                                         syscheck.file_entry_limit,
                                         0,
                                         NULL);
#else
    FIMDBErrorCode ret_val = fim_db_init(FIM_DB_DISK,
                                         loggingFunction,
                                         syscheck.file_entry_limit,
                                         syscheck.db_entry_registry_limit,
                                         loggingErrorFunction);
#endif

    if (ret_val != FIMDB_OK) {
        merror("Unable to initialize database. FIM module will be disabled.");
        syscheck.disabled = 1;
        return;
    }

    syscheck.file_limit = 0;
    syscheck.registry_key_limit = 0;
    syscheck.registry_value_limit = 0;
    while (!fetch_document_limits_from_agentd())
    {
        mdebug1("Trying to fetch limits from agentd...");
#ifdef WIN32
        Sleep(1000);
#else
        sleep(1);
#endif // WIN32
    }

    // Initialize locks before sync handle creation
    w_rwlock_init(&syscheck.directories_lock, NULL);
    w_mutex_init(&syscheck.fim_scan_mutex, NULL);
    w_mutex_init(&syscheck.fim_realtime_mutex, NULL);
#ifdef WIN32
    w_mutex_init(&syscheck.fim_registry_scan_mutex, NULL);
#else
    w_mutex_init(&syscheck.fim_symlink_mutex, NULL);
#endif
    syscheck.fim_pause_requested = (atomic_int_t)ATOMIC_INT_INITIALIZER(0);
    syscheck.fim_pausing_is_allowed = (atomic_int_t)ATOMIC_INT_INITIALIZER(0);

    notify_scan = syscheck.notify_first_scan;

    // Initialize sync handle early so it's available for document promotion
    MQ_Functions mq_funcs = {
        .start = fim_startmq,
        .send_binary = fim_send_binary_msg
    };

    syscheck.sync_handle = asp_create("fim", FIM_SYNC_PROTOCOL_DB_PATH, &mq_funcs, loggingFunction, syscheck.sync_end_delay, syscheck.sync_response_timeout, FIM_SYNC_RETRIES, syscheck.sync_max_eps);
    if (!syscheck.sync_handle) {
        merror_exit("Failed to initialize AgentSyncProtocol");
    }

// Check for limit changes
#ifdef WIN32
    int table_count = 3;
    char* table_names[3] = {FIMDB_FILE_TABLE_NAME, FIMDB_REGISTRY_KEY_TABLENAME, FIMDB_REGISTRY_VALUE_TABLENAME};
#else
    int table_count = 1;
    char* table_names[1] = {FIMDB_FILE_TABLE_NAME};
#endif

    for (int i = 0; i < table_count; i++) {
        char* table_name = table_names[i];

        // Get the appropriate limit and synced_docs pointer for this table
        int limit = 0;
        int* synced_docs_ptr = NULL;
        if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
            limit = syscheck.file_limit;
            synced_docs_ptr = &synced_docs_files;
        } else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
            limit = syscheck.registry_key_limit;
            synced_docs_ptr = &synced_docs_registry_keys;
        } else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
            limit = syscheck.registry_value_limit;
            synced_docs_ptr = &synced_docs_registry_values;
        }

        *synced_docs_ptr = fim_db_count_synced_docs(table_name);
        if (*synced_docs_ptr != 0) { // No need to check if no scans have been run
            if (limit == 0) { // If moving from limited agent to unlimited, promote everything
                limit = INT_MAX;
            }
            if (*synced_docs_ptr < limit) { // Limit might have increased
                int document_count = limit - *synced_docs_ptr;
                cJSON* docs_to_promote = fim_db_get_documents_to_promote(table_name, document_count);

                if (docs_to_promote) { // Limit has increased
                    // Send promoted documents to persistent queue as CREATE events
                    minfo("Document limit increased from  %d to %d for index %s. Currently synced documents: %d", *synced_docs_ptr, limit, table_name, *synced_docs_ptr + cJSON_GetArraySize(docs_to_promote));
                    persist_sync_documents(table_name, docs_to_promote, OPERATION_CREATE);

                    OSList* pending_sync_updates = OSList_Create();
                    if (pending_sync_updates) {
                        OSList_SetFreeDataPointer(pending_sync_updates, free_pending_sync_item);

                        // Iterate through full documents and extract primary keys for sync flag update
                        cJSON* full_doc = NULL;
                        cJSON_ArrayForEach(full_doc, docs_to_promote) {
                            cJSON* primary_keys = extract_primary_keys(table_name, full_doc);
                            if (primary_keys) {
                                add_pending_sync_item(pending_sync_updates, primary_keys, 1);
                                cJSON_Delete(primary_keys);
                                (*synced_docs_ptr)++;
                            }
                        }

                        // Process pending sync updates
                        process_pending_sync_updates(table_name, pending_sync_updates);
                        OSList_Destroy(pending_sync_updates);
                    }
                    cJSON_Delete(docs_to_promote);
                }
            } else if (*synced_docs_ptr > limit) { // Limit might have decreased
                int document_count = *synced_docs_ptr - limit;
                cJSON* docs_to_demote = fim_db_get_documents_to_demote(table_name, document_count);

                if (docs_to_demote) { // Limit has decreased
                    minfo("Document limit decreased from %d to %d for table %s. Currently synced documents: %d", document_count, limit, table_name, limit);
                    // Send demoted documents to persistent queue as DELETE events
                    persist_sync_documents(table_name, docs_to_demote, OPERATION_DELETE);

                    OSList* pending_sync_updates = OSList_Create();
                    if (pending_sync_updates) {
                        OSList_SetFreeDataPointer(pending_sync_updates, free_pending_sync_item);

                        // Iterate through the cJSON array and add to pending list
                        cJSON* item = NULL;
                        cJSON_ArrayForEach(item, docs_to_demote) {
                            add_pending_sync_item(pending_sync_updates, item, 0);
                            (*synced_docs_ptr)--;
                        }

                        // Process pending sync updates
                        process_pending_sync_updates(table_name, pending_sync_updates);
                        OSList_Destroy(pending_sync_updates);
                    }
                    cJSON_Delete(docs_to_demote);
                }
            }
        }
    }

    // Initialize schema validator from embedded resources
    if (!schema_validator_is_initialized()) {
        if (schema_validator_initialize()) {
            minfo("Schema validator initialized successfully from embedded resources");
        } else {
            mwarn("Failed to initialize schema validator. Schema validation will be disabled.");
        }
    }
}


#ifdef WIN32
/* syscheck main for Windows */
int Start_win32_Syscheck() {
    int debug_level = 0;
    int r = 0;
    char *cfg = OSSECCONF;
    OSListNode *node_it;

    /* Read internal options */
    read_internal(debug_level);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit(NO_CONFIG, cfg);
    }

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        mwarn(RCONFIG_ERROR, SYSCHECK, cfg);
        syscheck.disabled = 1;
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        /* Disabled */
        minfo(FIM_DIRECTORY_NOPROVIDED);

        // Free directories list
        OSList_foreach(node_it, syscheck.directories) {
            free_directory(node_it->data);
            node_it->data = NULL;
        }
        OSList_CleanNodes(syscheck.directories);

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            os_free(syscheck.ignore[0]);
        }

        if (!syscheck.registry) {
            dump_syscheck_registry(&syscheck, "", 0, NULL, NULL,  0, NULL, 0, -1);
        }
        os_free(syscheck.registry[0].entry);

        minfo(FIM_DISABLED);
    }

    /* Rootcheck config */
    if (rootcheck_init(0) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
    }

    if (!syscheck.disabled) {
        directory_t *dir_it;
        OSListNode *node_it;
#ifndef WIN_WHODATA
        int whodata_notification = 0;
        /* Remove whodata attributes */
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            if (dir_it->options & WHODATA_ACTIVE) {
                if (!whodata_notification) {
                    whodata_notification = 1;
                    minfo(FIM_REALTIME_INCOMPATIBLE);
                }
                dir_it->options &= ~WHODATA_ACTIVE;
                dir_it->options |= REALTIME_ACTIVE;
            }
        }
#endif

        /* Print options */
        r = 0;
        // TODO: allow sha256 sum on registries
        while (syscheck.registry[r].entry != NULL) {
            char optstr[1024];
            minfo(FIM_MONITORING_REGISTRY, syscheck.registry[r].entry,
                  syscheck.registry[r].arch == ARCH_64BIT ? " [x64]" : "",
                  syscheck_opts2str(optstr, sizeof(optstr), syscheck.registry[r].opts));
            if (syscheck.file_size_enabled){
                mdebug1(FIM_DIFF_FILE_SIZE_LIMIT, syscheck.registry[r].diff_size_limit, syscheck.registry[r].entry);
            }
            r++;
        }

        /* Print directories to be monitored */
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            char optstr[ 1024 ];

            minfo(FIM_MONITORING_DIRECTORY, dir_it->path, syscheck_opts2str(optstr, sizeof(optstr), dir_it->options));

            if (dir_it->tag != NULL) {
                mdebug2(FIM_TAG_ADDED, dir_it->tag, dir_it->path);
            }

            // Print diff file size limit
            if ((dir_it->options & CHECK_SEECHANGES) && syscheck.file_size_enabled) {
                mdebug2(FIM_DIFF_FILE_SIZE_LIMIT, dir_it->diff_size_limit, dir_it->path);
            }
        }

        if (!syscheck.file_size_enabled) {
            minfo(FIM_FILE_SIZE_LIMIT_DISABLED);
        }

        // Print maximum disk quota to be used by the queue\diff\local folder
        if (syscheck.disk_quota_enabled) {
            mdebug2(FIM_DISK_QUOTA_LIMIT, syscheck.disk_quota_limit);
        }
        else {
            minfo(FIM_DISK_QUOTA_LIMIT_DISABLED);
        }

        /* Print ignores. */
        if(syscheck.ignore)
            for (r = 0; syscheck.ignore[r] != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "file", syscheck.ignore[r]);

        /* Print sregex ignores. */
        if(syscheck.ignore_regex)
            for (r = 0; syscheck.ignore_regex[r] != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "file", syscheck.ignore_regex[r]->raw);

        /* Print registry ignores. */
        if(syscheck.key_ignore)
            for (r = 0; syscheck.key_ignore[r].entry != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "registry", syscheck.key_ignore[r].entry);

        /* Print sregex registry ignores. */
        if(syscheck.key_ignore_regex)
            for (r = 0; syscheck.key_ignore_regex[r].regex != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "registry", syscheck.key_ignore_regex[r].regex->raw);

        if(syscheck.value_ignore)
            for (r = 0; syscheck.value_ignore[r].entry != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "value", syscheck.value_ignore[r].entry);

        /* Print sregex registry ignores. */
        if(syscheck.value_ignore_regex)
            for (r = 0; syscheck.value_ignore_regex[r].regex != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "value", syscheck.value_ignore_regex[r].regex->raw);

        /* Print registry values with nodiff. */
        if(syscheck.registry_nodiff)
            for (r = 0; syscheck.registry_nodiff[r].entry != NULL; r++)
                minfo(FIM_NO_DIFF_REGISTRY, "registry value", syscheck.registry_nodiff[r].entry);

        /* Print sregex registry values with nodiff. */
        if(syscheck.registry_nodiff_regex)
            for (r = 0; syscheck.registry_nodiff_regex[r].regex != NULL; r++)
                minfo(FIM_NO_DIFF_REGISTRY, "registry sregex", syscheck.registry_nodiff_regex[r].regex->raw);

        /* Print files with no diff. */
        if (syscheck.nodiff){
            r = 0;
            while (syscheck.nodiff[r] != NULL) {
                minfo(FIM_NO_DIFF, syscheck.nodiff[r]);
                r++;
            }
        }

        /* Start up message */
        minfo(STARTUP_MSG, getpid());
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            if (dir_it->options & REALTIME_ACTIVE) {
                realtime_start();
                break;
            }
        }

        if (syscheck.realtime == NULL) {
            // Check if a wildcard might require realtime later
            OSList_foreach(node_it, syscheck.wildcards) {
                dir_it = node_it->data;
                if (dir_it->options & REALTIME_ACTIVE) {
                    realtime_start();
                    break;
                }
            }
        }
    }

    /* Some sync time */
    fim_initialize();

    start_daemon();

    return 0;
}
#endif /* WIN32 */

#ifdef __linux__
#ifdef ENABLE_AUDIT
/* Wrapper for eBPF that provides syscheck.directories internally
 * This is cleaner than keeping a reference to syscheck.directories inside the ebpf instance.
 * eBPF uses the old 2-parameter signature, and this wrapper translates to the new 3-parameter version.
 * */
static directory_t *fim_configuration_directory_ebpf(const char *path, bool notify_not_found) {
    return fim_configuration_directory(path, notify_not_found, syscheck.directories);
}

void check_ebpf_availability() {
    minfo(FIM_EBPF_INIT);
    fimebpf_initialize(fim_configuration_directory_ebpf, get_user, get_group, fim_whodata_event,
                       free_whodata_event, loggingFunction, abspath, fim_shutdown_process_on, syscheck.queue_size);
    if (ebpf_whodata_healthcheck()) {
        mwarn(FIM_ERROR_EBPF_HEALTHCHECK);

        // Switch whodata eBPF to whodata audit
        syscheck.whodata_provider = AUDIT_PROVIDER;
    }
}
#endif /* ENABLE_AUDIT */
#endif /* __linux__ */
