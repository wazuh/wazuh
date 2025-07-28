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
#include "file/file.h"
#include "registry/registry.h"
#ifdef __linux__
#ifdef ENABLE_AUDIT
#include "ebpf/include/ebpf_whodata.h"
#endif /* ENABLE_AUDIT */
#endif /* __linux__ */

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

time_t fim_scan() {
    struct timespec start;
    struct timespec end;
    time_t end_of_scan;
    clock_t cputime_start;
    int nodes_count = 0;

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

    fim_diff_folder_size();
    syscheck.disk_quota_full_msg = true;

    mdebug2(FIM_DIFF_FOLDER_SIZE, DIFF_DIR, syscheck.diff_folder_size);

    update_wildcards_config();

    // First file scan
    fim_file_scan();

    // Check if a second file scan is needed
    if (syscheck.file_limit_enabled) {
        nodes_count = fim_db_get_count_file_entry();

        if (nodes_count >= syscheck.file_entry_limit) {
            fim_file_scan();
        }
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

    if (isDebug()) {
        fim_print_info(start, end, cputime_start); // LCOV_EXCL_LINE
    }
    audit_queue_full_reported = 0;

#ifdef __linux__
#ifdef ENABLE_AUDIT
    ebpf_kernel_queue_full_reported = 0;
#endif /* ENABLE_AUDIT */
#endif  /* __linux__ */

    return end_of_scan;
}

void fim_realtime_event(char *file) {
    struct stat file_stat;

    // If the file exists, generate add or modify events.
    if (w_lstat(file, &file_stat) >= 0) {
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
void create_unix_who_data_events(void * data, void * ctx)
{
    char *path = (char *)data;
    whodata_evt *w_evt = (whodata_evt *)ctx;

    fim_process_missing_entry(path, FIM_WHODATA, w_evt);
}

void fim_whodata_event(whodata_evt * w_evt) {
    struct stat file_stat;

    // If the file exists, generate add or modify events.
    if(w_lstat(w_evt->path, &file_stat) >= 0) {
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
        const unsigned long int device = strtoul(w_evt->dev, NULL, 10);
        callback_context_t callback_data;
        callback_data.callback = create_unix_who_data_events;
        callback_data.context = w_evt;
        fim_db_file_inode_search(inode, device, callback_data);
#endif
    }
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
            if ((FIM_MODE(dir_it->options) == FIM_WHODATA) && syscheck.whodata_provider == AUDIT_PROVIDER) {
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

        // Remove the directory from the DB
        event_data_t evt_data = {
            .mode = FIM_SCHEDULED,
            .w_evt = NULL,
            .report_event = true,
            .type = FIM_DELETE
        };

        fim_handle_delete_by_path(dir_it->path, &evt_data, dir_it, true, true);

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
