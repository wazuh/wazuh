/**
 * @file fim_sync.c
 * @brief Definition of FIM data synchronization library
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2020 Wazuh, Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include <openssl/evp.h>
#include "syscheck.h"
#include "integrity_op.h"
#include "db/fim_db.h"
#include "registry/registry.h"

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when unit testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#endif

#define FIM_COMPONENT_FILE      "fim_file"
#define FIM_COMPONENT_REGISTRY  "fim_registry"

static long fim_sync_cur_id;
static w_queue_t * fim_sync_queue;

// LCOV_EXCL_START
// Starting data synchronization thread
#ifdef WIN32
DWORD WINAPI fim_run_integrity(void __attribute__((unused)) * args) {
#else
void * fim_run_integrity(void * args) {
#endif
    // Keep track of synchronization failures
    long sync_interval = syscheck.sync_interval;
    struct timespec start;
    struct timespec end;

    fim_sync_queue = queue_init(syscheck.sync_queue_size);

    while (1) {
        bool sync_successful = true;

        mdebug1("Initializing FIM Integrity Synchronization check. Sync interval is %li seconds.", sync_interval);

        gettime(&start);
        fim_sync_checksum(FIM_TYPE_FILE, &syscheck.fim_entry_mutex);
#ifdef WIN32
        if (syscheck.enable_registry_synchronization) {
            fim_sync_checksum(FIM_TYPE_REGISTRY, &syscheck.fim_entry_mutex);
        }
#endif
        gettime(&end);

        mdebug2("Finished calculating FIM integrity. Time: %.3f seconds.", time_diff(&start, &end));

        struct timespec timeout = { .tv_sec = time(NULL) + sync_interval };

        // Get messages until timeout
        char * msg;

        while ((msg = queue_pop_ex_timedwait(fim_sync_queue, &timeout))) {
            long margin = time(NULL) + syscheck.sync_response_timeout;

            fim_sync_dispatch(msg);
            free(msg);

            // Wait for sync_response_timeout seconds since the last message received, or sync_interval
            timeout.tv_sec = timeout.tv_sec > margin ? timeout.tv_sec : margin;

            sync_successful = false;
        }

        if (sync_successful) {
            sync_interval = syscheck.sync_interval;
        }
        else {
            // Duplicate for every failure
            mdebug1("FIM Integrity Synchronization check failed. Adjusting sync interval for next run.");
            sync_interval *= 2;
            sync_interval = (sync_interval < syscheck.max_sync_interval) ? sync_interval : syscheck.max_sync_interval;
        }
    }

#ifndef WIN32
    return args;
#endif
}
// LCOV_EXCL_STOP

// Create file entry JSON from a FIM entry structure
cJSON *fim_entry_json(const char *key, fim_entry *entry) {
    assert(entry != NULL);
    assert(key != NULL);

    cJSON * attributes;
    cJSON * root = cJSON_CreateObject();

#ifndef WIN32
    cJSON_AddStringToObject(root, "path", key);

    cJSON_AddNumberToObject(root, "timestamp", entry->file_entry.data->last_event);

    attributes = fim_attributes_json(entry->file_entry.data);
#else
    if (entry->type == FIM_TYPE_FILE) {
        cJSON_AddStringToObject(root, "path", key);

        cJSON_AddNumberToObject(root, "timestamp", entry->file_entry.data->last_event);

        attributes = fim_attributes_json(entry->file_entry.data);
    } else if (entry->registry_entry.value == NULL) {
        registry *configuration = fim_registry_configuration(entry->registry_entry.key->path,
                                                             entry->registry_entry.key->arch);

        cJSON_AddStringToObject(root, "path", entry->registry_entry.key->path);
        cJSON_AddStringToObject(root, "arch", entry->registry_entry.key->arch == ARCH_64BIT ? "[x64]" : "[x32]");
        cJSON_AddNumberToObject(root, "timestamp", entry->registry_entry.key->last_event);

        attributes = fim_registry_key_attributes_json(entry->registry_entry.key, configuration);
    } else {
        char buffer[OS_MAXSTR];
        registry *configuration;

        cJSON_AddNumberToObject(root, "timestamp", entry->registry_entry.value->last_event);

        snprintf(buffer, OS_MAXSTR, "%s\\%s", entry->registry_entry.key->path, entry->registry_entry.value->name);

        configuration = fim_registry_configuration(buffer, entry->registry_entry.key->arch);

        cJSON_AddStringToObject(root, "path", entry->registry_entry.key->path);
        cJSON_AddStringToObject(root, "arch", entry->registry_entry.key->arch == ARCH_64BIT ? "[x64]" : "[x32]");
        cJSON_AddStringToObject(root, "value_name", entry->registry_entry.value->name);

        attributes = fim_registry_value_attributes_json(entry->registry_entry.value, configuration);
    }
#endif

    cJSON_AddItemToObject(root, "attributes", attributes);

    return root;
}

void fim_sync_checksum(fim_type type, pthread_mutex_t *mutex) {
    char *start = NULL;
    char *top = NULL;
    const char *component = type == FIM_TYPE_FILE ? FIM_COMPONENT_FILE : FIM_COMPONENT_REGISTRY;
    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    w_mutex_lock(mutex);

    if (fim_db_get_first_path(syscheck.database, type, &start) != FIMDB_OK) {
        merror(FIM_DB_ERROR_GET_ROW_PATH, "FIRST", type == FIM_TYPE_FILE ? "FILE" : "REGISTRY");
        w_mutex_unlock(mutex);
        goto end;
    }

    if (fim_db_get_last_path(syscheck.database, type, &top) != FIMDB_OK) {
        merror(FIM_DB_ERROR_GET_ROW_PATH, "LAST", type == FIM_TYPE_FILE ? "FILE" : "REGISTRY");
        w_mutex_unlock(mutex);
        goto end;
    }

    if (fim_db_get_data_checksum(syscheck.database, type, (void*) ctx) != FIMDB_OK) {
        merror(FIM_DB_ERROR_CALC_CHECKSUM);
        w_mutex_unlock(mutex);
        goto end;
    }

    w_mutex_unlock(mutex);

    fim_sync_cur_id = time(NULL);

    if (start && top) {
        unsigned char digest[EVP_MAX_MD_SIZE] = {0};
        unsigned int digest_size;
        os_sha1 hexdigest  = {0};

        EVP_DigestFinal_ex(ctx, digest, &digest_size);
        OS_SHA1_Hexdigest(digest, hexdigest);

        char * plain = dbsync_check_msg(component, INTEGRITY_CHECK_GLOBAL, fim_sync_cur_id, start, top, NULL, hexdigest);
        fim_send_sync_msg(component, plain);

        os_free(plain);

    } else { // If database is empty
        char * plain = dbsync_check_msg(component, INTEGRITY_CLEAR, fim_sync_cur_id, NULL, NULL, NULL, NULL);
        fim_send_sync_msg(component, plain);
        os_free(plain);
    }

end:
    os_free(start);
    os_free(top);
    EVP_MD_CTX_destroy(ctx);
}

void fim_sync_checksum_split(const char * start, const char * top, long id) {
    fim_entry *entry = NULL;
    cJSON *file_data = NULL;
    fim_type type;
    int range_size;
    const char *component;
    char *str_pathlh = NULL;
    char *str_pathuh = NULL;
    EVP_MD_CTX *ctx_left;
    EVP_MD_CTX *ctx_right;
    int result;

    if (strncmp(start, "[x32]", 5) == 0) {
        type = FIM_TYPE_REGISTRY;
        component = FIM_COMPONENT_REGISTRY;
    } else if (strncmp(start, "[x64]", 5) == 0) {
        type = FIM_TYPE_REGISTRY;
        component = FIM_COMPONENT_REGISTRY;
    } else {
        type = FIM_TYPE_FILE;
        component = FIM_COMPONENT_FILE;
    }

    w_mutex_lock(&syscheck.fim_entry_mutex);
    if (fim_db_get_count_range(syscheck.database, type, start, top, &range_size) != FIMDB_OK) {
        merror(FIM_DB_ERROR_COUNT_RANGE, start, top);
        range_size = 0;
    }
    w_mutex_unlock(&syscheck.fim_entry_mutex)

    switch (range_size) {
    case 0:
        return;

    case 1:
        w_mutex_lock(&syscheck.fim_entry_mutex);
        entry = fim_db_get_entry_from_sync_msg(syscheck.database, type, start);
        w_mutex_unlock(&syscheck.fim_entry_mutex);

        if (entry == NULL) {
            merror(FIM_DB_ERROR_GET_PATH, start);
            return;
        }

        file_data = fim_entry_json(start, entry);
        char * plain = dbsync_state_msg(component, file_data);
        fim_send_sync_msg(component, plain);
        os_free(plain);
        free_entry(entry);
        return;

    default:
        ctx_left = EVP_MD_CTX_create();
        ctx_right = EVP_MD_CTX_create();

        EVP_DigestInit(ctx_left, EVP_sha1());
        EVP_DigestInit(ctx_right, EVP_sha1());

        w_mutex_lock(&syscheck.fim_entry_mutex);
        result = fim_db_get_checksum_range(syscheck.database, type, start, top, range_size, ctx_left, ctx_right,
                                            &str_pathlh, &str_pathuh);
        w_mutex_unlock(&syscheck.fim_entry_mutex)

        if (result == FIMDB_OK) {
            unsigned char digest[EVP_MAX_MD_SIZE] = {0};
            unsigned int digest_size = 0;
            os_sha1 hexdigest;
            char *plain;

            // Send message with checksum of first half
            EVP_DigestFinal_ex(ctx_left, digest, &digest_size);
            OS_SHA1_Hexdigest(digest, hexdigest);
            plain = dbsync_check_msg(component, INTEGRITY_CHECK_LEFT, id, start, str_pathlh, str_pathuh, hexdigest);
            fim_send_sync_msg(component, plain);
            os_free(plain);

            // Send message with checksum of second half
            EVP_DigestFinal_ex(ctx_right, digest, &digest_size);
            OS_SHA1_Hexdigest(digest, hexdigest);
            plain = dbsync_check_msg(component, INTEGRITY_CHECK_RIGHT, id, str_pathuh, top, "", hexdigest);
            fim_send_sync_msg(component, plain);
            os_free(plain);
        }

        os_free(str_pathlh);
        os_free(str_pathuh);

        EVP_MD_CTX_destroy(ctx_left);
        EVP_MD_CTX_destroy(ctx_right);
        return;
    }
}

void fim_sync_send_list(const char *start, const char *top) {
    fim_tmp_file *file = NULL;
    int it;
    char *line;
    fim_type type;
    const char *component;

    if (strncmp(start, "[x32]", 5) == 0) {
        type = FIM_TYPE_REGISTRY;
        component = FIM_COMPONENT_REGISTRY;
    } else if (strncmp(start, "[x64]", 5) == 0) {
        type = FIM_TYPE_REGISTRY;
        component = FIM_COMPONENT_REGISTRY;
    } else {
        type = FIM_TYPE_FILE;
        component = FIM_COMPONENT_FILE;
    }

    w_mutex_lock(&syscheck.fim_entry_mutex);
    if (fim_db_get_path_range(syscheck.database, type, start, top, &file, syscheck.database_store) != FIMDB_OK) {
        merror(FIM_DB_ERROR_SYNC_DB);
        if (file != NULL) {
            fim_db_clean_file(&file, syscheck.database_store);
        }
        w_mutex_unlock(&syscheck.fim_entry_mutex);
        return;
    }
    w_mutex_unlock(&syscheck.fim_entry_mutex);

    if (file == NULL) {
        return;
    }

    if (file->elements == 0) {
        fim_db_clean_file(&file, syscheck.database_store);
        return;
    }

    for (it = 0; (fim_db_read_line_from_file(file, syscheck.database_store, it, &line) == 0) ; it++) {
        fim_entry *entry;
        cJSON *file_data;
        char *plain;

        w_mutex_lock(&syscheck.fim_entry_mutex);
        entry = fim_db_get_entry_from_sync_msg(syscheck.database, type, line);
        w_mutex_unlock(&syscheck.fim_entry_mutex);

        if (entry == NULL) {
            merror(FIM_DB_ERROR_GET_PATH, line);
            os_free(line);
            continue;
        }

        file_data = fim_entry_json(line, entry);
        plain = dbsync_state_msg(component, file_data);
        fim_send_sync_msg(component, plain);
        os_free(plain);
        os_free(line);
        free_entry(entry);
    }

    fim_db_clean_file(&file, syscheck.database_store);
}

void fim_sync_dispatch(char * payload) {
    assert(payload != NULL);

    char * command = payload;
    char * json_arg = strchr(payload, ' ');

    if (json_arg == NULL) {
        mdebug1(FIM_DBSYNC_NO_ARGUMENT, payload);
        return;
    }

    *json_arg++ = '\0';
    cJSON * root = cJSON_Parse(json_arg);

    if (root == NULL) {
        mdebug1(FIM_DBSYNC_INVALID_ARGUMENT, json_arg);
        return;
    }

    cJSON * id = cJSON_GetObjectItem(root, "id");

    if (!cJSON_IsNumber(id)) {
        mdebug1(FIM_DBSYNC_INVALID_ARGUMENT, json_arg);
        goto end;
    }

    // Discard command if (data.id > global_id)
    // Decrease global ID if (data.id < global_id)

    if (id->valuedouble < fim_sync_cur_id) {
        fim_sync_cur_id = id->valuedouble;
        mdebug1(FIM_DBSYNC_DEC_ID, fim_sync_cur_id);
    } else if (id->valuedouble > fim_sync_cur_id) {
        mdebug1(FIM_DBSYNC_DROP_MESSAGE, (long)id->valuedouble, fim_sync_cur_id);
        goto end;
    }

    char * begin = cJSON_GetStringValue(cJSON_GetObjectItem(root, "begin"));
    char * end = cJSON_GetStringValue(cJSON_GetObjectItem(root, "end"));

    if (begin == NULL || end == NULL) {
        mdebug1(FIM_DBSYNC_INVALID_ARGUMENT, json_arg);
        goto end;
    }

    if (strcmp(command, "checksum_fail") == 0) {
        fim_sync_checksum_split(begin, end, id->valuedouble);
    } else if (strcmp(command, "no_data") == 0) {
        fim_sync_send_list(begin, end);
    } else {
        mdebug1(FIM_DBSYNC_UNKNOWN_CMD, command);
    }

end:
    cJSON_Delete(root);
}

void fim_sync_push_msg(const char * msg) {

    if (fim_sync_queue == NULL) {
        mwarn("A data synchronization response was received before sending the first message.");
        return;
    }

    char * copy;
    os_strdup(msg, copy);

    if (queue_push_ex(fim_sync_queue, copy) == -1) {
        mdebug2("Cannot push a data synchronization message: queue is full.");
        free(copy);
    }
}
