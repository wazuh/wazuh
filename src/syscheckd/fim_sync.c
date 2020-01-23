/**
 * @file fim_sync.c
 * @author Vikman Fernandez-Castro (victor@wazuh.com)
 * @brief Definition of FIM data synchronization library
 * @version 0.1
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include <openssl/evp.h>
#include "syscheck.h"
#include "integrity_op.h"
#include "fim_db.h"

static long fim_sync_cur_id;
static w_queue_t * fim_sync_queue;

// LCOV_EXCL_START
// Starting data synchronization thread
void * fim_run_integrity(void * args) {
    // Keep track of synchronization failures
    long sync_interval = syscheck.sync_interval;

    fim_sync_queue = queue_init(syscheck.sync_queue_size);

    while (1) {
        bool sync_successful = true;

        mdebug1("Initializing FIM Integrity Synchronization check. Sync interval is %li seconds.", sync_interval);
        fim_sync_checksum();

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

    return args;
}
// LCOV_EXCL_STOP

void fim_sync_checksum() {
    char *start, *top;
    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    w_mutex_lock(&syscheck.fim_entry_mutex);

    if (fim_db_get_row_path(syscheck.database, FIM_FIRST_ROW,
        &start) != FIMDB_OK) {
        merror("fim_sync_checksum(): Couldn't get first row's path");
        goto end;
    }

    if (fim_db_get_row_path(syscheck.database, FIM_LAST_ROW,
        &top) != FIMDB_OK) {
        merror("fim_sync_checksum(): Couldn't get last row's path");
        goto end;
    }

    fim_db_get_data_checksum(syscheck.database, (void*) ctx);

    w_mutex_unlock(&syscheck.fim_entry_mutex);
    fim_sync_cur_id = time(NULL);

    if (start && top) {
        unsigned char digest[EVP_MAX_MD_SIZE] = {0};
        unsigned int digest_size;
        os_sha1 hexdigest  = {0};

        EVP_DigestFinal_ex(ctx, digest, &digest_size);
        OS_SHA1_Hexdigest(digest, hexdigest);

        char * plain = dbsync_check_msg("syscheck", INTEGRITY_CHECK_GLOBAL, fim_sync_cur_id, start, top, NULL, hexdigest);
        fim_send_sync_msg(plain);

        free(start);
        free(top);
        free(plain);

    } else { // If database is empty
        char * plain = dbsync_check_msg("syscheck", INTEGRITY_CLEAR, fim_sync_cur_id, NULL, NULL, NULL, NULL);
        fim_send_sync_msg(plain);
        free(plain);
    }

    end:
        EVP_MD_CTX_destroy(ctx);
}

void fim_sync_checksum_split(const char * start, const char * top, long id) {
    fim_entry *entry    = NULL;
    cJSON *entry_data   = NULL;
    int range_size      = 0;

    if (fim_db_get_count_range(syscheck.database, start, top,
        &range_size) != FIMDB_OK) {
        merror("fim_db_get_count_range(): Couldn't get range size between %s and %s",
                start, top);
        return;
    }

    w_mutex_lock(&syscheck.fim_entry_mutex);

    switch (range_size) {
    case 0:
        break;

    case 1:
        entry = fim_db_get_path(syscheck.database, start);
        entry_data = fim_entry_json(start, entry->data);
        char * plain = dbsync_state_msg("syscheck", entry_data);
        fim_send_sync_msg(plain);
        free(plain);
        free_entry(entry);
        cJSON_Delete(entry_data);
        break;

    default:
        fim_db_data_checksum_range(syscheck.database, start, top, id, range_size);
        break;
    }

    w_mutex_unlock(&syscheck.fim_entry_mutex);
}

void fim_sync_send_list(const char * start, const char * top) {
    w_mutex_lock(&syscheck.fim_entry_mutex);
    // SQLite Development
    //char ** keys = rbtree_range(syscheck.fim_entry, start, top);
    w_mutex_unlock(&syscheck.fim_entry_mutex);

/* SQLite Development
    for (int i = 0; keys[i]; i++) {
        w_mutex_lock(&syscheck.fim_entry_mutex);
        fim_entry_data * data = rbtree_get(syscheck.fim_entry, keys[i]);

        if (data == NULL) {
            w_mutex_unlock(&syscheck.fim_entry_mutex);
            continue;
        }

        cJSON * entry_data = fim_entry_json(keys[i], data);
        w_mutex_unlock(&syscheck.fim_entry_mutex);

        char * plain = dbsync_state_msg("syscheck", entry_data);
        fim_send_sync_msg(plain);
        free(plain);
    }
    free_strarray(keys);
    */
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
        return;
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
