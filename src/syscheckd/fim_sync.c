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

#ifdef UNIT_TESTING
/* Remove static qualifier when unit testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

static long fim_sync_cur_id;
static w_queue_t * fim_sync_queue;

// LCOV_EXCL_START
// Starting data synchronization thread
void * fim_run_integrity(void * args) {
    // Keep track of synchronization failures
    long sync_interval = syscheck.sync_interval;
    struct timespec start;
    struct timespec end;

    fim_sync_queue = queue_init(syscheck.sync_queue_size);

    while (1) {
        bool sync_successful = true;

        mdebug1("Initializing FIM Integrity Synchronization check. Sync interval is %li seconds.", sync_interval);

        gettime(&start);
        fim_sync_checksum();
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

    return args;
}
// LCOV_EXCL_STOP

void fim_sync_checksum() {
    char ** keys;
    int i;
    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    w_mutex_lock(&syscheck.fim_entry_mutex);

    {
        keys = rbtree_keys(syscheck.fim_entry);

        for (i = 0; keys[i]; i++) {
            fim_entry_data * data = rbtree_get(syscheck.fim_entry, keys[i]);
            assert(data != NULL);
            EVP_DigestUpdate(ctx, data->checksum, strlen(data->checksum));
        }
    }

    w_mutex_unlock(&syscheck.fim_entry_mutex);
    fim_sync_cur_id = time(NULL);

    if (i > 0) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_size;
        os_sha1 hexdigest;

        EVP_DigestFinal_ex(ctx, digest, &digest_size);
        OS_SHA1_Hexdigest(digest, hexdigest);

        char * plain = dbsync_check_msg("syscheck", INTEGRITY_CHECK_GLOBAL, fim_sync_cur_id, keys[0], keys[i - 1], NULL, hexdigest);
        fim_send_sync_msg(plain);
        free(plain);
    } else {
        char * plain = dbsync_check_msg("syscheck", INTEGRITY_CLEAR, fim_sync_cur_id, NULL, NULL, NULL, NULL);
        fim_send_sync_msg(plain);
        free(plain);
    }

    EVP_MD_CTX_destroy(ctx);
    free_strarray(keys);
}

void fim_sync_checksum_split(const char * start, const char * top, long id) {
    cJSON * entry_data = NULL;
    char ** keys;
    int n;
    int m = 0;
    EVP_MD_CTX * ctx_left = EVP_MD_CTX_create();
    EVP_MD_CTX * ctx_right = EVP_MD_CTX_create();

    EVP_DigestInit(ctx_left, EVP_sha1());
    EVP_DigestInit(ctx_right, EVP_sha1());

    w_mutex_lock(&syscheck.fim_entry_mutex);

    {
        keys = rbtree_range(syscheck.fim_entry, start, top);
        for (n = 0; keys[n]; n++);

        switch (n) {
        case 0:
            break;

        case 1:
            // Unary list: send the file state
            entry_data = fim_entry_json(keys[0], (fim_entry_data *) rbtree_get(syscheck.fim_entry, keys[0]));
            break;

        default:
            // Other case: split the list
            m = n / 2;

            for (int i = 0; i < m; i++) {
                fim_entry_data * data = rbtree_get(syscheck.fim_entry, keys[i]);
                assert(data != NULL);
                EVP_DigestUpdate(ctx_left, data->checksum, strlen(data->checksum));
            }

            for (int i = m; i < n; i++) {
                fim_entry_data * data = rbtree_get(syscheck.fim_entry, keys[i]);
                assert(data != NULL);
                EVP_DigestUpdate(ctx_right, data->checksum, strlen(data->checksum));
            }
        }
    }

    w_mutex_unlock(&syscheck.fim_entry_mutex);

    if (n > 0) {
        if (entry_data == NULL) {
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int digest_size;
            os_sha1 hexdigest;

            EVP_DigestFinal_ex(ctx_left, digest, &digest_size);
            OS_SHA1_Hexdigest(digest, hexdigest);
            char * plain = dbsync_check_msg("syscheck", INTEGRITY_CHECK_LEFT, id, keys[0], keys[m - 1], keys[m], hexdigest);
            fim_send_sync_msg(plain);
            free(plain);

            EVP_DigestFinal_ex(ctx_right, digest, &digest_size);
            OS_SHA1_Hexdigest(digest, hexdigest);
            plain = dbsync_check_msg("syscheck", INTEGRITY_CHECK_RIGHT, id, keys[m], keys[n - 1], "", hexdigest);
            fim_send_sync_msg(plain);
            free(plain);
        } else {
            char * plain = dbsync_state_msg("syscheck", entry_data);
            fim_send_sync_msg(plain);
            free(plain);
        }
    }

    free_strarray(keys);
    EVP_MD_CTX_destroy(ctx_left);
    EVP_MD_CTX_destroy(ctx_right);
}

void fim_sync_send_list(const char * start, const char * top) {
    w_mutex_lock(&syscheck.fim_entry_mutex);
    char ** keys = rbtree_range(syscheck.fim_entry, start, top);
    w_mutex_unlock(&syscheck.fim_entry_mutex);

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
