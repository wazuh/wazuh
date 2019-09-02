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

#define critical_section(m, b) w_mutex_lock(&m); b w_mutex_unlock(&m);

cJSON * integrity_json(const char * start, const char * top, const char * tail, const char * checksum) {
    cJSON * root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "component", "fim");

    if (checksum == NULL) {
        cJSON_AddStringToObject(root, "type", "clear");
    } else {
        cJSON_AddStringToObject(root, "type", "check");
        cJSON_AddStringToObject(root, "begin", start);
        cJSON_AddStringToObject(root, "end", top);

        if (tail != NULL) {
            cJSON_AddStringToObject(root, "tail", tail);
        }

        cJSON_AddStringToObject(root, "checksum", checksum);
    }

    return root;
}

void fim_sync_checksum() {
    char ** keys;
    int i = 0;
    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    w_mutex_lock(&syscheck.fim_entry_mutex);

    {
        keys = rbtree_keys(syscheck.fim_entry);

        for (; keys[i]; i++) {
            fim_entry_data * data = rbtree_get(syscheck.fim_entry, keys[i]);
            assert(data);
            EVP_DigestUpdate(ctx, data->checksum, strlen(data->checksum));
        }
    }

    w_mutex_unlock(&syscheck.fim_entry_mutex);

    if (i > 0) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_size;
        os_sha1 hexdigest;

        EVP_DigestFinal_ex(ctx, digest, &digest_size);
        OS_SHA1_Hexdigest(digest, hexdigest);

        cJSON * json = integrity_json(keys[0], keys[i - 1], NULL, hexdigest);
        char * plain = cJSON_PrintUnformatted(json);
        minfo(" -- send(%s)", plain);
        cJSON_Delete(json);
        free(plain);
    } else {
        cJSON * json = integrity_json(NULL, NULL, NULL, NULL);
        char * plain = cJSON_PrintUnformatted(json);
        minfo(" -- send(%s)", plain);
        cJSON_Delete(json);
        free(plain);
    }

    EVP_MD_CTX_destroy(ctx);
    free_strarray(keys);
}

void fim_sync_checksum_split(const char * start, const char * top) {
    char * entry = NULL;
    char ** keys;
    int n;
    int m;
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
            entry = strdup(keys[0]);
            break;

        default:
            // Other case: split the list
            m = n / 2;

            for (int i = 0; i < m; i++) {
                fim_entry_data * data = rbtree_get(syscheck.fim_entry, keys[i]);
                assert(data);
                EVP_DigestUpdate(ctx_left, data->checksum, strlen(data->checksum));
            }

            for (int i = m; i < n; i++) {
                fim_entry_data * data = rbtree_get(syscheck.fim_entry, keys[i]);
                assert(data);
                EVP_DigestUpdate(ctx_right, data->checksum, strlen(data->checksum));
            }
        }
    }

    if (n > 0) {
        if (entry == NULL) {
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int digest_size;
            os_sha1 hexdigest;

            EVP_DigestFinal_ex(ctx_left, digest, &digest_size);
            OS_SHA1_Hexdigest(digest, hexdigest);
            cJSON * json = integrity_json(keys[0], keys[m - 1], keys[m], hexdigest);
            char * plain = cJSON_PrintUnformatted(json);
            minfo(" -- send(%s)", plain);
            cJSON_Delete(json);
            free(plain);

            EVP_DigestFinal_ex(ctx_right, digest, &digest_size);
            OS_SHA1_Hexdigest(digest, hexdigest);
            json = integrity_json(keys[m], keys[n - 1], "", hexdigest);
            plain = cJSON_PrintUnformatted(json);
            minfo(" -- send(%s)", plain);
            cJSON_Delete(json);
            free(plain);
        } else {
            minfo(" -- send(%s)", entry);
            free(entry);
        }
    }

    free_strarray(keys);
    EVP_MD_CTX_destroy(ctx_left);
    EVP_MD_CTX_destroy(ctx_right);
}
