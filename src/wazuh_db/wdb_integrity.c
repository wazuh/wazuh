/**
 * @file wdb_integrity.c
 * @author Vikman Fernandez-Castro (victor@wazuh.com)
 * @brief DB integrity synchronization library definition.
 * @version 0.1
 * @date 2019-08-14
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "os_crypto/sha1/sha1_op.h"
#include <openssl/evp.h>

static const char * COMPONENT_NAMES[] = {
    [WDB_FIM] = "fim"
};

/**
 * @brief Run checksum of a data range
 *
 * @param[in] wdb Database node.
 * @param component[in] Name of the component.
 * @param begin[in] First element.
 * @param end[in] Last element.
 * @param[out] hexdigest
 * @retval 1 On success.
 * @retval 0 If no files were found in that range.
 * @retval -1 On error.
 */
static int wdbi_checksum_range(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, os_sha1 hexdigest) {
    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_SELECT_CHECKSUM_RANGE };
    assert(component < sizeof(INDEXES) / sizeof(int));

    if (wdb_stmt_cache(wdb, INDEXES[component]) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[INDEXES[component]];
    sqlite3_bind_text(stmt, 1, begin, -1, NULL);
    sqlite3_bind_text(stmt, 2, end, -1, NULL);

    int step = sqlite3_step(stmt);

    if (step != SQLITE_ROW) {
        return 0;
    }

    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    for (; step == SQLITE_ROW; step = sqlite3_step(stmt)) {
        const unsigned char * checksum = sqlite3_column_text(stmt, 0);

        if (checksum == 0) {
            mdebug1("DB(%s) has a NULL %s checksum.", wdb->agent_id, COMPONENT_NAMES[component]);
            continue;
        }

        EVP_DigestUpdate(ctx, checksum, strlen((const char *)checksum));
    }

    // Get the hex SHA-1 digest

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;

    EVP_DigestFinal_ex(ctx, digest, &digest_size);
    EVP_MD_CTX_destroy(ctx);
    OS_SHA1_Hexdigest(digest, hexdigest);

    return 1;
}

// Query the checksum of a data range
int wdbi_query_checksum_range(wdb_t * wdb, wdb_component_t component, const char * payload) {
    int retval = -1;
    char * begin;
    char * end;
    char * checksum;
    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse checksum range payload: '%s'", wdb->agent_id, payload);
        return -1;
    }

    cJSON * item = cJSON_GetObjectItem(data, "begin");

    if (!(item && cJSON_IsString(item))) {
        goto end;
    }

    begin = item->valuestring;
    item = cJSON_GetObjectItem(data, "end");

    if (!(item && cJSON_IsString(item))) {
        goto end;
    }

    end = item->valuestring;
    item = cJSON_GetObjectItem(data, "checksum");

    if (!(item && cJSON_IsString(item))) {
        goto end;
    }

    checksum = item->valuestring;
    os_sha1 hexdigest;

    struct timespec ts_start, ts_end;
    gettime(&ts_start);

    switch (wdbi_checksum_range(wdb, component, begin, end, hexdigest)) {
    case -1:
        break;

    case 0:
        retval = 0;
        break;

    case 1:
        gettime(&ts_end);
        mdebug2("Agent '%s' %s range checksum: Time: %.3f ms.", wdb->agent_id, COMPONENT_NAMES[component], time_diff(&ts_start, &ts_end) * 1e3);

        retval = strcmp(hexdigest, checksum) ? 1 : 2;
    }

end:
    cJSON_Delete(data);
    return retval;
}
