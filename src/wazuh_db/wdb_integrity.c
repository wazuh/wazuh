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

/**
 * @brief Delete old elements in a table
 *
 * This function shall delete every item in the corresponding table,
 * between end and tail (none of them included).
 *
 * Should tail be NULL, this function will delete every item
 * from end.
 *
 * @param component Name of the component.
 * @param end Previous element to the first item to delete.
 * @param tail Subsequent element to the first item to delete.
 * @retval 0 On success.
 * @retval -1 On error.
 */
static int wdbi_delete_tail(wdb_t * wdb, wdb_component_t component, const char * end, const char * tail) {
    const int INDEXES_UNARY[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_TAIL_UNARY };
    const int INDEXES_BINARY[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_TAIL_BINARY };
    assert(component < sizeof(INDEXES_UNARY) / sizeof(int));
    assert(component < sizeof(INDEXES_BINARY) / sizeof(int));

    int index = tail ? INDEXES_BINARY[component] : INDEXES_UNARY[component];

    if (wdb_stmt_cache(wdb, index) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[index];
    sqlite3_bind_text(stmt, 1, end, -1, NULL);

    if (tail) {
        sqlite3_bind_text(stmt, 2, tail, -1, NULL);
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Query the checksum of a data range
int wdbi_query_checksum_range(wdb_t * wdb, wdb_component_t component, const char * payload) {
    int retval = -1;
    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse checksum range payload: '%s'", wdb->agent_id, payload);
        return -1;
    }

    cJSON * item = cJSON_GetObjectItem(data, "begin");

    if (!(item && cJSON_IsString(item))) {
        mdebug1("No such string 'begin' in JSON payload.");
        goto end;
    }

    char * begin = item->valuestring;
    item = cJSON_GetObjectItem(data, "end");

    if (!(item && cJSON_IsString(item))) {
        mdebug1("No such string 'end' in JSON payload.");
        goto end;
    }

    char * end = item->valuestring;
    item = cJSON_GetObjectItem(data, "checksum");

    if (!(item && cJSON_IsString(item))) {
        mdebug1("No such string 'checksum' in JSON payload.");
        goto end;
    }

    char * checksum = item->valuestring;
    os_sha1 hexdigest;
    struct timespec ts_start, ts_end;
    gettime(&ts_start);

    switch (wdbi_checksum_range(wdb, component, begin, end, hexdigest)) {
    case -1:
        goto end;

    case 0:
        retval = 0;
        break;

    case 1:
        gettime(&ts_end);
        mdebug2("Agent '%s' %s range checksum: Time: %.3f ms.", wdb->agent_id, COMPONENT_NAMES[component], time_diff(&ts_start, &ts_end) * 1e3);
        retval = strcmp(hexdigest, checksum) ? 1 : 2;
    }

    item = cJSON_GetObjectItem(data, "tail");
    wdbi_delete_tail(wdb, component, end, item && cJSON_IsString(item) ? item->valuestring : NULL);

end:
    cJSON_Delete(data);
    return retval;
}
