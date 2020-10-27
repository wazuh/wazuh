/**
 * @file wdb_integrity.c
 * @brief DB integrity synchronization library definition.
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
int wdbi_checksum_range(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, os_sha1 hexdigest) {

    assert(wdb != NULL);
    assert(hexdigest != NULL);

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
            mdebug1("DB(%s) has a NULL %s checksum.", wdb->id, COMPONENT_NAMES[component]);
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
 * Should tail be NULL, this function will delete every item from the first
 * element to 'begin' and from 'end' to the last element.
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @param begin First valid element in the list.
 * @param end Last valid element. This is the previous element to the first item to delete.
 * @param tail Subsequent element to the last item to delete.
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdbi_delete(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, const char * tail) {

    assert(wdb != NULL);

    const int INDEXES_AROUND[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_AROUND };
    const int INDEXES_RANGE[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_RANGE };
    assert(component < sizeof(INDEXES_AROUND) / sizeof(int));
    assert(component < sizeof(INDEXES_RANGE) / sizeof(int));

    int index = tail ? INDEXES_RANGE[component] : INDEXES_AROUND[component];

    if (wdb_stmt_cache(wdb, index) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[index];

    if (tail) {
        sqlite3_bind_text(stmt, 1, end, -1, NULL);
        sqlite3_bind_text(stmt, 2, tail, -1, NULL);
    } else {
        sqlite3_bind_text(stmt, 1, begin, -1, NULL);
        sqlite3_bind_text(stmt, 2, end, -1, NULL);
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

/**
 * @brief Update sync attempt timestamp
 *
 * Set the column "last_attempt" with the timestamp argument,
 * and increase "n_attempts" one unit.
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @param timestamp Synchronization event timestamp (field "id");
 */

void wdbi_update_attempt(wdb_t * wdb, wdb_component_t component, long timestamp) {

    assert(wdb != NULL);

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_UPDATE_ATTEMPT) == -1) {
        return;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_UPDATE_ATTEMPT];

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_text(stmt, 2, COMPONENT_NAMES[component], -1, NULL);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
}

/**
 * @brief Update sync completion timestamp
 *
 * Set the columns "last_attempt" and "last_completion" with the timestamp argument.
 * Increase "n_attempts" and "n_completions" one unit.
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @param timestamp Synchronization event timestamp (field "id");
 */

static void wdbi_update_completion(wdb_t * wdb, wdb_component_t component, long timestamp) {

    assert(wdb != NULL);

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_UPDATE_COMPLETION) == -1) {
        return;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_UPDATE_COMPLETION];

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_int64(stmt, 2, timestamp);
    sqlite3_bind_text(stmt, 3, COMPONENT_NAMES[component], -1, NULL);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
}

// Query the checksum of a data range
int wdbi_query_checksum(wdb_t * wdb, wdb_component_t component, const char * command, const char * payload) {
    int retval = -1;
    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse checksum range payload: '%s'", wdb->id, payload);
        return -1;
    }

    cJSON * item = cJSON_GetObjectItem(data, "begin");
    char * begin = cJSON_GetStringValue(item);

    if (begin == NULL) {
        mdebug1("No such string 'begin' in JSON payload.");
        goto end;
    }

    item = cJSON_GetObjectItem(data, "end");
    char * end = cJSON_GetStringValue(item);

    if (end == NULL) {
        mdebug1("No such string 'end' in JSON payload.");
        goto end;
    }

    item = cJSON_GetObjectItem(data, "checksum");
    char * checksum = cJSON_GetStringValue(item);

    if (checksum == NULL) {
        mdebug1("No such string 'checksum' in JSON payload.");
        goto end;
    }

    item = cJSON_GetObjectItem(data, "id");

    if (!cJSON_IsNumber(item)) {
        mdebug1("No such string 'id' in JSON payload.");
        goto end;
    }

    long timestamp = item->valuedouble;
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
        mdebug2("Agent '%s' %s range checksum: Time: %.3f ms.", wdb->id, COMPONENT_NAMES[component], time_diff(&ts_start, &ts_end) * 1e3);
        retval = strcmp(hexdigest, checksum) ? 1 : 2;
    }

    // Remove old elements

    if (strcmp(command, "integrity_check_global") == 0) {
        wdbi_delete(wdb, component, begin, end, NULL);

        // Update synchronization timestamp

        switch (retval) {
        case 0: // No data
        case 1: // Checksum failure
            wdbi_update_attempt(wdb, component, timestamp);
            break;

        case 2: // Data is synchronized
            wdbi_update_completion(wdb, component, timestamp);
        }

    } else if (strcmp(command, "integrity_check_left") == 0) {
        item = cJSON_GetObjectItem(data, "tail");
        wdbi_delete(wdb, component, begin, end, cJSON_GetStringValue(item));
    }

end:
    cJSON_Delete(data);
    return retval;
}

// Query a complete table clear
int wdbi_query_clear(wdb_t * wdb, wdb_component_t component, const char * payload) {
    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_CLEAR };
    assert(component < sizeof(INDEXES) / sizeof(int));

    int retval = -1;
    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse checksum range payload: '%s'", wdb->id, payload);
        goto end;
    }

    cJSON * item = cJSON_GetObjectItem(data, "id");

    if (!cJSON_IsNumber(item)) {
        mdebug1("No such string 'id' in JSON payload.");
        goto end;
    }

    long timestamp = item->valuedouble;

    if (wdb_stmt_cache(wdb, INDEXES[component]) == -1) {
        goto end;
    }

    sqlite3_stmt * stmt = wdb->stmt[INDEXES[component]];

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        goto end;
    }

    wdbi_update_completion(wdb, component, timestamp);
    retval = 0;

end:
    cJSON_Delete(data);
    return retval;
}
