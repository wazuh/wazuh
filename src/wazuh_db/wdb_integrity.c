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
 * @brief Get the number of blocks per level
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @param level Level number.
 * @return Number of blocks.
 * @retval -1 Any error occurs.
 */
static int wdbi_max_block(wdb_t * wdb, wdb_component_t component, int level) {
    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_MAX_BLOCK };
    assert(component < sizeof(INDEXES) / sizeof(int));
    assert(level >= 0 && level <= 2);

    int stmt_index = (level == 0) ? INDEXES[component] : WDB_STMT_MAX_HASH_BLOCK;

    if (wdb_stmt_cache(wdb, stmt_index) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[stmt_index];

    if (level > 0) {
        sqlite3_bind_int(stmt, 1, level);
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        return sqlite3_column_int(stmt, 0);
    } else {
        return -1;
    }
}

/**
 * @brief Clear the integrity table for a component
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @retval 0 On success.
 * @retval -1 Any error occurs.
 */
static int wdbi_clear(wdb_t * wdb, wdb_component_t component) {
    // Clear integrity blocks

    if (wdb_stmt_cache(wdb, WDB_STMT_CLEAR_INTEGRITY_BLOCKS) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_CLEAR_INTEGRITY_BLOCKS];
    sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        return -1;
    }

    // Clear integrity levels relationship

    if (wdb_stmt_cache(wdb, WDB_STMT_CLEAR_INTEGRITY_LEVELS) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        return -1;
    }

    return 0;
}

/**
 * @brief Fill an integrity block set
 *
 * @param wdb
 * @param component Name of the component.
 * @param level Block set level.
 * @retval 0 On success.
 * @retval -1 Any error occurs.
 */
static int wdbi_fill_level(wdb_t * wdb, wdb_component_t component, int level) {
    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_SELECT_L0_SUM };
    assert(component < sizeof(INDEXES) / sizeof(int));
    assert(level >= 0 && level <= 2);

    int result = -1;
    int max_block = wdbi_max_block(wdb, component, level);

    if (max_block == -1) {
        return -1;
    }

    EVP_MD_CTX * ctx = EVP_MD_CTX_create();

    for (int i = 0; i < max_block; i++) {
        sqlite3_stmt * stmt;
        EVP_DigestInit(ctx, EVP_sha1());

        if (level == 0) {
            // Select all files of level-0 block 'i'

            if (wdb_stmt_cache(wdb, INDEXES[component]) == -1) {
                goto end;
            }

            stmt = wdb->stmt[INDEXES[component]];
        } else {
            // Select all blocks of the previous level

            if (wdb_stmt_cache(wdb, WDB_STMT_SELECT_BLOCK_SUMS) == -1) {
                goto end;
            }

            stmt = wdb->stmt[WDB_STMT_SELECT_BLOCK_SUMS];
            sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);
            sqlite3_bind_int(stmt, 2, level - 1);
        }

        // Iterate down the hashes and accumulate

        while (sqlite3_step(stmt) == SQLITE_DONE) {
            const unsigned char * checksum = sqlite3_column_text(stmt, 0);
            EVP_DigestUpdate(ctx, checksum, strlen((const char *)checksum));
        }

        // Get the hex SHA-1 digest

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_size;
        EVP_DigestFinal_ex(ctx, digest, &digest_size);
        EVP_MD_CTX_reset(ctx);

        os_sha1 hexdigest;
        OS_SHA1_Hexdigest(digest, hexdigest);

        // Insert digest into table block_hash

        if (wdb_stmt_cache(wdb, WDB_STMT_INSERT_BLOCK_SUM) == -1) {
            goto end;
        }

        stmt = wdb->stmt[WDB_STMT_INSERT_BLOCK_SUM];
        sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);
        sqlite3_bind_int(stmt, 2, level);
        sqlite3_bind_int(stmt, 3, i);
        sqlite3_bind_text(stmt, 4, hexdigest, sizeof(hexdigest) - 1, NULL);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            merror("DB(%s) Cannot insert L%d-block checksum: %s", wdb->agent_id, level, sqlite3_errmsg(wdb->db));
        }

        // Insert integrity level relationship

        if (wdb_stmt_cache(wdb, WDB_STMT_INSERT_INTEGRITY_LEVEL) == -1) {
            goto end;
        }

        stmt = wdb->stmt[WDB_STMT_INSERT_BLOCK_SUM];
        sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);
        sqlite3_bind_int(stmt, 2, level);
        sqlite3_bind_int(stmt, 3, i);
        sqlite3_bind_int(stmt, 4, level - 1);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            merror("DB(%s) Cannot insert L%d-block relationship: %s", wdb->agent_id, level, sqlite3_errmsg(wdb->db));
        }
    }

    result = 0;

end:
    EVP_MD_CTX_destroy(ctx);
    return result;
}

/**
 * @brief Renew the block hash version ID
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @return Version ID of the new block hash.
 * @retval -1 Any error occurs.
 */
static long wdbi_renew_id(wdb_t * wdb, wdb_component_t component) {
    time_t now = time(NULL);

    if (wdb_stmt_cache(wdb, WDB_STMT_REPLACE_INTEGRITY_VERSION) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_REPLACE_INTEGRITY_VERSION];
    sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);
    sqlite3_bind_int64(stmt, 2, now);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        merror("DB(%s) Cannot insert integrity ID: %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    return now;
}

/**
 * @brief Create or update an integrity checksum tree
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @return Version ID of the new block hash.
 * @retval -1 Any error occurs.
 */
long wdbi_make(wdb_t * wdb, wdb_component_t component) {
    if (wdbi_clear(wdb, component) == -1) {
        return -1;
    }

    struct timespec ts_start, ts_end;
    gettime(&ts_start);

    for (int level = 0; level <= 2; level++) {
        if (wdbi_fill_level(wdb, component, level) == -1) {
            return -1;
        }
    }

    gettime(&ts_end);
    mdebug2("Agent '%s' %s integrity made. Time: %.3f ms.", wdb->agent_id, COMPONENT_NAMES[component], time_diff(&ts_start, &ts_end) * 1e3);
    return wdbi_renew_id(wdb, component);
}
