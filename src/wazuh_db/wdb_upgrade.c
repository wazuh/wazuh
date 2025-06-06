/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * December 12, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "wdb.h"

// This function performs those data migrations between
// updates that cannot be resolved with queries
static int wdb_adjust_upgrade(wdb_t *wdb, int upgrade_step);
static int wdb_adjust_global_upgrade(wdb_t *wdb, int upgrade_step);

// Migrate to the fourth version of the database:
// - The attributes field of the fim_entry table is decoded
static int wdb_adjust_v4(wdb_t *wdb);

/* SQL statements used for the global.db upgrade */
typedef enum wdb_stmt_global {
    WDB_STMT_GLOBAL_CHECK_MANAGER_KEEPALIVE,
} wdb_stmt_metadata;

static const char *SQL_GLOBAL_STMT[] = {
    "SELECT COUNT(*) FROM agent WHERE id=0 AND last_keepalive=253402300799;",
};

// Upgrade agent database to last version
wdb_t * wdb_upgrade(wdb_t *wdb) {
    const char * UPDATES[] = {
        schema_upgrade_v1_sql,
        schema_upgrade_v2_sql,
        schema_upgrade_v3_sql,
        schema_upgrade_v4_sql,
        schema_upgrade_v5_sql,
        schema_upgrade_v6_sql,
        schema_upgrade_v7_sql,
        schema_upgrade_v8_sql,
        schema_upgrade_v9_sql,
        schema_upgrade_v10_sql,
        schema_upgrade_v11_sql,
        schema_upgrade_v12_sql,
        schema_upgrade_v13_sql,
        schema_upgrade_v14_sql,
        schema_upgrade_v15_sql
    };

    bool database_updated = false;
    char db_version[OS_SIZE_256];
    int version = 0;

    int ret = wdb_metadata_get_entry(wdb, "db_version", db_version);
    if (ret == OS_SUCCESS || ret == OS_NOTFOUND) {
        version = atoi(db_version);

        if (version < 0) {
            merror("DB(%s): Incorrect database version: %d", wdb->id, version);
            return NULL;
        }

        for (unsigned i = version; i < sizeof(UPDATES) / sizeof(char *); i++) {
            mdebug2("Updating database '%s' to version %d", wdb->id, i + 1);
            database_updated = false;

            if (wdb_sql_exec(wdb, UPDATES[i]) == -1 ||
                wdb_adjust_upgrade(wdb, i)) {
                wdb = wdb_backup(wdb, version);
                break;
            }
            database_updated = true;
        }
    }

    if (router_agent_events_handle && database_updated) {
        cJSON* j_msg_to_send = NULL;
        cJSON* j_agent_info = NULL;
        cJSON* j_data = NULL;
        char* msg_to_send = NULL;

        j_msg_to_send = cJSON_CreateObject();
        j_agent_info = cJSON_CreateObject();
        j_data = cJSON_CreateObject();

        cJSON_AddStringToObject(j_agent_info, "agent_id", wdb->id);
        cJSON_AddItemToObject(j_msg_to_send, "agent_info", j_agent_info);

        cJSON_AddStringToObject(j_msg_to_send, "action", "upgradeAgentDB");

        cJSON_AddNumberToObject(j_data, "db_version", version);
        cJSON_AddNumberToObject(j_data, "new_db_version", sizeof(UPDATES) / sizeof(char *));
        cJSON_AddItemToObject(j_msg_to_send, "data", j_data);

        msg_to_send = cJSON_PrintUnformatted(j_msg_to_send);

        if (msg_to_send) {
            router_provider_send(router_agent_events_handle, msg_to_send, strlen(msg_to_send));
        } else {
            mdebug2("Unable to dump agent db upgrade message to publish. Agent %s", wdb->id);
        }

        cJSON_Delete(j_msg_to_send);
        cJSON_free(msg_to_send);
    }

    return wdb;
}

wdb_t * wdb_upgrade_global(wdb_t *wdb) {
    const char * UPDATES[] = {
        schema_global_upgrade_v1_sql,
        schema_global_upgrade_v2_sql,
        schema_global_upgrade_v3_sql,
        schema_global_upgrade_v4_sql,
        schema_global_upgrade_v5_sql,
        schema_global_upgrade_v6_sql,
        schema_global_upgrade_v7_sql,
    };

    char output[OS_MAXSTR + 1] = { 0 };
    char db_version[OS_SIZE_256 + 2];
    int version = 0;
    int updates_length = (int)(sizeof(UPDATES) / sizeof(char *));

    int count = 0;
    if (wdb_count_tables_with_name(wdb, "metadata", &count) == OS_SUCCESS) {
        if (0 < count) {
            if (wdb_metadata_get_entry(wdb, "db_version", db_version) == OS_SUCCESS) {
                version = atoi(db_version);
            }
            else {
                /**
                 * We can't determine if the database should be upgraded. If we
                 * allow the usage, we could have many errors because of an
                 * operation over an old database version. We should block the
                 * usage until determine whether we should upgrade or not.
                 */
                mwarn("DB(%s): Error trying to get DB version", wdb->id);
                wdb->enabled = false;
            }
        }
        else {
            /*
             * The table does not exist which could mean that we have and old
             * version of the db. If we have an older version than 3.10 we can
             * recreate the global.db database and not lose critical data.
             */
            if (wdb_is_older_than_v310(wdb)) {
                if (OS_SUCCESS != wdb_global_create_backup(wdb, output, "-pre_upgrade")) {
                    merror("Creating pre-upgrade Global DB snapshot failed: %s", output);
                    wdb->enabled = false;
                }
                else {
                    wdb = wdb_recreate_global(wdb);
                }

                return wdb;
            }
        }
    }
    else {
        /*
         * An error occurred trying to get the table count and so we can't
         * determine if the database should be upgraded. If we allow the
         * database usage, we could have many errors because of an operation
         * over an old or corrupted database. If we recreate the database, we
         * have the risk of loosing data of the newer database versions. Instead
         * we block the usage until we can determine whether we should upgrade
         * or not.
         */
        merror("DB(%s) Error trying to find metadata table", wdb->id);
        wdb->enabled = false;
        return wdb;
    }

    if (version < updates_length) {
        if (OS_SUCCESS != wdb_global_create_backup(wdb, output, "-pre_upgrade")) {
            merror("Creating pre-upgrade Global DB snapshot failed: %s", output);
            wdb->enabled = false;
        }
        else {
            for (int i = version; i < updates_length; i++) {
                mdebug2("Updating database '%s' to version %d", wdb->id, i + 1);
                if (wdb_sql_exec(wdb, UPDATES[i]) == OS_INVALID ||
                    wdb_adjust_global_upgrade(wdb, i)) {
                    if (OS_INVALID != wdb_global_restore_backup(&wdb, NULL, false, output)) {
                        merror("Failed to update global.db to version %d. The global.db was "
                               "restored to the original state.",
                               i + 1);
                    }
                    else {
                        merror("Failed to update global.db to version %d.", i + 1);
                        wdb->enabled = false;
                    }
                    break;
                }
            }
        }
    }

    return wdb;
}

// Create backup and generate an empty DB
wdb_t * wdb_backup(wdb_t *wdb, int version) {
    char path[PATH_MAX];
    char * sagent_id;

    os_strdup(wdb->id, sagent_id),
    snprintf(path, PATH_MAX, "%s/%s.db", WDB2_DIR, sagent_id);

    if (wdb_close(wdb, TRUE) != -1) {
        if (wdb_create_backup(sagent_id, version) != -1) {
            mwarn("Creating DB backup and create clear DB for agent: '%s'", sagent_id);
            unlink(path);

            //Recreate DB
            if (wdb_create_agent_db2(sagent_id) < 0) {
                merror("Couldn't create SQLite database for agent '%s'", sagent_id);
                free(sagent_id);
                return NULL;
            }

            if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
                merror("Can't open SQLite backup database '%s': %s", path, sqlite3_errmsg(wdb->db));
                sqlite3_close_v2(wdb->db);
                wdb->db = NULL;
                free(sagent_id);
                return NULL;
            }
        }
    } else {
        merror("Couldn't create SQLite database backup for agent '%s'", sagent_id);
    }

    free(sagent_id);
    return wdb;
}

wdb_t * wdb_recreate_global(wdb_t *wdb) {
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

    if (wdb_close(wdb, TRUE) != OS_INVALID) {
        unlink(path);

        if (OS_SUCCESS != wdb_create_global(path)) {
            merror("Couldn't create SQLite database '%s'", path);
            return NULL;
        }

        if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
            merror("Can't open SQLite backup database '%s': %s", path, sqlite3_errmsg(wdb->db));
            sqlite3_close_v2(wdb->db);
            wdb->db = NULL;
            return NULL;
        }
    }

    return wdb;
}

/* Create backup for agent. Returns 0 on success or -1 on error. */
int wdb_create_backup(const char * agent_id, int version) {
    char path[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int result = 0;

    snprintf(path, OS_FLSIZE, "%s/%s.db", WDB2_DIR, agent_id);

    if (!(source = wfopen(path, "r"))) {
        merror("Couldn't open source '%s': %s (%d)", path, strerror(errno), errno);
        return -1;
    }

    snprintf(path, OS_FLSIZE, "%s/%s.db-oldv%d-%lu", WDB2_DIR, agent_id, version, (unsigned long)time(NULL));

    if (!(dest = wfopen(path, "w"))) {
        merror("Couldn't open dest '%s': %s (%d)", path, strerror(errno), errno);
        fclose(source);
        return -1;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {
            unlink(path);
            result = -1;
            break;
        }
    }

    fclose(source);
    if (fclose(dest) == -1) {
        merror("Couldn't create file %s completely ", path);
        return -1;
    }

    if (result < 0) {
        unlink(path);
        return -1;
    }

    if (chmod(path, 0640) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        unlink(path);
        return -1;
    }

    return 0;
}

int wdb_adjust_upgrade(wdb_t *wdb, int upgrade_step) {
    switch (upgrade_step) {
        case 3:
            return wdb_adjust_v4(wdb);
        default:
            return 0;
    }
}

int wdb_adjust_global_upgrade(wdb_t *wdb, int upgrade_step) {
    switch (upgrade_step) {
        case 3:
            return wdb_global_adjust_v4(wdb);
        default:
            return 0;
    }
}

int wdb_adjust_v4(wdb_t *wdb) {

    if (wdb_begin2(wdb) < 0) {
        merror("DB(%s) The begin statement could not be executed.", wdb->id);
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_GET_ATTRIBUTES) < 0) {
        merror("DB(%s) Can't cache statement: get_attributes.", wdb->id);
        return -1;
    }

    sqlite3_stmt *get_stmt = wdb->stmt[WDB_STMT_FIM_GET_ATTRIBUTES];
    char decoded_attrs[OS_SIZE_256];

    while (wdb_step(get_stmt) == SQLITE_ROW) {
        const char *file = (char *) sqlite3_column_text(get_stmt, 0);
        const char *attrs = (char *) sqlite3_column_text(get_stmt, 1);

        if (!file || !attrs || !isdigit(*attrs)) {
            continue;
        }

        decode_win_attributes(decoded_attrs, (unsigned int) atoi(attrs));

        if (wdb_stmt_cache(wdb, WDB_STMT_FIM_UPDATE_ATTRIBUTES) < 0) {
            merror("DB(%s) Can't cache statement: update_attributes.", wdb->id);
            return -1;
        }

        sqlite3_stmt *update_stmt = wdb->stmt[WDB_STMT_FIM_UPDATE_ATTRIBUTES];

        sqlite3_bind_text(update_stmt, 1, decoded_attrs, -1, NULL);
        sqlite3_bind_text(update_stmt, 2, file, -1, NULL);

        if (wdb_step(update_stmt) != SQLITE_DONE) {
            mdebug1("DB(%s) The attribute coded as %s could not be updated.", wdb->id, attrs);
        }
    }

    if (wdb_commit2(wdb) < 0) {
        merror("DB(%s) The commit statement could not be executed.", wdb->id);
        return -1;
    }

    return 0;
}

bool wdb_is_older_than_v310(wdb_t *wdb) {
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;

    if (sqlite3_prepare_v2(wdb->db, SQL_GLOBAL_STMT[WDB_STMT_GLOBAL_CHECK_MANAGER_KEEPALIVE], -1, &stmt, NULL) !=
        SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
    else {
        switch (wdb_step(stmt)) {
            case SQLITE_ROW: {
                result = sqlite3_column_int(stmt, 0);
                break;
            }
            case SQLITE_DONE: {
                result = OS_SUCCESS;
                break;
            }
            default: {
                result = OS_INVALID;
                break;
            }
        }
        sqlite3_finalize(stmt);
    }

    return (result != 1);
}
