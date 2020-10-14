/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
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
// Migrate to the fourth version of the database:
// - The attributes field of the fim_entry table is decoded
static int wdb_adjust_v4(wdb_t *wdb);

// Upgrade agent database to last version
wdb_t * wdb_upgrade(wdb_t *wdb) {
    const char * UPDATES[] = {
        schema_upgrade_v1_sql,
        schema_upgrade_v2_sql,
        schema_upgrade_v3_sql,
        schema_upgrade_v4_sql,
        schema_upgrade_v5_sql,
    };

    char db_version[OS_SIZE_256 + 2];
    int version = 0;

    switch (wdb_metadata_get_entry(wdb, "db_version", db_version)) {
    case -1:
        return wdb;

    case 0:
        break;

    default:
        version = atoi(db_version);

        if (version < 0) {
            merror("DB(%s): Incorrect database version: %d", wdb->id, version);
            return wdb;
        }
    }

    for (unsigned i = version; i < sizeof(UPDATES) / sizeof(char *); i++) {
        mdebug2("Updating database '%s' to version %d", wdb->id, i + 1);

        if (wdb_sql_exec(wdb, UPDATES[i]) == -1 || wdb_adjust_upgrade(wdb, i)) {
            wdb = wdb_backup(wdb, version);
            break;
        }
    }

    return wdb;
}

wdb_t * wdb_upgrade_global(wdb_t *wdb) {
    const char * UPDATES[] = {
        schema_global_upgrade_v1_sql,
    };

    char db_version[OS_SIZE_256 + 2];
    int version = 0;

    switch (wdb_metadata_table_check(wdb,"metadata")) {
    case OS_INVALID:
        mwarn("DB(%s) Error trying to find metadata table", wdb->id);
        wdb = wdb_backup_global(wdb, -1);
        return wdb;
    case 0:
        // The table doesn't exist. Checking if version is 3.10 to upgrade or recreate
        if (wdb_global_check_manager_keepalive(wdb) != 1) {
            wdb = wdb_backup_global(wdb, -1);
            return wdb;
        }
        break;
    default:
        if( wdb_metadata_get_entry(wdb, "db_version", db_version) == 1) {
            version = atoi(db_version);
        }
        else{
            mwarn("DB(%s): Error trying to get DB version", wdb->id);
            wdb = wdb_backup_global(wdb, -1);
            return wdb;
        }
    }

    for (unsigned i = version; i < sizeof(UPDATES) / sizeof(char *); i++) {
        mdebug2("Updating database '%s' to version %d", wdb->id, i + 1);

        if (wdb_sql_exec(wdb, UPDATES[i]) == -1) {
            mwarn("Failed to update global.db to version %d", i + 1);
            wdb = wdb_backup_global(wdb, version);
            break;
        }
    }

    return wdb;
}

// Create backup and generate an empty DB
wdb_t * wdb_backup(wdb_t *wdb, int version) {
    char path[PATH_MAX];
    char * sagent_id;
    wdb_t * new_wdb = NULL;
    sqlite3 * db;

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

            if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
                merror("Can't open SQLite backup database '%s': %s", path, sqlite3_errmsg(db));
                sqlite3_close_v2(db);
                free(sagent_id);
                return NULL;
            }

            new_wdb = wdb_init(db, sagent_id);
            wdb_pool_append(new_wdb);
        }
    } else {
        merror("Couldn't create SQLite database backup for agent '%s'", sagent_id);
    }

    free(sagent_id);
    return new_wdb;
}

wdb_t * wdb_backup_global(wdb_t *wdb, int version) {
    char path[PATH_MAX];
    wdb_t * new_wdb = NULL;
    sqlite3 * db;

    snprintf(path, PATH_MAX, "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

    if (wdb_close(wdb, TRUE) != -1) {
        if (wdb_create_backup_global(version) != -1) {
            mwarn("Creating Global DB backup and creating empty DB");
            unlink(path);
            
            if (OS_SUCCESS != wdb_create_global(path)) {
                merror("Couldn't create SQLite database '%s'", path);
                return NULL;
            }

            if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
                merror("Can't open SQLite backup database '%s': %s", path, sqlite3_errmsg(db));
                sqlite3_close_v2(db);
                return NULL;
            }

            new_wdb = wdb_init(db, WDB_GLOB_NAME);
            wdb_pool_append(new_wdb);
        }
    } else {
        merror("Couldn't create SQLite Global backup database.");
    }

    return new_wdb;
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

    if (!(source = fopen(path, "r"))) {
        merror("Couldn't open source '%s': %s (%d)", path, strerror(errno), errno);
        return -1;
    }

    snprintf(path, OS_FLSIZE, "%s/%s.db-oldv%d-%lu", WDB2_DIR, agent_id, version, (unsigned long)time(NULL));

    if (!(dest = fopen(path, "w"))) {
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

int wdb_create_backup_global(int version) {
    char path[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int result = 0;

    snprintf(path, OS_FLSIZE, "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

    if (!(source = fopen(path, "r"))) {
        merror("Couldn't open source '%s': %s (%d)", path, strerror(errno), errno);
        return OS_INVALID;
    }

    snprintf(path, OS_FLSIZE, "%s/%s.db-oldv%d-%lu", WDB2_DIR, WDB_GLOB_NAME, version, (unsigned long)time(NULL));

    if (!(dest = fopen(path, "w"))) {
        merror("Couldn't open dest '%s': %s (%d)", path, strerror(errno), errno);
        fclose(source);
        return OS_INVALID;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {            
            result = OS_INVALID;
            break;
        }
    }

    fclose(source);
    if (fclose(dest) == -1) {
        unlink(path);
        merror("Couldn't create file %s completely.", path);
        return OS_INVALID;
    }

    if (result < 0) {
        unlink(path);
        return OS_INVALID;
    }

    if (chmod(path, 0640) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        unlink(path);
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

int wdb_adjust_upgrade(wdb_t *wdb, int upgrade_step) {
    switch (upgrade_step) {
        case 3:
            return wdb_adjust_v4(wdb);
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

    while (sqlite3_step(get_stmt) == SQLITE_ROW) {
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

        if (sqlite3_step(update_stmt) != SQLITE_DONE) {
            mdebug1("DB(%s) The attribute coded as %s could not be updated.", wdb->id, attrs);
        }
    }

    if (wdb_commit2(wdb) < 0) {
        merror("DB(%s) The commit statement could not be executed.", wdb->id);
        return -1;
    }

    return 0;
}
