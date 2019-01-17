/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * December 12, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "wdb.h"

// Upgrade agent database to last version
wdb_t * wdb_upgrade(wdb_t *wdb) {
    char db_version[OS_SIZE_256 + 2];
    int version = 0;
    int result = 0;
    wdb_t *new_wdb = NULL;

    if(result = wdb_metadata_get_entry(wdb, "db_version", db_version), result) {
        version = atoi(db_version);
    }

    //All cases must contain /* Fallthrough */ except the last one that needs to break;
    switch(version) {
    case 0:
        mdebug2("Updating database for agent %s to version 1", wdb->agent_id);
        if(result = wdb_sql_exec(wdb, schema_upgrade_v1_sql), result == -1) {
            new_wdb = wdb_backup(wdb, version);
        }
        /* Fallthrough */
    case 1:
        //Updated to last version
        break;
    default:
        merror("Incorrect database version %d", version);
    }

    return new_wdb;
}

// Create backup and generate an emtpy DB
wdb_t * wdb_backup(wdb_t *wdb, int version) {
    char path[PATH_MAX];
    char * sagent_id;
    wdb_t * new_wdb = NULL;
    sqlite3 * db;

    os_strdup(wdb->agent_id, sagent_id),
    snprintf(path, PATH_MAX, "%s/%s.db", WDB2_DIR, sagent_id);

    if (wdb_close(wdb) != -1) {
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
                merror("Can't open SQLite backup database '%s': %s", path, sqlite3_errmsg(wdb->db));
                sqlite3_close_v2(wdb->db);
                free(sagent_id);
                return NULL;
            }

            new_wdb = wdb_init(db, sagent_id);

            if (wdb_metadata_initialize(new_wdb) < 0) {
                mwarn("Couldn't initialize metadata table in '%s'", path);
            }
            if (wdb_scan_info_init(new_wdb) < 0) {
                mwarn("Couldn't initialize scan_info table in '%s'", path);
            }
        }
    } else {
        merror("Couldn't create SQLite database backup for agent '%s'", sagent_id);
    }

    free(sagent_id);
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
