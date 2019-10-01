/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

int wdb_mitre_attack_get(wdb_t *wdb, char *id, char *output){
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_GET) < 0) {
        mdebug1("at wdb_mitre_attack_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_GET];
    
    sqlite3_bind_text(stmt, 1, id, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
        return 1;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_mitre_phases_get(wdb_t *wdb, char *phase_name, char *output){
    int r;
    int count;
    int i;
    char *out;
    sqlite3_stmt *stmt = NULL;
    cJSON * data;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PHASE_GET) < 0) {
        mdebug1("at wdb_mitre_phases_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PHASE_GET];

    sqlite3_bind_text(stmt, 1, phase_name, -1, NULL);

    data = cJSON_CreateArray();

    while (r = sqlite3_step(stmt), r == SQLITE_ROW) {
        if (count = sqlite3_column_count(stmt), count > 0) {

            for (i = 0; i < count; i++) {
                switch (sqlite3_column_type(stmt, i)) {
                case SQLITE_INTEGER:
                case SQLITE_FLOAT:
                case SQLITE_TEXT:
                case SQLITE_BLOB:
                    cJSON_AddItemToArray(data, cJSON_CreateString((const char *)sqlite3_column_text(stmt, i)));
                    break;

                case SQLITE_NULL:
                default:
                    ;
                }
            }
        }
    }

    if (r != SQLITE_DONE) {
        mdebug1("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        cJSON_Delete(data);
        data = NULL;
        return -1;
    }

    out = cJSON_PrintUnformatted(data);
    snprintf(output, OS_MAXSTR + 1, "%s", out);
    free(out);
    cJSON_Delete(data);
    return 1;
}

int wdb_mitre_platforms_get(wdb_t *wdb, char *platform_name, char *output){
    int r;
    int count;
    int i;
    char *out;
    sqlite3_stmt *stmt = NULL;
    cJSON * data;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PLATFORM_GET) < 0) {
        mdebug1("at wdb_mitre_phases_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PLATFORM_GET];

    sqlite3_bind_text(stmt, 1, platform_name, -1, NULL);

    data = cJSON_CreateArray();

    while (r = sqlite3_step(stmt), r == SQLITE_ROW) {
        if (count = sqlite3_column_count(stmt), count > 0) {

            for (i = 0; i < count; i++) {
                switch (sqlite3_column_type(stmt, i)) {
                case SQLITE_INTEGER:
                case SQLITE_FLOAT:
                case SQLITE_TEXT:
                case SQLITE_BLOB:
                    cJSON_AddItemToArray(data, cJSON_CreateString((const char *)sqlite3_column_text(stmt, i)));
                    break;

                case SQLITE_NULL:
                default:
                    ;
                }
            }
        }
    }

    if (r != SQLITE_DONE) {
        mdebug1("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        cJSON_Delete(data);
        data = NULL;
        return -1;
    }

    out = cJSON_PrintUnformatted(data);
    snprintf(output, OS_MAXSTR + 1, "%s", out);
    free(out);
    cJSON_Delete(data);
    return 1;
}

int wdb_mitre_tactics_get(wdb_t *wdb, char *id_attack, char *output){
    int r;
    int count;
    int i;
    char *out;
    sqlite3_stmt *stmt = NULL;
    cJSON * row;
    cJSON * data;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_TACTICS_GET) < 0) {
        mdebug1("at wdb_mitre_phases_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_TACTICS_GET];

    sqlite3_bind_text(stmt, 1, id_attack, -1, NULL);

    data = cJSON_CreateArray();

    while (r = sqlite3_step(stmt), r == SQLITE_ROW) {
        if (count = sqlite3_column_count(stmt), count > 0) {
            row = cJSON_CreateObject();

            for (i = 0; i < count; i++) {
                switch (sqlite3_column_type(stmt, i)) {
                case SQLITE_INTEGER:
                case SQLITE_FLOAT:
                    cJSON_AddNumberToObject(row, sqlite3_column_name(stmt, i), sqlite3_column_double(stmt, i));
                    break;

                case SQLITE_TEXT:
                case SQLITE_BLOB:
                    cJSON_AddStringToObject(row, sqlite3_column_name(stmt, i), (const char *)sqlite3_column_text(stmt, i));
                    break;

                case SQLITE_NULL:
                default:
                    ;
                }
            }
            cJSON_AddItemToArray(data, row);
        }
    }

    if (r != SQLITE_DONE) {
        mdebug1("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        cJSON_Delete(data);
        data = NULL;
        return -1;
    }

    out = cJSON_PrintUnformatted(data);
    snprintf(output, OS_MAXSTR + 1, "%s", out);
    free(out);
    cJSON_Delete(data);
    return 1;
}

int wdb_mitre_ids_get(wdb_t *wdb, char *output){
    int r;
    int count;
    int i;
    char *out;
    sqlite3_stmt *stmt = NULL;
    cJSON * row;
    cJSON * data;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_IDS_GET) < 0) {
        mdebug1("at wdb_mitre_phases_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_IDS_GET];
    data = cJSON_CreateArray();

    while (r = sqlite3_step(stmt), r == SQLITE_ROW) {
        if (count = sqlite3_column_count(stmt), count > 0) {
            row = cJSON_CreateObject();

            for (i = 0; i < count; i++) {
                switch (sqlite3_column_type(stmt, i)) {
                case SQLITE_INTEGER:
                case SQLITE_FLOAT:
                    cJSON_AddNumberToObject(row, sqlite3_column_name(stmt, i), sqlite3_column_double(stmt, i));
                    break;

                case SQLITE_TEXT:
                case SQLITE_BLOB:
                    cJSON_AddStringToObject(row, sqlite3_column_name(stmt, i), (const char *)sqlite3_column_text(stmt, i));
                    break;

                case SQLITE_NULL:
                default:
                    ;
                }
            }
            cJSON_AddItemToArray(data, row);
        }
    }

    if (r != SQLITE_DONE) {
        mdebug1("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        cJSON_Delete(data);
        data = NULL;
        return -1;
    }

    out = cJSON_PrintUnformatted(data);
    snprintf(output, OS_MAXSTR + 1, "%s", out);
    free(out);
    cJSON_Delete(data);
    return 1;
}
